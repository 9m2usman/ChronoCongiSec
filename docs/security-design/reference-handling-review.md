# M4 Review — Memory-Reference Contract (M2/M3) and PR #4

**Document ID:** AMSC-SEC-008
**Owner:** M4 — Security Engine & Incident Response Lead
**Date:** 2026-11-18
**Scope:** four items: (1) `status=OK` vs `trust_state`; (2) `DUPLICATE_REF`; (3) M3's 100-reference default; (4) PR #4.
**Nature:** review, verification and coordination. **No M2, M3, M1 or M6 code was changed. PR #4 was NOT approved, merged, closed or modified.**

---

## 0. What exists, and who owns it

| Component | Location | Owner | State |
|---|---|---|---|
| Memory-reference verification `verify_memory_refs`, `MemoryRefCheck`, `MemoryRefStatus`, `MAX_MEMORY_REFS_PER_PROPOSAL` | `backend/app/memory/retrieval.py`, `models.py` on branches `feat/m3-memory-provenance` (`d018ff1`) and `feat/m3-days5-7-chronimem-graph-audit` (`651a51f`, which contains `d018ff1`) | **M3** | **Not merged to `main`.** The code says *"Interface not yet confirmed by M4/M2; shape may change."* |
| M2 agent runtime / proposal controller / consumer of `verify_memory_refs` | — | **M2** | **Does not exist.** No M2 branch or code in the repository (all 23 remote branches searched). |
| Interim gateway (M2's responsibility, written by M1) | `backend/app/api/gateway.py` on `feat/m1-day4-protected-gateway` and `…day7…` (identical) | M1 / M2 | Not merged. Doesn't call `verify_memory_refs`; reads raw `record.trust_state` itself (Day 4 review §8). |
| Authoritative trust decision for actions | `backend/app/security/trust.py` `assess_for_action`; `backend/app/security/policy.py` | **M4** | Local, tested (Days 3–7) |
| Proposal reference validation (duplicates, count, format) | `backend/app/security/policy.py` `normalize_proposal` | **M4** | Local, tested |

So the `status=OK` contract is **M3-owned** and is meant for **M2/M1's gateway**, which doesn't consume it yet. M4 doesn't use it either; M4 relies on `assess_for_action`.

---

## 1. Issue 1 — `status=OK` does not mean trusted

### Verified behaviour of M3's `verify_memory_refs`
I ran it in a scratch copy of M3's branch with 23 probe tests, all passing. M3's own `test_trust_check.py` also passes (12/12).

| Observation | Evidence |
|---|---|
| `status=OK` means only *found in the tenant* **and** *the current version's checksum matches*. It's returned for **every** trust state: UNVERIFIED, TRUSTED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED. | probe `test_ok_status_is_independent_of_trust_state` (6 cases) |
| `trust_state` is the **raw stored string**, passed through unvalidated. An unknown value (`"MOSTLY_TRUSTED"`) is returned with `status=OK`. | `test_unknown_stored_state_is_passed_through_as_ok` |
| Only the **current** version is integrity-checked. Tampered history still gives `OK`. | `test_only_current_version_integrity_is_checked` |
| The stored state is not reconciled with M4's history. A record set to TRUSTED through M3's unguarded `transition_memory_trust_state` (finding F-2) reports `OK`/`TRUSTED`. | `test_bypassed_trust_shows_ok_trusted` |
| The `OK` reason text is *"Memory reference verified and current version integrity valid."* "Verified" invites misreading. | source |
| Failures fail closed: a repository exception gives `ERROR`, never `OK`. | `test_repository_exception_maps_to_error_not_ok` |

**M2 consumer:** none exists, so whether M2 "relies on `status=OK`" can't be verified. It is the **highest-risk misuse** of this interface. A consumer that treats `OK` as "usable" would allow QUARANTINED, REJECTED, SUSPICIOUS, SUPERSEDED, UNVERIFIED and unknown-state records.

**M4 behaviour** (`test_reference_handling.py`, all passing):
- intact-but-untrusted memory is blocked in all five non-TRUSTED states;
- `status`/`trust_state`/`eligible` fields placed inside a proposal reference are **ignored**;
- an unknown stored state fails closed;
- only TRUSTED memory with M4 version-bound evidence passes.

### Contract options

| Option | Benefit | Risk |
|---|---|---|
| A. Keep `status=OK` and document it | No change | Highest misread risk; "OK" plus a "verified" reason looks like approval |
| B. Rename the value to `VERIFIED_INTACT` | Says what was checked; cheap now because **there are no consumers yet** | Still one field mixing lookup and integrity; still sits next to a raw `trust_state` that could be read as eligibility |
| **C. Separate fields (recommended)** | Unambiguous | Small schema change, which is still free while unmerged and unconsumed |

**Recommendation (C), for M3 and M2 to agree:**
- Rename `status` → `integrity_status`, with values `VERIFIED_INTACT | NOT_FOUND | INTEGRITY_FAILED | INVALID_REF | DUPLICATE_REF | ERROR`. That is, **adopt `VERIFIED_INTACT`**, but as the value of an explicitly integrity-scoped field.
- Rename `trust_state` → `stored_trust_state`, documented as *"raw stored value, not an authorisation input"*.
- **Add no eligibility or "usable" field to M3's response.**
- Change the reason text to *"Record found; current version checksum matches. This is not a trust decision."*
- Have the gateway take action eligibility **only** from M4: `PolicyEngine.evaluate`, which uses `TrustEvaluator.assess_for_action`. `verify_memory_refs` stays a diagnostic/early-reject helper.

**Owners:** M3 (schema) and M2 (consumer). M4 confirms the semantics.

---

## 2. Issue 2 — duplicate references

### M3 `verify_memory_refs` (verified)
- **Order:** a single pass. For each reference: type/empty check, then **duplicate check**, then add to `seen_ids`, then lookup and integrity check. The duplicate check for a given occurrence therefore happens *before* its lookup, but *after* the first occurrence was fully processed.
- **First occurrence:** fully looked up and checked (for example `OK`/`TRUSTED`).
- **Repeats:** `DUPLICATE_REF`, `trust_state=None`, **no lookup at all** (same call count as a single-reference request). Every repeat gets its own `DUPLICATE_REF` (`[q,u,q,q,u]` gives `OK, OK, DUP, DUP, DUP`).
- **Normalisation:** ids are `.strip()`ped before comparison, so `" id "` is treated as a duplicate of `"id"`.
- **Whole proposal:** **no verdict.** The function returns per-reference results only. Whether a duplicate blocks the proposal is entirely the consumer's decision, so M2's behaviour is currently undefined.
- **Deterministic:** yes (20 repeated runs gave identical output).

### M4 policy engine (verified, `test_reference_handling.py`)
- **Any repeated `record_id` blocks the whole proposal** at input validation (`POLICY_INPUT_INVALID`) **before any reference is evaluated**: zero trust lookups, empty memory evidence. This applies whether the duplicate is TRUSTED, QUARANTINED or UNVERIFIED.
- It also catches repeats as plain id + pinned `{record_id, version}`, and the same id with different versions.
- **Padded ids** (`" id "`) are rejected outright rather than silently merged.
- **Deterministic:** yes. The adapter is never invoked.

**Recommendation:** a duplicate should **block the whole proposal** (as M4 does). M2 must not treat `DUPLICATE_REF` as "skip the repeat and continue", because a malformed or replayed proposal shouldn't be partially honoured. M3 and M4 should agree on id normalisation: reject padded ids rather than strip them.

---

## 3. Issue 3 — the 100-reference default

| Limit | Value | Location | What it is |
|---|---|---|---|
| `MAX_MEMORY_REFS_PER_PROPOSAL` | **100** | M3 `retrieval.py` | Proposal reference-verification limit, an *"M3 default pending M4/M2 formal confirmation"* |
| Retrieval pagination | max 100 (default 50) | M3 `repository.py`, `api/memory.py` | Page size for `GET /memory`. **Unrelated** to proposals (TRD §22) |
| `MAX_MEMORY_REFS` | **50** | M4 `policy.py` | Proposal input validation (engine) |
| `MAX_MEMORY_REFS_COUNT` | **50** | M1 interim gateway `ActionProposalRequest` (unmerged) | Request schema (`max_length=50`) |
| M2 proposal schema | — | — | **Does not exist** |

**Consequences of the mismatch:**
- A proposal with **51–100** references passes M3's check but is rejected by the interim gateway schema (400/422) and by M4 (`POLICY_INPUT_INVALID`).
- With **more than 100**, M3 returns a **single** `ERROR` item with `record_id=None` instead of one result per reference. Likewise a non-list returns a single `INVALID_REF`. A consumer that maps results back to references by position or id must handle the length mismatch.
- **Individual validation:** M3 checks each reference up to 100; M4 evaluates each up to 50 (tested: 50 trusted → 50 evidence entries, ALLOW).

**Performance and denial of service:**
- **Measured** (M4 in-memory, flat lineage, n=200): **p95 0.32 ms at 1 reference, 5.0 ms at 50, 10.6 ms at 100**. The 100 figure was measured with the limit lifted in a scratch script only.
- **Worst case per reference:** a lineage traversal of up to 50 nodes and 200 edges, plus database round-trips in production. 100 references can approach the 2 s policy budget, which **fails closed** (BLOCK). That's an availability concern, not a safety one.
- **No id length or charset limit in M3:** a 100,000-character id was accepted and looked up. M4 and the interim gateway cap ids at 128 characters.

**Recommendation:** use **one contract**. M2's proposal schema owns the number and enforces it at ingress; M3's and M4's constants equal it. **50 is the lower-risk choice** (it's already enforced in two places, and lineage cost scales per reference). If 100 is needed, measure M4 with realistic lineage on PostgreSQL first. M3 should also cap the id format (≤128 characters, `[A-Za-z0-9_.:-]`).

---

## 4. Issue 4 — PR #4 review

**PR #4** (`refs/pull/4/head` = `docs/research-backed-agent-memory-security` @ `ce7e2c7`, by 9m2usman). I fetched it read-only. Its merge base is PR #3 (2026-11-16). It is **not in `main`**, and **merging it into current `main` produces conflicts** in `README.md`, `docs/02-TRD-SRS.md` and `docs/07-…` (add/add). I checked with `git merge-tree`, which changes no worktree.

### 4.1 What the PR intended (diff against its merge base)

| File | Change | Security impact | Recommendation |
|---|---|---|---|
| `docs/01-PRD.md` | FR-011/SEC-005 → trusted-only retrieval; FR-014/SEC-002 → every non-TRUSTED state blocks; NFR-003 adds the SHA-256 authenticity caveat; licence claims softened to "not independently verified" | **Strengthens** | ACCEPT. **Already in `main`.** |
| `docs/02-TRD-SRS.md` | §15.1 authenticity boundary; §15.3 state meanings and UNVERIFIED-by-default; §16 Check 6 → "all TRUSTED"; §17 trusted-only retrieval; §18 adds revalidation **but keeps a "Mark Restored Records as TRUSTED" step before "Revalidate"**; SEC-005 updated | Mostly strengthens; **§18 is internally contradictory**: it marks records TRUSTED before revalidating them | REQUEST CHANGES (§18) |
| `docs/03-APPLICATION-FLOW.md` | Ingestion → `UNVERIFIED`; quarantine note → trusted-only retrieval; recovery → revalidate, then TRUSTED only on success | **Strengthens** | ACCEPT. **Already in `main`.** |
| `docs/05-DATABASE-API-SCHEMA.md` | Mandatory composite tenant foreign keys; `sources`/`memory_records` default → `UNVERIFIED` | **Strengthens** (matches M6 migrations 0001–0002) | ACCEPT. **Already in `main`.** |
| `docs/07-…` | Adds the research standard (866 lines) | Neutral/positive | ACCEPT. **`main` already has it** (add/add conflict). |
| `README.md` | Status text; adds Doc 07 to the index and tree | Neutral | Superseded by `main` |

### 4.2 What merging the PR into current `main` would change (`main` → PR head, same files: +23 / −59)

| File / section | Current `main` | After PR | Security / implementation impact | Affected | Recommendation |
|---|---|---|---|---|---|
| TRD §13 step 2 (Context Retrieval) | Server returns **only eligible TRUSTED** records | `GET /memory?...&exclude_quarantined=true` — *"Quarantined records are automatically excluded"* | **Weakens.** Re-introduces the GAP-001 contract defect: UNVERIFIED, SUSPICIOUS and SUPERSEDED become implied as retrievable. Conflicts with FR-011, SEC-005 and the implemented M3 code. | M3, M4, M2, M7 | **REQUEST CHANGES** |
| TRD §18 recovery diagram | Rollback → Revalidate → TRUSTED only on pass | Rollback → **Mark Restored Records as TRUSTED** → Revalidate | **Weakens.** Contradicts TRD §15.3 ("recovery must not automatically set TRUSTED"), Doc 03 §10 and the M4 Day 3 matrix (RECOVERY_RESTORE → UNVERIFIED). | M4, M6 (rewind), M3 | **REQUEST CHANGES** |
| TRD §12 / §12.1, PRD §7.1 and Demo 3, Flow §1, TRD §6.1, README | Single company with branches; "a branch is NOT a tenant" | Three-company multi-tenant; branch architecture removed | Product-scope change; isolation testing is still required either way. Conflicts with M6's OD-28 open question. | All; M1, M6, M7 | **NEEDS TEAM DISCUSSION** |
| Doc 05 `branches` table | Defined | **Removed** | **The contract would no longer match the implemented schema** (M6 migration 0001 creates `branches`) | M6, M1 | **REQUEST CHANGES** |
| Doc 07 "read together with" list; README index and tree | Lists Doc 08 (gap register) | Doc 08 references **removed** | Weakens traceability of open security findings | All | **REQUEST CHANGES** |

### 4.3 Verdict
The PR's own changes are security improvements, but **`main` already contains them** through later merges. The branch is **stale**: merging it as-is would conflict, and a careless conflict resolution would **revert newer security requirements** (the GAP-001 retrieval contract, recovery revalidation, the Doc 08 links, the `branches` schema).

**Overall: REQUEST CHANGES.** Rebase onto current `main`. The remaining diff should then be close to empty apart from the §18 contradiction, which must be fixed. Otherwise close it as superseded; that's the owner's decision.

**NOT APPROVED OR MERGED BY THIS REVIEW.** The earlier "APPROVE / MERGE" recommendation by an agent is not supported by the diff.

---

## 5. Other findings from this review

| ID | Owner | Finding |
|---|---|---|
| RV-1 | **M4** | **Resolved 2026-11-19:** M4 now imports from the `backend.app.memory` package. Original finding: **M4 imports will break when M3's branch merges.** M3 removes `backend/app/memory/service.py` and `hashing.py` (split into `ingestion.py`, `versioning.py`, `retrieval.py`, `integrity.py`). `security/trust.py` and `security/quarantine.py` import `memory.hashing` / `memory.service`, and M4 tests import `memory.service`. Fix: import from the package (`from backend.app.memory import sha256_hex, get_memory_detail, ingest_memory, update_memory, retrieve_memory`). Both branches export these, though `main` doesn't export `transition_memory_trust_state`. `quarantine.py` also has an unused `sha256_hex` import. **Not changed in this review.** To do when M3's branch is merged or rebased. |
| RV-2 | M3 | `verify_memory_refs` accepts ids with no length or charset limit (100,000 characters, newlines, `../`). |
| RV-3 | M3 / M4 | F-1 / F-2 remain on M3's branch (`transition_memory_trust_state` is unguarded; see the Day 3 review). `verify_memory_refs` reflects such bypassed states as `OK`. |

---

## 6. Coordination messages (drafts; not yet sent or confirmed)

### To M2
> **Subject: Memory-reference contract — trust semantics, duplicates, reference limit (M4 review)**
>
> Hi M2. I've reviewed M3's `verify_memory_refs` (on `feat/m3-days5-7-chronimem-graph-audit`), which the gateway is meant to call. I couldn't find any M2 proposal controller or consumer in the repo yet, so this is about the contract before you build against it.
>
> **1. `status=OK` ≠ trusted.** `OK` only means "found in this tenant, and the current version's checksum matches". It's returned for every trust state, including QUARANTINED, REJECTED, SUSPICIOUS, SUPERSEDED, UNVERIFIED, and even unknown stored values. `trust_state` is the raw stored string, not M4's reconciled state. **Please never treat `OK` (or `trust_state == "TRUSTED"`) as authorisation.** Action eligibility must come from the M4 policy engine (`PolicyEngine.evaluate` → `TrustEvaluator.assess_for_action`). That checks the TRUSTED state against M4's history, version-bound trust evidence, all-version integrity and lineage, and fails closed on missing or unknown data.
>
> **2. Naming.** I recommend separate fields rather than only renaming: `integrity_status` with values `VERIFIED_INTACT | NOT_FOUND | INTEGRITY_FAILED | INVALID_REF | DUPLICATE_REF | ERROR`, plus `stored_trust_state`, documented as not an authorisation input, and no eligibility field in M3's response. There are no consumers yet, so the change is free now. Can you confirm that works for the controller?
>
> **3. Duplicates.** M3 fully checks the first occurrence. Each repeat gets `DUPLICATE_REF` with no lookup and `trust_state=None`. M3 returns no proposal-level verdict, so blocking is up to the consumer. M4's engine **blocks the whole proposal** on any repeated `record_id` (`POLICY_INPUT_INVALID`), before evaluating any reference, deterministically. I recommend the controller do the same and not "skip and continue". Note that M3 strips whitespace before comparing, while M4 rejects padded ids.
>
> **4. Reference count.** *"Can the proposal controller accept up to 100 memory references in one proposal? Is this compatible with the current proposal schema and security validation pipeline?"* Today M3 defaults to 100, while M4's engine and the interim gateway schema both cap at 50. A 51–100-reference proposal passes M3 but is blocked by M4. I measured M4 at p95 5 ms (50 refs) and 10.6 ms (100 refs) in memory, with flat lineage; deep lineage on PostgreSQL will be much slower, and the 2 s budget fails closed. I recommend your schema own one number (50 suggested) enforced at ingress, with M3/M4 aligned to it. Which value do you need?
>
> Evidence: `docs/security-design/reference-handling-review.md` and `backend/tests/security/test_reference_handling.py`.

### To M3
> **Subject: `verify_memory_refs` — 100-reference default, response semantics, id validation (M4 review)**
>
> Hi M3. I've reviewed `verify_memory_refs` on `feat/m3-days5-7-chronimem-graph-audit`. Your 12 trust-check tests pass, and I added 23 scratch probes (not committed); behaviour matches the docstring and failures fail closed.
>
> 1. **`MAX_MEMORY_REFS_PER_PROPOSAL = 100`:** can you confirm it's intended as the *proposal* verification limit, and not derived from the 100-row retrieval page size? M4's engine and the interim gateway schema use **50**. Please align with M2 on one value. M2's schema should own it, and I suggest 50 unless M2 needs more. Also, past the limit (and for non-list input) the function returns a **single** result item with `record_id=None`, not one per reference. Please document this, or return per-reference results.
> 2. **Response semantics:** `status=OK` is returned with any trust state (QUARANTINED included, and unknown values passed through). I propose `integrity_status` (`VERIFIED_INTACT | …`) and `stored_trust_state`, no eligibility field, and a reason text that says it's not a trust decision. Eligibility stays with M4.
> 3. **Id validation:** there's no length or charset limit (a 100k-character id was accepted). Please cap at 128 characters with `[A-Za-z0-9_.:-]` and reject padded ids rather than stripping them, to match M4 and the gateway schema.
> 4. **Heads-up:** your branch removes `memory/service.py` and `memory/hashing.py`. M4 will switch to package-level imports (`from backend.app.memory import …`), so please keep those names exported. It would also help to export `transition_memory_trust_state` from the package on `main` too, or better, route it through M4 (F-2).

---

## 7. Tests

| File | Status |
|---|---|
| `backend/tests/security/test_reference_handling.py` (new, M4) | 35 passed. Mutation check: removing M4's duplicate check → 8 failures; raising M4's limit to 100 → 3 failures. |
| Scratch probe of M3 `verify_memory_refs` (not committed; runs against M3's unmerged branch) | 23 passed |
| M3 `backend/app/memory/tests/test_trust_check.py` on M3's branch (scratch copy) | 12 passed |
| `pytest backend/tests/security` | 1009 passed, 5 skipped, 2 xfailed |
| `pytest backend/app/memory/tests -k gap` | 9 passed (GAP-001..004) |
| `pytest --ignore=backend/tests/database` | 1183 passed, 5 skipped, 2 xfailed |
| M2 integration | **Not testable:** no M2 code exists |
| M6 database suite, PostgreSQL drift tests | Not run: no PostgreSQL server |
