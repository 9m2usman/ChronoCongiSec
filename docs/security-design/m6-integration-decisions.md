# M4 decisions on M6's open database dependencies

**Owner:** M4, Security Engine & Incident Response
**For:** M6, who writes the final integration migration. Also for M1, M2, M3 and M5 where their code or sign-off is named.
**Answers:** the M4-owned and M4-co-owned items in `docs/database-design/M6-PROGRESS-LOG.md`, OPEN-DEPENDENCIES: OD-1 to OD-4, OD-6, OD-7, OD-9, OD-15, OD-17, OD-19, OD-21 to OD-26.
**Not answered here** (no M4 stake): OD-5, OD-8, OD-10 to OD-14, OD-16, OD-18, OD-20, OD-27, OD-28. M4 adds security input to OD-5 only (section 6.2).
**Date:** 2026-11-18

## 0. How to read this

- **"M4 decides"** marks the security semantics M4 owns. M6 can implement them without further M4 input.
- **"Sign-off"** marks enum changes. DOC-005 section 7, rule 4 requires synchronous approval by M1, M6 and M5 for any enum change. M4's decision is the proposal they approve.
- **P0** means it must be in the integration migration. **P1** means it should be, but can follow.
- Each SQL fragment is a specification of the rule, not a migration. M6 writes the migration, the model change and the tests, following M6's own conventions: pre-check existing rows, stop on violation, exact inverse on downgrade.
- **Evidence** is the code as read on these heads (2026-11-18):
  - `origin/main` @ `2b3f738` (M6 migrations 0001–0009);
  - M1 `feat/m1-day7-api-finalization` @ `650fe10` (`api/gateway.py`, the only producer of gateway rows);
  - M5 `feat/m5-amsc-frontend-workstation` @ `e6b14d4`;
  - M3 `feat/m3-days5-7-chronimem-graph-audit` @ `651a51f` and `feat/m3-async-postgres-adapter` @ `d84aded`;
  - M4's working tree on `feat/m4-security-ml`.
  - **No M2 proposal controller exists on any branch.**
  - **`backend/app/recovery/` is empty**, and `api/security.py`, `api/incidents.py` and `api/recovery.py` exist on no branch.

---

## 1. Summary

| OD | M4 decision (short) | Database change for M6 | Code change needed by | Sign-off |
|---|---|---|---|---|
| OD-1 | `ALLOW / BLOCK / REQUIRES_APPROVAL`. `REVIEW` is an incorrect alias and is never produced. | CHECK on `decision`, plus a cross-column CHECK (P0) | M1: drop `REVIEW` | M1, M5, M6 |
| OD-2 | 6 trust states + `NOT_REFERENCED`, `NOT_FOUND`, `INELIGIBLE`, `UNKNOWN`, `UNAVAILABLE`. The label must be honest. | CHECK on `memory_trust` (P0); ALLOW/approval only with `TRUSTED`/`NOT_REFERENCED` | M1: honest labels; add `REJECTED`/`SUPERSEDED` | M1, M5, M6 |
| OD-3 | Confirmed `PERMITTED / DENIED / ELEVATED`, mapped 1:1 to the decision | Part of the cross-column CHECK (P0) | none | M1, M5, M6 |
| OD-4 | 6 values; initial value fixed by the decision; forward-only transitions | CHECK + insert rule + transition trigger (P0) | M1 (none beyond OD-6); M4 (ALLOW initial value); M5 (types) | M1, M2, M5, M6 |
| OD-6 | An execution row only for ALLOW, or for REQUIRES_APPROVAL with a valid approval. A row means the adapter was invoked. | Trigger on `tool_executions` INSERT (P0); deferred existence check (P1) | M1: no `BLOCKED_BY_TOCTOU` row; use an audit event | M2 |
| OD-7 | `PENDING / APPROVED / REJECTED / EXPIRED`; one approval; analyst or admin; not the submitter; expires | CHECK, terminal immutability, `expires_at`, `submitted_by_user_id`, approver trigger (P0/P1) | M1/M2 approval route; M4 engine wiring | M1, M5, M6 |
| OD-9 | `actor_id` = `user:` / `agent:` / `system:` prefix; 6 outcome values; `event_type` format plus an M4 registry | `NOT VALID` CHECKs on new audit rows (P0); index for the trust ledger (P0) | M1 + M4: prefix actor ids, map outcomes | M1, M5, M6 |
| OD-15 | Ingest only from `ACTIVE` sources not in `QUARANTINED`/`REJECTED`. Source trust never confers record trust. | CHECK `sources.trust_state` and `memory_records.trust_state` to the 6 states (P0) | M3 ingestion | M3 |
| OD-17 | Rollback **appends a new version**; it never moves `current_version` back. Checkpoint hash = SHA-256 over sorted items. | Trust reset on version change (P0); checkpoint hash function, item-checksum and immutability triggers (P1) | M4 restore callback (M3 confirms) | M3 |
| OD-19 | 4 PRD role names, held in `memberships.role`; role lists in M4 code; no `role_permissions` in the MVP; branch access explicit; TENANT_ADMIN company-wide | CHECK on `memberships.role` (P0); P2 branch tables as designed by M6 | **M4 renames `DEVELOPER` → `AI_DEVELOPER` and adds `AUDITOR`**; M1 re-reads the role for privileged actions | M1, M3 |
| OD-21 | Plan: `PENDING → PREVIEWED → EXECUTED`, `FAILED` retryable. 5 action values; 2 outcomes. Restored records stay UNVERIFIED until M4 revalidates. | CHECKs, transition trigger, status ⇔ `executed_at` (P0); drop the `'SUCCESS'` default | M6: `RewindCoordinator` also sets `status`; M4 recovery service | M3 |
| OD-22 | M4 owns `api/recovery.py` and `recovery/` (business semantics) on M6's `RewindCoordinator` | none | M4 | Project owner |
| OD-23 | No new table: one `recovery_actions` row per prior external execution, `EXTERNAL_ACTION_IRREVERSIBLE` / `REQUIRES_COMPENSATION` | Covered by the OD-21 CHECKs | M4 recovery service | M2 |
| OD-24 | Memory rows are never physically deleted | RESTRICT on all memory-side FKs; append-only `memory_versions` (P0) | M3: no delete paths | M3 |
| OD-25 | Keep `execution_status` on `policy_decisions`, but only as a forward-only state machine (OD-4). `tool_executions` + audit stay the evidence. | The OD-4 transition trigger | none | M1 |
| OD-26 | Phase 2 (TRD). Not in the integration migration. Accepted risk, documented with an interim export. | none now | M7 (export job, later) | Project owner, M7 |

Section 7 lists further rules M4 needs. M6 didn't raise them, but they come from the same evidence: fail-open defaults, mutable proposals, and no durable trust ledger.

---

## 2. Gateway decisions (OD-1, OD-2, OD-3, OD-25)

### 2.1 OD-1: `policy_decisions.decision`

**Evidence**

| Party | Values | Where |
|---|---|---|
| DOC-005 :320 | `ALLOW, BLOCK, REQUIRES_APPROVAL` | schema comment |
| PRD FR-015, TRD §2.3 / Check 5 | `BLOCKED` or `REQUIRES_APPROVAL` | requirements |
| M4 engine | `ALLOW, BLOCK, REQUIRES_APPROVAL` (`PolicyOutcome`) | `backend/app/security/policy.py` |
| M5 | `'ALLOW' \| 'BLOCK' \| 'REQUIRES_APPROVAL'` | `frontend/src/types/gateway.ts`, Overview filter |
| M1 gateway | enum `ALLOW, BLOCK, REVIEW  # Also known as REQUIRES_APPROVAL` | `api/gateway.py:75-77` |

- **`REVIEW` is declared but never produced.** M1's `DeterministicPolicyEvaluator` returns only ALLOW or BLOCK; an amount over the $300 threshold returns **BLOCK**. `REVIEW` appears only in one comparison (`gateway.py:1374`), and no M1 test mentions it (0 matches in the four M1 gateway test files).
- **In M4, `REVIEW` is an internal check outcome** (`CheckOutcome.REVIEW`), never a decision. It concludes to `REQUIRES_APPROVAL`.

**M4 decides**
- Canonical: **`ALLOW`, `BLOCK`, `REQUIRES_APPROVAL`**.
- `REVIEW` is an **incorrect substitute**, not a legacy value or a separate state. It must not be stored.
- Meanings:
  - `ALLOW`: every mandatory check passed. It permits execution only through the guard, after revalidation.
  - `BLOCK`: execution is prohibited, permanently for this proposal.
  - `REQUIRES_APPROVAL`: no check blocked, at least one check needs a human, and the tool permits review. It never executes without a valid approval (OD-7).

**Database (P0)**

```sql
-- ck_policy_decisions_decision
decision IN ('ALLOW','BLOCK','REQUIRES_APPROVAL')

-- ck_policy_decisions_consistent  (also covers OD-2, OD-3, OD-4)
(
  decision = 'ALLOW' AND policy_result = 'PERMITTED'
  AND memory_trust IN ('TRUSTED','NOT_REFERENCED')
  AND execution_status IN ('PENDING_EXECUTION','EXECUTED','FAILED','UNKNOWN','NOT_EXECUTED')
) OR (
  decision = 'REQUIRES_APPROVAL' AND policy_result = 'ELEVATED'
  AND memory_trust IN ('TRUSTED','NOT_REFERENCED')
  AND execution_status IN ('PENDING_APPROVAL','PENDING_EXECUTION','EXECUTED','FAILED','UNKNOWN','NOT_EXECUTED')
) OR (
  decision = 'BLOCK' AND policy_result = 'DENIED'
  AND execution_status = 'NOT_EXECUTED'
  AND jsonb_typeof(reasons_json) = 'array' AND jsonb_array_length(reasons_json) > 0
)
```

- **The CHECK uses only NOT NULL columns.** It therefore can't be bypassed through a NULL result, which is the same lesson as M6's Day 5 snapshot-hash defect.
- **Pre-check:** stop if any existing row is `REVIEW` or violates the consistency rule, and list the ids. Never rewrite them: decisions are permanent (0009).

**Code changes:** M1 removes `GatewayDecision.REVIEW`. The PENDING_APPROVAL branch then uses `REQUIRES_APPROVAL`. M5 needs no change for this item.

### 2.2 OD-2: `policy_decisions.memory_trust`

**Evidence**
- **DOC-005 :321:** `TRUSTED, SUSPICIOUS, QUARANTINED, NOT_REFERENCED`.
- **M1** writes `TRUSTED, SUSPICIOUS, QUARANTINED, UNVERIFIED, NOT_REFERENCED`. Three problems (from reading the code; not executed):
  1. A missing or cross-tenant record is labelled `QUARANTINED` (`gateway.py:1281`), and an agent-binding mismatch is also labelled `QUARANTINED` (`:1289`). The permanent record therefore claims a trust state that no record has.
  2. `MemoryTrustDecision` has no `REJECTED`. A REJECTED reference reaches `MemoryTrustDecision("REJECTED")` (`:1060`), which raises `ValueError`, so the request errors instead of writing a BLOCK row.
  3. A `SUPERSEDED` reference falls through to `resolved_trust = TRUSTED` (`:1072-1076`), giving **ALLOW with `memory_trust = TRUSTED`**. M1's pre-dispatch revalidation (`:1457-1472`) then stops the adapter, but the permanent decision row stays wrong.
- **M4** writes the worst label across all references (`policy.py:_check_memory`):
  - the six trust states;
  - `NOT_REFERENCED`;
  - `NOT_FOUND` (missing or cross-tenant, indistinguishable);
  - `INELIGIBLE` (stored TRUSTED, but no version-bound evidence);
  - `UNKNOWN` (unrecognised stored state);
  - `UNAVAILABLE` (trust evaluator failed).

**M4 decides**
- Canonical **11 values:** `TRUSTED, UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED, NOT_REFERENCED, NOT_FOUND, INELIGIBLE, UNKNOWN, UNAVAILABLE`.
- **The column is a forensic summary, so it must be honest.** It names the most restrictive condition found, and a missing record is never given a real trust state. Severity order, least to most:
  `TRUSTED < INELIGIBLE = UNVERIFIED < SUPERSEDED < SUSPICIOUS < QUARANTINED < REJECTED < UNKNOWN < NOT_FOUND < UNAVAILABLE`.
- `ALLOW` and `REQUIRES_APPROVAL` are possible only with `TRUSTED` or `NOT_REFERENCED`. This is enforced by the consistency CHECK in 2.1.

**Database**
- **P0, CHECK:** `memory_trust IN (<11 values>)`.
- **P1, defense in depth: trigger `trg_policy_decisions_memory_refs_trusted`, BEFORE INSERT.** It catches M1's SUPERSEDED case at the database. If `decision` is `ALLOW` or `REQUIRES_APPROVAL`:
  - every element of the proposal's `memory_refs_json` must resolve to a `memory_records` row in the same tenant with `trust_state = 'TRUSTED'`;
  - an element may be a string id, or an object with a string `record_id`; anything else is rejected;
  - `memory_trust = 'NOT_REFERENCED'` requires `memory_refs_json = '[]'`, and `'TRUSTED'` requires a non-empty array.
  - Raise SQLSTATE 23514.
  - This checks the **stored** state only. M4's version-bound evidence remains the real authority; the trigger only stops a contradictory row from becoming permanent.

**Code changes:** M1 labels missing or mis-bound references `NOT_FOUND` and adds `REJECTED`/`SUPERSEDED` to its enum, or delegates to M4's engine, which already does all of this.

### 2.3 OD-3: `policy_decisions.policy_result`

- **Confirmed:** `PERMITTED, DENIED, ELEVATED`, mapped 1:1: ALLOW→PERMITTED, BLOCK→DENIED, REQUIRES_APPROVAL→ELEVATED. M4 builds it exactly this way (`policy.py:_build`).
- **Database (P0):** `policy_result IN ('PERMITTED','DENIED','ELEVATED')`, plus the consistency CHECK in 2.1.
- **M1:** currently never writes `ELEVATED`. That's fine once the BLOCK→REQUIRES_APPROVAL path exists.

### 2.4 OD-25: where the execution outcome lives

**M4 decides:** keep `execution_status` on `policy_decisions`. It isn't decision content; it is a lifecycle projection allowed to move **forward only**, under the OD-4 state machine.
- **Content stays permanent:** `decision`, `memory_trust`, `policy_result` and `reasons_json` (already enforced by 0009).
- **The evidence of what ran** remains `tool_executions` plus the audit chain.

**Why not move it now:**
- M1's idempotency path reads `execution_status` (`PENDING_EXECUTION` gives a 409 "currently executing"), and M1's response depends on it.
- Removing the column means rewriting M1's gateway with no security gain, once transitions are forward-only and audited.
- TRD §8's actual rule ("no `UPDATE` or `DELETE` API endpoints") is still met.

**Database:** the transition trigger in 3.1 replaces the "any change allowed" rule that 0009 left on this column. 0009's grant `UPDATE (execution_status)` in `roles.py` stays.

---

## 3. Execution, approval and audit (OD-4, OD-6, OD-7, OD-9)

### 3.1 OD-4: `policy_decisions.execution_status`

**Evidence**
- **DOC-005:** `EXECUTED, NOT_EXECUTED, PENDING_APPROVAL`.
- **M1:** adds `PENDING_EXECUTION, FAILED, UNKNOWN`.
- **M5:** types only `'EXECUTED' | 'NOT_EXECUTED'`.
- **M4:** `ExecutionOutcome.status` uses `EXECUTED, NOT_EXECUTED, PENDING_APPROVAL, FAILED, UNKNOWN`.

**M4 decides:** six values.

| Value | Meaning |
|---|---|
| `PENDING_APPROVAL` | REQUIRES_APPROVAL waiting for a human |
| `PENDING_EXECUTION` | Permitted and persisted; dispatch not yet recorded |
| `EXECUTED` | Adapter returned |
| `FAILED` | Adapter raised or reported failure |
| `UNKNOWN` | Adapter outcome cannot be determined (timeout, crash after dispatch). Honest-outcome rule (TRD §18). |
| `NOT_EXECUTED` | Will never execute: blocked, rejected or expired approval, or pre-dispatch revalidation or mandatory control failed |

**Insert rule (trigger, BEFORE INSERT):** the initial value is fixed by the decision.
- ALLOW → `PENDING_EXECUTION`
- REQUIRES_APPROVAL → `PENDING_APPROVAL`
- BLOCK → `NOT_EXECUTED`

**Transition rule (trigger, BEFORE UPDATE OF execution_status).** Anything else raises 55000.

```
PENDING_APPROVAL  -> PENDING_EXECUTION   (only if an APPROVED, unexpired approval exists: OD-7)
PENDING_APPROVAL  -> NOT_EXECUTED        (rejected / expired / revalidation blocked)
PENDING_EXECUTION -> EXECUTED | FAILED | UNKNOWN | NOT_EXECUTED
UNKNOWN           -> EXECUTED | FAILED   (analyst reconciliation, audited)
EXECUTED, FAILED, NOT_EXECUTED           terminal
```

**Deferred existence check (P1; `CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED` on both tables):**
- at commit, `execution_status IN ('EXECUTED','FAILED')` ⇔ a `tool_executions` row exists for the proposal;
- `UNKNOWN` may exist without a row (a crash after dispatch);
- it is deferred because M1 updates the status before inserting the execution row in the same transaction (`gateway.py:643-665`).

**A stuck `PENDING_EXECUTION`** (crash between persistence and dispatch) is moved to `UNKNOWN` by reconciliation, never to `NOT_EXECUTED`: the adapter may already have run.

**Code changes:**
- **M4 (done 2026-11-18):** `PolicyDecision.initial_execution_status` now gives `PENDING_EXECUTION` only for an ALLOW that passes `decision_is_executable`; any other ALLOW (incomplete, timed out, contradictory) gives `NOT_EXECUTED`. Covered by `backend/tests/security/test_db_contract.py`; the former strict xfail is now a passing test.
- **M5:** widen the type to the six values; show `UNKNOWN` as "outcome unknown, needs reconciliation".
- **M1:** none beyond OD-6.

### 3.2 OD-6: when may a `tool_executions` row exist?

**Evidence**
- 0007 already forces an execution's decision to belong to its proposal.
- `tool_executions.proposal_id` is UNIQUE, so there is one execution per proposal.
- M1 writes `status = 'BLOCKED_BY_TOCTOU'` (403) for an ALLOW decision whose memory changed before dispatch, and the adapter is **not** called (`gateway.py:1474-1499`).

**M4 decides**
- **A `tool_executions` row means "the adapter was invoked".** Nothing else may create one. This keeps the forensic question "did a side effect possibly happen?" answerable by row existence.
- **Revalidation aborts are not executions.** M1's TOCTOU abort records:
  - `policy_decisions.execution_status = 'NOT_EXECUTED'`;
  - an audit event `TOOL_EXECUTION_ABORTED`, outcome `BLOCKED`, with the new reason codes in `details_json`;
  - no execution row.
- **M1's response must report the persisted decision.** Today M1 returns `decision: BLOCK` while the permanent row says `ALLOW`. The response should give `ALLOW`, `execution_status: NOT_EXECUTED`, with the revalidation reason appended. A response that contradicts the permanent record is a forensic defect.

**Database (P0): trigger `trg_tool_executions_require_permission`, BEFORE INSERT.** Lock the decision row (`FOR UPDATE`), then require:
1. `decision = 'ALLOW'`, **or** `decision = 'REQUIRES_APPROVAL'` with at least one approval for that decision where `status = 'APPROVED' AND now() <= expires_at`;
2. `execution_status IN ('PENDING_EXECUTION','EXECUTED','FAILED','UNKNOWN')`. Together with the transition rule, this proves `PENDING_EXECUTION` was persisted first.

On failure, raise 55000. On top of the existing UNIQUE `proposal_id`, the execution grant is single-use at the database too.

**Code changes:** M1 replaces the `BLOCKED_BY_TOCTOU` row with the audit event above. M4's guard already behaves this way: on revalidation failure it returns `NOT_EXECUTED` and calls no executor.

### 3.3 OD-7: approvals

**Evidence**
- **DOC-005:** `PENDING, APPROVED, REJECTED`.
- **0003:** the approver must be a member of the same tenant.
- **M4's engine already requires approval evidence the table can't hold** (`policy.py:ApprovalEvidence`): an expiry, binding to the exact proposal, the approver's role, and single use.
- **`tool_proposals` rows are mutable for the app role.** `parameters_json` could change after approval, so the decision → proposal binding needs proposal immutability (section 7.2).
- **`tool_proposals` has no submitting user**, so "the approver is not the submitter" can't be checked at the database.

**M4 decides**

| Question | Decision |
|---|---|
| Status values | `PENDING, APPROVED, REJECTED, EXPIRED` |
| Transitions | `PENDING → APPROVED \| REJECTED \| EXPIRED`. Terminal rows are immutable. |
| How many approvals | **One** APPROVED approval executes an MVP REQUIRES_APPROVAL decision. At most one `PENDING` and at most one `APPROVED` per decision. |
| Which status permits execution | `APPROVED` only, while `now() <= expires_at` |
| Approver | Active membership (`status = 'ACTIVE'`) in the same tenant, role `SECURITY_ANALYST` or `TENANT_ADMIN`, **not the proposal's submitter**. Checked when the row becomes terminal. |
| Expiry | Every approval has `expires_at`, set by M4 (default 15 minutes after creation). Past it, the approval can only become `EXPIRED`. |
| Binding | Approval → decision → proposal. Exact-payload binding comes from immutable proposals (section 7.2), so no fingerprint column is needed. |
| Re-check at approval time | M4's engine re-evaluates the proposal with the approval (memory trust is revalidated). The result goes in an audit event `TOOL_POLICY_REEVALUATED`; `policy_decisions` keeps one immutable row per proposal. A BLOCK result moves `execution_status` to `NOT_EXECUTED`. |

**Database**
- **P0:**
  - `status IN ('PENDING','APPROVED','REJECTED','EXPIRED')`;
  - `CHECK (status = 'PENDING' OR (responded_at IS NOT NULL AND approver_user_id IS NOT NULL))`;
  - new column `expires_at timestamptz NOT NULL` (pre-check: stop if rows exist, or set existing PENDING rows to `EXPIRED` with `expires_at = now()`, which fails toward restriction; M6 chooses);
  - partial UNIQUE `(tenant_id, decision_id) WHERE status = 'APPROVED'`, and the same `WHERE status = 'PENDING'`;
  - transition/immutability trigger;
  - an approval may only be created for a decision whose `decision = 'REQUIRES_APPROVAL'`.
- **P1:**
  - `tool_proposals.submitted_by_user_id` (nullable for service agents, composite FK to memberships);
  - trigger at the terminal transition: approver ≠ submitter; approver membership `ACTIVE` with role `SECURITY_ANALYST` or `TENANT_ADMIN`.

**Code changes:**
- **M1/M2** (approval route, which doesn't exist yet): write approvals through these rules.
- **M4:** build `ApprovalEvidence` from the row, using `consumed` = an execution row exists.
- **M5:** approval UI states.

### 3.4 OD-9: audit vocabulary and `actor_id`

**Evidence**
- **DOC-005:** `event_type` examples, and `outcome` `SUCCESS, BLOCKED, DENIED, FAILED`.
- **M1:**
  - writes `TOOL_POLICY_DECIDED` with `outcome = <decision>` (ALLOW/BLOCK/REVIEW);
  - writes `INCIDENT_CREATED`, `EVIDENCE_ATTACHED`, `FORENSIC_MEMORY_ACCESSED` and `MEMORY_QUARANTINED` with `SUCCESS`;
  - uses `actor_id` = the bare `context.user_id`.
- **M4:** `DRIFT_OBSERVATION_REVIEWED`/`SUCCESS` and `FORENSIC_MEMORY_ACCESSED`. M4's system actors use a bare `process_ref`, which could collide with a user id.
- **M5:** shows `action` strings that are mock data only (`GATEWAY_PROPOSAL_BLOCKED`, …).
- **The chain is append-only and hash-linked (0009),** so a wrong value can never be corrected.

**M4 decides**
- **`actor_id`** = `user:<users.id>` | `agent:<agents.id>` | `system:<component>`, always derived server-side: from M1's verified `TenantContext`, the registered agent, or the server process.
  - `component` comes from a fixed M4 list: `gateway`, `policy-engine`, `trust-evaluator`, `quarantine`, `drift-monitor`, `recovery`, `reconciler`.
  - The prefix makes the restricting-only system actions (M4 monotone-automation rule) distinguishable from human ones in the permanent record.
- **`outcome`** has six values:
  - `SUCCESS`: the operation completed;
  - `BLOCKED`: security policy prohibited it;
  - `DENIED`: authorization (RBAC or tenant) refused the caller;
  - `FAILED`: attempted and failed;
  - `PENDING_APPROVAL`: waiting for a human;
  - `UNKNOWN`: the result can't be determined (needs reconciliation).
  - For `TOOL_POLICY_DECIDED`: ALLOW → `SUCCESS`, BLOCK → `BLOCKED`, REQUIRES_APPROVAL → `PENDING_APPROVAL`. The decision itself stays in `details_json.decision`.
- **`event_type`** is upper snake case. The registry lives in M4 code (`backend/app/security/audit_vocabulary.py`, an M4 follow-up), not in a database list, so a new event type needs no migration. Initial registry:
  - `TOOL_POLICY_DECIDED`, `TOOL_POLICY_REEVALUATED`, `TOOL_EXECUTION_ABORTED`, `TOOL_EXECUTED`, `TOOL_EXECUTION_RECONCILED`;
  - `APPROVAL_REQUESTED`, `APPROVAL_RESPONDED`;
  - `MEMORY_INGESTED`, `MEMORY_TRUST_TRANSITIONED`, `MEMORY_QUARANTINED`, `FORENSIC_MEMORY_ACCESSED`;
  - `INCIDENT_CREATED`, `EVIDENCE_ATTACHED`;
  - `DRIFT_OBSERVATION_REVIEWED`;
  - `RECOVERY_PREVIEWED`, `RECOVERY_SNAPSHOT_CAPTURED`, `RECOVERY_EXECUTED`, `RECOVERY_FAILED`.
- **`action`** is a free-form short verb phrase (max 64), never secrets or raw content.

**Database (P0). All CHECKs are added `NOT VALID`,** so existing rows (and their hashes) are untouched while every new row is checked.

```sql
actor_id ~ '^(user|agent):[A-Za-z0-9_.:-]{1,120}$|^system:[a-z][a-z0-9-]{1,40}$'
outcome IN ('SUCCESS','BLOCKED','DENIED','FAILED','PENDING_APPROVAL','UNKNOWN')
event_type ~ '^[A-Z][A-Z0-9_]{2,63}$'
```

- **Index for the trust ledger (section 7.4):** `(tenant_id, event_type, resource_id, chain_seq)`.
- **Code changes:** M1 prefixes `actor_id` and maps outcomes in its five audit writes. M4 does the same in drift, quarantine and trust.

---

## 4. Memory, sources and RBAC (OD-15, OD-19, OD-24)

### 4.1 OD-15: sources (M4 part)

**M4 decides**
- **Ingestion accepts only** `sources.status = 'ACTIVE'` with `sources.trust_state NOT IN ('QUARANTINED','REJECTED')`. Anything else is refused and audited as `MEMORY_INGESTED` / `BLOCKED`.
- **Source trust never confers record trust.** Every ingested record starts `UNVERIFIED`; only the M4 trust workflow promotes it.

**Database (P0):** `CHECK (trust_state IN ('TRUSTED','UNVERIFIED','SUSPICIOUS','QUARANTINED','REJECTED','SUPERSEDED'))` on **both** `sources` and `memory_records`. Today neither has a CHECK, so a value like `MOSTLY_TRUSTED` can be stored. M4 fails closed on it (`MEMORY_STATE_UNKNOWN`), but other readers may not.

**Code changes:** M3 ingestion enforces the rule. Exposing `sources.status` in the API is M1/M5's call.

### 4.2 OD-19: RBAC source of truth (P7) and branches (P2)

**Evidence**
- **PRD FR-003, TRD §11, DOC-005:** `TENANT_ADMIN, SECURITY_ANALYST, AI_DEVELOPER, AUDITOR`.
- **M4's Day 2 evaluator** recognises `TENANT_ADMIN, SECURITY_ANALYST, DEVELOPER`, from the Doc 06 Day 2 task wording. It deliberately denies `AI_DEVELOPER` and `AUDITOR`.
- **With M6's proposed CHECK** (the four PRD names), every `AI_DEVELOPER` would be denied by M4. That fails closed, but it breaks the product.

**M4 decides (P7)**
1. **Role names:** the four PRD names. **M4 will rename `Role.DEVELOPER` to `AI_DEVELOPER` and add `AUDITOR` (read-only)** as an M4 follow-up, after confirmation. It's a rename, not an alias: `DEVELOPER` stops being accepted.
2. **Source of truth:** `memberships.role` (P0 CHECK with the four names, as M6 proposed). Authorization uses role-name lists in M4 code. `roles`, `permissions` and `role_permissions` stay unused in the MVP; M4 sends no permission keys.
3. **No "disabled role":** change the membership's role, or set `memberships.status`.
4. **Freshness:** the JWT role is fine for reads. For privileged writes (approval response, trust promotion/release, quarantine release, recovery execution), M4 re-reads the active membership in the same transaction (GAP-007). A stale token can't approve after demotion.

**M4 decides (P2 branches;** M6's design is accepted with these answers):
- **"Head Office sees all" is not a database flag.**
  - `TENANT_ADMIN` is company-wide by role.
  - Every other role sees company-wide data (`branch_id IS NULL`) plus the branches in its `membership_branches` rows. This makes branch authorization explicit (TRD §12.1, rule 3).
  - A Head Office analyst who needs every branch gets every branch assigned.
- **No `membership_branches` row** means company-wide data only.
- **Branch ids are looked up per request**, not carried in the JWT, so revocation is immediate.
- **Branch removal:** RESTRICT plus deactivation (agree with M6).
- **For M3:** a record's branch must never be broader than its source's. A derived record takes the most restrictive branch of its parents (`NULL` counts as broadest).

**Database:** P0 is the CHECK on `memberships.role`. The P2 tables follow M6's design when M3 answers its part.

### 4.3 OD-24: memory-side cascades

**M4 decides:** memory rows are **never physically deleted**. TRD §17: exclusion "does not delete the records or their forensic lineage". Removal from use is a trust state (`QUARANTINED`/`REJECTED`/`SUPERSEDED`).

**Database (P0)**
- `ON DELETE RESTRICT` for every FK that references `memory_records` or `memory_versions`:
  - `memory_versions.record_id`;
  - `provenance_edges.from/to`;
  - `transformations.input/output`;
  - `retrieval_events.record_id`;
  - `quarantines.record_id`;
  - `checkpoint_items.record_id/version_id` (both FKs);
  - `drift_observations.record_id`.
- **Also RESTRICT**, replacing SET NULL, on `incidents.affected_record_id` and `recovery_plans.target_record_id`. SET NULL silently erases evidence linkage.
- **`memory_versions` append-only:** a trigger refuses UPDATE and DELETE. `retrieval_events` and `quarantines` are append-only too. A content/checksum rewrite through the app role is otherwise possible (GAP-011 notes SHA-256 isn't tamper-proof against that writer).

---

## 5. Recovery (OD-17, OD-21, OD-22, OD-23)

### 5.1 OD-17: rollback semantics and the checkpoint hash

**M4 decides: append a new version, never move `current_version` backwards.**
- **The restore** appends version `highest + 1`, with the checkpoint version's content and a recomputed checksum (`RecoveryTransaction.append_version`). It then moves the pointer forward with `compare_and_set_current_version(expected=<current>, new=<appended>)`.
- **Why:** M4's trust evidence is version-bound.
  - `TrustEvaluator.assess_for_action` accepts the latest TRUSTED decision only if its `record_version` **and** `version_checksum` equal the current ones.
  - Moving the pointer back to an old version could revive that version's old TRUSTED evidence and skip revalidation.
  - A new version has no evidence, so it is `UNVERIFIED` until M4 revalidates (TRD §18).
  - It also keeps the contaminated version as evidence, and version numbers stay monotone.

**Database (P0): trigger `trg_memory_records_trust_reset`, BEFORE UPDATE.** If `NEW.current_version <> OLD.current_version` and `NEW.trust_state = 'TRUSTED'`, raise 23514.
- A version change can never carry TRUSTED forward. The writer must set `UNVERIFIED`, or a more restrictive state, in the same statement.
- This matches M3's newest branch (`versioning.py` on `feat/m3-async-postgres-adapter` sets TRUSTED → UNVERIFIED on a new version), and closes the "update laundering" path at the database.

**Checkpoint `integrity_hash` (P1). M4 decides combined SHA-256, not Merkle,** because the MVP needs no inclusion proofs.

```
integrity_hash = sha256_hex( join(U+001F, [ record_id || U+001E || version::text || U+001E || checksum
                                            FOR items ORDER BY record_id ]) )
```

- `version` is `memory_versions.version` of the item's `version_id`.
- M6 provides `amsc_checkpoint_hash(tenant_id, checkpoint_id)` (database-computed, like the snapshot hash).
- Triggers:
  - `checkpoint_items.checksum` must equal `memory_versions.checksum` of its `version_id`;
  - `checkpoints` and `checkpoint_items` are immutable after the checkpoint is sealed;
  - `record_count` equals the item count.
- M4 refuses a checkpoint whose recomputed hash differs ("Validate Checkpoint Integrity Checksum", TRD §18).

### 5.2 OD-21: recovery vocabulary

**M4 decides**

| Column | Values | Rules |
|---|---|---|
| `recovery_plans.status` | `PENDING, PREVIEWED, EXECUTED, FAILED` (DOC-005) | `PENDING → PREVIEWED → EXECUTED`; `PREVIEWED → FAILED`; `FAILED → EXECUTED` (retry under the same committed snapshot, which `RewindCoordinator` supports). `EXECUTED` is terminal. A snapshot may be captured only in `PREVIEWED` or `FAILED`. |
| `recovery_actions.action_taken` | `RESTORED_TO_CHECKPOINT`, `QUARANTINED_INTERMEDIARY` (DOC-005), `RESTORED_RECORD_TRUSTED`, `RESTORED_RECORD_UNVERIFIED`, `EXTERNAL_ACTION_IRREVERSIBLE` | `RESTORED_RECORD_TRUSTED` is written only after M4's revalidation promotes the new version (M4 trust ledger entry exists) |
| `recovery_actions.outcome` | `SUCCESS`, `REQUIRES_COMPENSATION` | `REQUIRES_COMPENSATION` only with `EXTERNAL_ACTION_IRREVERSIBLE`. **Remove the `'SUCCESS'` default.** |

- **The trust state of restored records** is `UNVERIFIED` after the restore (guaranteed by the 5.1 trigger). It becomes `TRUSTED` only through the M4 trust workflow (VALIDATE, with an assessment bound to the new version and checksum). If revalidation fails or is uncertain, the record stays `UNVERIFIED` or is quarantined.
- **A failed rollback** rolls back transaction 2 entirely. M4 then sets `status = 'FAILED'` and appends `RECOVERY_FAILED` in a separate transaction, so failure evidence exists without partial actions.
- **API wording:** Doc 03 shows the execute response `status: 'COMPLETED'`. M4 uses the stored value `EXECUTED` in the API too (M1/M5 sign-off).

**Database (P0)**
- CHECKs on all three columns.
- Plan transition trigger.
- `CHECK ((status = 'EXECUTED') = (executed_at IS NOT NULL))`. The existing `executed_requires_snapshot` CHECK stays.
- Drop the `outcome` default.
- **M6 code:** `RewindCoordinator.execute_rollback` sets `status = 'EXECUTED'` in the same UPDATE as `executed_at`. Today it sets only `executed_at`, which would violate the new CHECK.

### 5.3 OD-22: owner of `api/recovery.py`

- **Evidence:**
  - `ownership.md` (lines 22, 89, 183–197) and `backend/owner.md` (lines 19, 22) give `recovery/` and `api/recovery.py` to **M4**;
  - DOC-006 :171 lists `api/recovery.py` as the M6 Day 5 deliverable;
  - M6 delivered the database layer only (`RewindCoordinator`), which is the right split.
- **M4 decides (project owner to confirm):**
  - M4 owns `backend/app/recovery/` (preview, impact, revalidation, trust outcome, honest classification) and `api/recovery.py`;
  - M4 builds strictly on M6's `RewindCoordinator` and `UnitOfWork`, with no second rollback or persistence path;
  - M6 keeps the database layer.

### 5.4 OD-23: irreversible external actions

**M4 decides: no new table.**
- **At preview,** M4 counts every `tool_executions` row whose proposal's `memory_refs_json` names the target or any downstream record, executed after the checkpoint's `created_at`.
  - All statuses count (`SUCCESS`, `FAILED`, `UNKNOWN`): a failed or unknown external call may still have had an effect, and the analyst decides.
  - The count goes in `impact_preview_json.irreversible_external_actions` (the DOC-005 §6.3 field).
- **At execution,** in transaction 2, M4 records one `recovery_actions` row per such execution: `action_taken = 'EXTERNAL_ACTION_IRREVERSIBLE'`, `resource_id = tool_executions.id`, `outcome = 'REQUIRES_COMPENSATION'`.
- **Database:** nothing beyond 5.2. An index for the JSON lookup can wait until volume shows a need (P2: a GIN index on `tool_proposals.memory_refs_json`).

---

## 6. Other items

### 6.1 OD-26: external anchoring of the audit chain

- **M4 decides:** Phase 2, as the TRD says (:517). It isn't part of the integration migration.
- **Accepted risk until then:** a database superuser can rebuild a whole chain or cut its tail undetected. M6 has proven this limit with a test.
- **Interim mitigation, for M7 later:** a scheduled export of `(tenant_id, chain_seq, event_hash)` heads to write-once storage outside the database, plus a verification job.
  - The rule for verification is that a later export must extend an earlier one: same `event_hash` at every earlier `chain_seq`.
  - M4 will supply that check.

### 6.2 OD-5: `tool_executions.status` (M2-owned; M4 security input only)

- The row means "the adapter was invoked" (OD-6), so `BLOCKED_BY_TOCTOU` is not a valid status.
- **Remove the defaults** `status = 'SUCCESS'` and `status_code = 200`. A writer that forgets them would record a success that never happened. Make both required.
- **Rows are immutable,** except `UNKNOWN → SUCCESS | FAILED` reconciliation, which must be audited (`TOOL_EXECUTION_RECONCILED`).

---

## 7. Further rules M4 needs in the same migration

| # | Rule | Why | Priority |
|---|---|---|---|
| 7.1 | Remove fail-open defaults:<br>• `tool_executions.status 'SUCCESS'` and `status_code 200` (6.2)<br>• `recovery_actions.outcome 'SUCCESS'` (5.2)<br>• `drift_observations.divergence_score '0.78'` and `classification 'POTENTIAL_POISONING'` | A missing value must fail, not invent evidence. A fabricated drift score of 0.78 is classified by M4 as a real score. | P0 |
| 7.2 | `tool_proposals` immutable (trigger: no UPDATE, no DELETE) | Approval and decision bind to the proposal. Today the app role could change `parameters_json` (for example `amount`) after approval or ALLOW. | P0 |
| 7.3 | `memory_records.trust_state` / `sources.trust_state` CHECK (4.1); `memory_versions` append-only (4.3) | Unknown states and content rewrites | P0 |
| 7.4 | **Durable M4 trust ledger.** M4's `TrustEvaluator` refuses its in-memory store in production, and no table exists. M4 decides to persist trust decisions as audit events, not as a new table:<br>• `event_type = 'MEMORY_TRUST_TRANSITIONED'`, `resource_id = record_id`;<br>• `details_json` holds from/to state, rule id, `record_version`, `version_checksum`, `trust_decision_id` and `assessment_id`.<br>M6 adds the index `(tenant_id, event_type, resource_id, chain_seq)` (3.4). The hash chain then also protects trust history. | Without it, no production deployment has version-bound evidence, and M4 fails closed (every protected action blocks) | P0 |
| 7.5 | An approval may exist only for a `REQUIRES_APPROVAL` decision (3.3) | Approval on ALLOW/BLOCK is meaningless and confuses the OD-6 trigger | P0 |

---

## 8. Ordered checklist for M6's integration migration

**Pre-checks** (stop and list ids on any violation; never rewrite permanent rows):
- decisions outside the vocabularies or the consistency rule;
- approvals without `expires_at` (choose: stop, or expire);
- unknown `trust_state` values;
- plans whose `status` and `executed_at` disagree;
- memory FK children (RESTRICT can always be added; no data change).

**P0:**
1. `policy_decisions`:
   - CHECKs on `decision`, `memory_trust`, `policy_result`, `execution_status`;
   - `ck_policy_decisions_consistent`;
   - insert rule and forward-only transition trigger, replacing 0009's "execution_status freely mutable".
2. `tool_executions`: permission trigger (3.2); drop the `status` and `status_code` defaults.
3. `approvals`: status CHECK; responded CHECK; `expires_at`; partial UNIQUEs; transition/immutability trigger; parent decision must be `REQUIRES_APPROVAL`.
4. `tool_proposals`: immutability trigger.
5. `audit_events`: `NOT VALID` CHECKs on `actor_id`, `outcome`, `event_type`; trust-ledger index.
6. `memory_records`, `sources`: `trust_state` CHECK; trust-reset trigger on `current_version` change.
7. Memory-side FKs to RESTRICT; `memory_versions`, `retrieval_events`, `quarantines` append-only.
8. `memberships.role` CHECK (four PRD names).
9. `recovery_plans`: status CHECK, transition trigger, `status ⇔ executed_at` CHECK. `recovery_actions`: `action_taken`/`outcome` CHECKs; drop the `outcome` default. `RewindCoordinator` sets `status`.
10. `drift_observations`: drop the fabricated defaults.

**P1:**
- decision memory-refs trigger (2.2);
- deferred execution-existence check (3.1);
- `tool_proposals.submitted_by_user_id` and the approver trigger (3.3);
- checkpoint hash function and checkpoint triggers (5.1).

**P2:** branch tables (M6's P2 design); GIN index on `memory_refs_json`.

`roles.py`: no grant change is needed. The app role keeps `UPDATE (execution_status)`, now constrained by the trigger, and has no UPDATE on the newly immutable tables beyond what the triggers allow.

---

## 9. M4's own follow-ups (not done in this task)

1. ~~`PolicyDecision.initial_execution_status`: ALLOW → `PENDING_EXECUTION`.~~ Done 2026-11-18 (see 3.1).
2. Rename `Role.DEVELOPER` → `AI_DEVELOPER`; add `AUDITOR` with read-only routes. Needs confirmation, because the Day 2 scope named `DEVELOPER`.
3. `actor_id` prefixes and outcome mapping in `drift.py`, `quarantine.py` and `trust.py`; add `backend/app/security/audit_vocabulary.py`.
4. Audit-backed trust decision store (7.4) on M6's `UnitOfWork` / `tx.audit`.
5. Approval wiring: `ApprovalEvidence` from the `approvals` row; `TOOL_POLICY_REEVALUATED`.
6. `backend/app/recovery/` and `api/recovery.py` on `RewindCoordinator` (after OD-22 confirmation).
7. ~~Package-level `backend.app.memory` imports (earlier review finding RV-1).~~ Done 2026-11-19 after the rebase onto `main`.

## 10. What was verified, and what was not

- **Verified by execution:** `backend/tests/security/test_db_contract.py`, 86 passed after the OD-4 fix (it was 66 passed and 1 xfailed before).
  - It checks every M4-persisted value against the vocabularies above, the consistency CHECK (as a Python mirror) and honest `memory_trust` labels, across 15 scenarios.
  - Mutation check: `REVIEW` as decision (4 failures), ELEVATED→PERMITTED (1), all labels TRUSTED (9), ALLOW initial PENDING_APPROVAL (2). All caught.
- **Not verified:**
  - No SQL in this document was run. There is no PostgreSQL in this environment, and the migration is M6's.
  - M1 behaviour in section 2.2 (the `ValueError` on REJECTED, the SUPERSEDED → ALLOW row) is from reading the code at `650fe10`, not from running it.
  - No M2 code exists to check.
