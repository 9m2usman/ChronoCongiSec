# M4 Day 6 — Drift Monitor: Deterministic Scoring & Analyst Review

> **Update 2026-11-19:**
> - **M4-F3:** listing now requires a canonical role (`READER_ROLES`, incl. read-only `AUDITOR`) at both the route and the service.
> - **M4-F4:** the review audit event's `actor_id` is `user:<id>` (OD-9).
> - The router is still **not registered** in `main.py` (M1), and the PostgreSQL adapter tests are still skipped (no database).

**Document ID:** AMSC-SEC-006
**Owner:** M4 — Security Engine & Incident Response Lead
**Status:**
- The scoring, review service, API router and PostgreSQL adapter are implemented. The logic, authorisation, tenant isolation, atomicity and concurrency are tested.
- **Persistence against real PostgreSQL is NOT TESTED** in this environment: no PostgreSQL server was available (§9).
- **Router registration in `main.py` is pending M1** (§8).

**Date:** 2026-11-18
**Plan reference:** Doc 06 §3 Day 6, M4 row: *"Implement Drift Monitor observation review and scoring endpoints"*, `api/drift.py`. Dependency: M6 Drift tables. Exit: *Drift observation review persists analyst status.*

| Artifact | Path |
|---|---|
| Scoring, review service, PostgreSQL store adapter | `backend/app/security/drift.py` |
| API router (canonical routes only) | `backend/app/api/drift.py` |
| Scoring, state-machine and SQL tests | `backend/tests/security/test_drift_scoring.py` |
| HTTP tests (M1 authentication, transactional store contract) | `backend/tests/security/test_drift_api.py` |
| PostgreSQL integration tests (skip without `TEST_DATABASE_URL`) | `backend/tests/security/test_drift_postgres.py` |

---

## 1. Requirement mapping

| Requirement | Canonical source | Existing | Implemented | Test |
|---|---|---|---|---|
| List the tenant's observations | Doc 05 §5.1 `GET /drift/observations` (Member) | M6 model only | `list_drift_observations` (any member, bounded) | `test_list_*`, `test_each_tenant_sees_only_its_observations` |
| Review with `{status}` | Doc 05 §5.1 `POST /drift/observations/{id}/review` (`SECURITY_ANALYST`) | — | `review_drift_observation` | `test_authorized_review_persists_and_audits` |
| Only analysts or admins review | Doc 04 Screen 08 §12 | Day 2 RBAC | `require_role_access(SECURITY_ANALYST, TENANT_ADMIN)` at the route **and** in the service | `test_unauthorized_roles_cannot_review`, `test_service_enforces_reviewer_role_without_http_layer` |
| Review persists status and emits an audit event | Doc 04 Screen 08 §15; Doc 06 exit | M6 `UnitOfWork`, `tx.audit.append` | One transaction: lock, compare-and-set, audit | API tests (contract); PG tests (**not run**) |
| Scoring is deterministic and explainable | Doc 06 Day 6; Doc 07 §2.7, §3.6 | — | `assess_observation` | `test_drift_scoring.py` |
| Classifications | Doc 04 Screen 08 §5 | DB default `POTENTIAL_POISONING` | `DriftClassification` (4 values) | `test_priority_matrix` |
| Reviewer statuses | Doc 04 Screen 08 §5; Doc 05 | DB default `PENDING` | `ReviewerStatus` + state machine | `test_review_state_machine` |
| Tenant isolation | FR-001, SEC-004 | M1 `TenantContext`, M6 tenant-scoped repositories | Tenant from context only; every SQL statement tenant-filtered | Section C tests, SQL compile tests |
| No competing model or table | Prompt §5 | `DriftObservation` (M6) | Reused unchanged | — |

---

## 2. Where this fits in AMSC

```text
(future detector / M3 ingestion diff) ──writes──► drift_observations (M6)  ◄── record_id ──► memory_records
                                                         │
GET  /drift/observations ── M1 auth ─► DriftReviewService.list ─► SqlDriftReviewStore (UnitOfWork, tenant-scoped)
                                                         │   + assess_observation(row)   (triage only)
POST /drift/observations/{id}/review ── M1 auth + Day 2 RBAC ─► DriftReviewService.review
        └─ one transaction: SELECT … FOR UPDATE → decide_review → UPDATE … WHERE reviewer_status=<locked> → tx.audit.append
REJECTED ⇒ follow_up = QUARANTINE_DECISION_REQUIRED ─(separate, explicit)─► Day 5 QuarantineWorkflow
```

**No observation generator exists yet** (no detector writes `drift_observations`). This deliverable reviews and scores stored observations; it does **not** invent detection, embeddings or vector results. Doc 06 §6 permits relational or string matching instead of embeddings, but building the detector isn't the Day 6 M4 task.

---

## 3. Scoring (triage, not a verdict)

`assess_observation(row, policy)` is pure and deterministic.

**1. Validate the stored evidence.**
- `divergence_score` is `VARCHAR(32)` in the M6 model (with a schema default of `'0.78'`). Only a plain decimal in `[0, 1]` with up to 6 fraction digits is accepted (`^(0(\.\d{1,6})?|1(\.0{1,6})?)$`).
- `-0.1`, `1.2`, `NaN`, `Infinity`, `1e-1`, padded strings, floats, booleans and empty values are all **invalid**. They are never clamped.
- `classification` must be one of the four Screen 08 values (exact case).
- `evidence_summary` must be non-blank.

**2. Missing or malformed evidence** gives priority `TRIAGE_REQUIRED` (the highest attention), never LOW.

**3. Otherwise:**

| Classification | Score ≥ threshold | Score < threshold |
|---|---|---|
| `POTENTIAL_POISONING` | HIGH | MEDIUM |
| `CONFLICTING_SOURCES` | MEDIUM | LOW |
| `OUTDATED` | MEDIUM | LOW |
| `LEGITIMATE_UPDATE` | MEDIUM (the detector's "legitimate" label is itself unverified evidence) | LOW |

- **The threshold** is `review_threshold = 0.35`. This is the anomaly threshold *displayed* on Doc 04 Screen 08, and it is **provisional and uncalibrated** (`scoring_policy_version = amsc-drift-scoring/1.0.0-provisional`). A score exactly at the threshold counts as exceeding it.
- **The output** contains: `valid_evidence`, `score` (canonical string), `classification`, `exceeds_review_threshold`, `review_threshold`, `priority`, `reason_codes`, `scoring_policy_version` and `is_verdict: false`. It **never copies evidence text**.

**What the assessment is not.** It isn't an authorisation input, it doesn't change trust state, and a high score isn't proof of poisoning. No ML model, embedding or LLM is involved. `anomaly_confidence` is **not produced**, because no source for it exists and fabricating it is prohibited.

---

## 4. API contract

All routes are under the project prefix, `/api/v1`, and use the standard M1 error envelope.

### `GET /drift/observations`
- **Auth:** any active member of the tenant (Doc 05 "Member"); tenant from M1's `TenantContext`.
- **Query:** `limit` 1–100 (default 50), `offset` ≥ 0, `classification` (one of the 4), `reviewer_status` (`PENDING|APPROVED|REJECTED`). Anything else is 400. `tenant_id` query values are ignored.
- **Response 200:** a JSON array (same shape as the existing frontend client expects: an array), ordered by `id` (M6 repository order):

```json
[{
  "id": "obs-…", "tenant_id": "…", "record_id": "mem-…",
  "classification": "POTENTIAL_POISONING", "divergence_score": "0.78",
  "evidence_summary": "…", "reviewer_status": "PENDING", "created_at": "2026-11-18T…Z",
  "assessment": {"valid_evidence": true, "score": "0.78", "classification": "POTENTIAL_POISONING",
                 "exceeds_review_threshold": true, "review_threshold": "0.35", "priority": "HIGH",
                 "reason_codes": ["CLASSIFIED_POTENTIAL_POISONING", "SCORE_AT_OR_ABOVE_REVIEW_THRESHOLD"],
                 "scoring_policy_version": "amsc-drift-scoring/1.0.0-provisional", "is_verdict": false}
}]
```

- **Errors:** 401 unauthenticated; 403 forged `X-Tenant-ID` (M1); 400 invalid query; 503 store unavailable, service not configured, or the store returned a row from another tenant.

### `POST /drift/observations/{id}/review`
- **Auth:** `SECURITY_ANALYST` or `TENANT_ADMIN`, through the Day 2 `require_role_access` at the route, re-checked in the service. The JWT role claim is ignored; the role comes from the membership.
- **Path:** `id` matches `^[A-Za-z0-9_.:\-]{1,128}$`.
- **Body:** `{"status": "APPROVED" | "REJECTED"}` (`extra="forbid"`: `tenant_id`, `actor_id`, `reviewer_status` and similar are rejected).
- **Response 200:**

```json
{"outcome": "APPLIED", "previous_status": "PENDING",
 "observation": { …same shape as the list item… },
 "audit_event_id": "…", "follow_up": "QUARANTINE_DECISION_REQUIRED", "policy_version": "amsc-drift-review/1.0.0"}
```

- **`outcome`:** `APPLIED`, or `UNCHANGED` for an idempotent repeat (`audit_event_id: null`, no new audit event).
- **`follow_up`:** advisory only. `REJECTED` gives `QUARANTINE_DECISION_REQUIRED`; `APPROVED` gives `NO_TRUST_CHANGE`.
- **Errors:** 400 invalid body or id; 401; 403 role, or forged tenant header; 404 not found (identical for another tenant's id); 409 conflict (already reviewed with a different decision, lost compare-and-set, or unknown stored status); 503 store or audit failure (nothing committed).

**No separate scoring route.** Doc 05 lists only the two routes above, so scoring is delivered inside both responses. A dedicated route would need M1/M5 agreement (Doc 05 §8).

---

## 5. Review state machine and concurrency

| Stored status | Request | Result |
|---|---|---|
| `PENDING` | `APPROVED` or `REJECTED` | **APPLIED**: status written, audit appended |
| `APPROVED` | `APPROVED` | **UNCHANGED** (idempotent; no write, no audit) |
| `REJECTED` | `REJECTED` | **UNCHANGED** |
| `APPROVED` | `REJECTED` (or the reverse) | **409**. Changing a recorded decision needs an explicit re-review policy, which isn't defined. |
| Anything else (e.g. `ESCALATED`, `pending`) | any | **409** (fail closed) |
| any | `PENDING` | **400**. A review can't revert to pending. |

**Meaning of the statuses** (Screen 08 §6). APPROVED is "Accept Change": the change is a legitimate update. REJECTED is "Reject & Quarantine": the change is treated as potential poisoning.

**Concurrency.** The adapter holds a row lock (`SELECT … FOR UPDATE`) and then runs a compare-and-set `UPDATE … WHERE tenant_id = :t AND id = :id AND reviewer_status = :locked_status RETURNING id`:
- If two reviewers race, the second waits on the lock, then sees the committed decision: UNCHANGED if it's the same decision, 409 if different.
- A compare-and-set that matches no row raises a conflict and rolls back.

Tested with `asyncio.gather` against the transactional test store, and in `test_drift_postgres.py` against PostgreSQL (not run here).

**Reviewer status is not memory trust state.** APPROVED never promotes memory, and REJECTED never quarantines (tested: the linked record stays `SUSPICIOUS`). Quarantine is the explicit Day 5 workflow, triggered by M1/M5 as a separate call after `QUARANTINE_DECISION_REQUIRED`.

---

## 6. Transaction and audit

Everything happens in one M6 `UnitOfWork(tenant_id)`. This sets `app.tenant_id` transaction-locally, commits on success and rolls back on any exception.

1. Tenant-filtered row lock. If no row is found, return 404, with nothing written and no audit.
2. `decide_review` (pure).
3. For APPLY: compare-and-set the status. If no row matches, a conflict rolls everything back.
4. `tx.audit.append(AuditEvent(...))`. The table is append-only and hash-chained by migration 0009, which assigns `chain_seq`, `prev_hash` and `event_hash`. **If the audit append fails, the status change is rolled back** and the response is 503.

**Audit event fields:**
- `event_type="DRIFT_OBSERVATION_REVIEWED"`, `action="REVIEW"`, `outcome="SUCCESS"`;
- `actor_id` from `TenantContext.user_id`;
- `resource_id` = the observation id;
- `trace_id` from M1's `get_trace_context` (validated format).

**`details_json`** contains:
- `observation_id`, `record_id`;
- `previous_status`, `new_status`;
- `classification`, `divergence_score` and the assessment;
- `actor_role`, `reviewed_at`, `review_policy_version`;
- `memory_trust_changed: false`.

**No evidence text, secrets or tokens** are stored.

**Why the audit event is the review record.** `drift_observations` has no `reviewed_by` or `reviewed_at` columns. Adding them would need an M6 migration, which wasn't requested (§10).

---

## 7. Frontend contract (M5): mismatches to resolve. No data is fabricated.

| `frontend/src/types/drift.ts` | Canonical / this API | Proposed handling |
|---|---|---|
| `cosine_divergence: number` | `divergence_score: string` (VARCHAR in M6); `assessment.score` (canonical decimal string) | M5 renders `assessment.score`. Don't relabel it "cosine" unless the generator really computes cosine distance. |
| `anomaly_confidence: string` | **Not available** (no source) | Remove, or show "—". Not fabricated. |
| `status: HIGH_DRIFT \| MODERATE_DRIFT \| NORMAL` | Two separate concepts: `reviewer_status` (`PENDING/APPROVED/REJECTED`) and `assessment.priority` (`TRIAGE_REQUIRED/HIGH/MEDIUM/LOW`) | Map the badge to `assessment.priority`; show `reviewer_status` separately. **Never map one onto the other.** |
| `record_name`, `baseline_doc` | Not in the schema | Join through M3 (record or ChroniMem) if needed; not added here |
| `observed_at` | `created_at` | Rename |
| — | `classification`, `evidence_summary` | Add (Screen 08 §5 shows both) |

The frontend client currently calls `GET /drift/observations` and falls back to fixtures on error. M5 must not treat a fixture as backend truth, and the review buttons need the role gating from Screen 08 §12. That's cosmetic only; the server enforces it.

---

## 8. Integration handover

**M1 (`main.py`, router registration and app state).** Not edited by M4:

```python
from backend.app.api.drift import router as drift_router
from backend.app.database.session import create_engine, create_session_factory
from backend.app.security.drift import DriftReviewService, SqlDriftReviewStore

session_factory = create_session_factory(create_engine())          # M6
app.state.drift_service = DriftReviewService(SqlDriftReviewStore(session_factory))
api_router.include_router(drift_router)
```

Without `app.state.drift_service`, both routes return 503 (fail closed, tested).

**M6:**
- Optionally absorb the two statements in `drift.py` (`build_lock_statement`, `build_compare_and_set_statement`) into a `DriftObservationRepository`.
- Run `test_drift_postgres.py` in the PostgreSQL CI job (it uses M6's helpers).
- Consider these for the vocabulary owners (OD-1…OD-9): CHECK constraints on `drift_observations.reviewer_status` and `classification`, and a numeric `divergence_score`.
- Optional `reviewed_by` / `reviewed_at` columns, if reads without the audit table are needed.

**M5:** §7.

**M7:** run the PostgreSQL drift tests and the three-company isolation suite against the registered router.

---

## 9. Verification (executed 2026-11-18)

Environment: Python 3.14.5, pinned requirements except `asyncpg` (0.29.0 can't build on 3.14; the scratch venv has 0.32.0 only so the SQL modules import). Branch `feat/m4-security-ml`, merged with `origin/main` @ `2b3f738` (M6 Day 4–7).

| Command | Result |
|---|---|
| `pytest backend/tests/security/test_drift_scoring.py backend/tests/security/test_drift_api.py` | **156 passed** |
| `pytest backend/tests/security/test_drift_postgres.py` | **5 skipped: NOT TESTED** (no `TEST_DATABASE_URL`, no PostgreSQL server) |
| `pytest backend/tests/security` (Days 2–6) | **766 passed, 5 skipped, 2 xfailed** |
| `pytest --ignore=backend/tests/database` (full suite) | **940 passed, 5 skipped, 2 xfailed**; no existing test modified |
| `pytest backend/app/memory/tests -k "gap or quarantin"` | 12 passed (GAP-001..004) |
| `pytest backend/tests/database` (M6) | **Not run:** needs PostgreSQL |
| Mutation check | 8 injected regressions. The first run caught **6 of 8**: the two survivors exposed missing *service-level* tests for role and status validation (masked by route-level checks). Tests were added, and a re-run catches 8 of 8. |

**Environment limitation.** I tried to obtain a local PostgreSQL by extracting the binaries bundled in the `pgserver` wheel. That action was **blocked by the session's permission policy** (executing downloaded binaries), and the download was deleted. There's no Docker or local PostgreSQL. The real-database behaviour (commit, rollback, `FOR UPDATE` blocking, audit hash chain) is therefore **not verified here**. It is covered by the transactional contract tests, by SQL compiled against the PostgreSQL dialect, and by the ready-to-run PG tests.

---

## 10. Research alignment

These are AMSC implementation decisions informed by the sources below. None of the sources' results are claimed.

| Principle | Source (status) | Decision | Limitation | Test |
|---|---|---|---|---|
| Poisoning can look valid at ingestion and surface later | [MINJA](https://arxiv.org/abs/2503.03704) (NeurIPS 2025) | Drift is reviewable evidence over time, not an ingestion gate | No detector yet generates observations | — |
| Judge consequences, not one detector score | [MemPoison](https://arxiv.org/abs/2607.14651), [MemSecBench](https://arxiv.org/abs/2607.27080) (preprints) | Scores give triage priority only; `is_verdict=false`; trust and actions remain with Day 3/4 | Priorities are uncalibrated | `test_priority_matrix`, `test_review_does_not_touch_memory_trust` |
| Thresholds are heuristics until calibrated | Doc 07 §3.6; KnowledgeLine lessons | 0.35 marked provisional and versioned; never used for authorisation | Needs a calibration set | `test_threshold_boundaries` |
| Stale memory can be worse than none; supersession claims need evidence | When Memory Lies (arXiv 2608.04574); ToxicRAG (arXiv 2609.11082), preprints per Doc 07 | `OUTDATED` and `LEGITIMATE_UPDATE` with a high score are not dismissed (MEDIUM) | Labels come from an unverified generator | `test_priority_matrix` |
| Verifiers are diagnostic; they never promote trust | [TrustMem](https://aclanthology.org/2026.findings-emnlp.2419/) (Findings of EMNLP 2026) | APPROVED doesn't touch trust state | — | `test_review_does_not_touch_memory_trust` |
| Lineage and authorisation continuity | [MemLineage](https://arxiv.org/abs/2605.14421) (preprint); AkasicMEM is cited by Doc 07 but was **not found** in this project's searches and is not relied on | `record_id` is kept; review never rewrites evidence; derived-record restrictions stay with Day 3/4 | — | `test_review_preserves_evidence_fields` |
| Attribution is a hypothesis until corroborated | AgentHallu (EMNLP 2026, per Doc 07; not re-verified this session) | Review records the analyst's decision; it does not auto-attribute cause | — | — |
| Trace correlation | OpenTelemetry GenAI semconv (Doc 07 §7) | `trace_id` from M1's validated trace context is stored on the audit event | No span is emitted (Dual Trace is M1's) | `test_authorized_review_persists_and_audits` |
| Broken access control, zero trust, least privilege | [OWASP Top 10 2025 A01](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/), [OWASP API1/API5:2023](https://owasp.org/projects/api-security-project), [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Per-request authorisation; object-level tenant filter in SQL; role re-checked in the service | — | Section C tests, `test_service_enforces_*` |

---

## 11. Remaining issues

| ID | Owner | Issue |
|---|---|---|
| DR-1 | M1 | Register the router and `app.state.drift_service` (§8). Until then, the endpoints aren't reachable in the real app. |
| DR-2 | M6 / M7 | Run `test_drift_postgres.py` against PostgreSQL. Persistence, rollback and locking aren't verified on a real database. |
| DR-3 | — | No drift observation generator exists. The Drift Monitor has nothing to review until a detector, or M3's change diff, writes `drift_observations`. |
| DR-4 | M5 | Frontend type mismatches (§7). |
| DR-5 | M6 / M4 | `divergence_score` is a string column; there are no CHECK constraints on status or classification, and no `reviewed_by` / `reviewed_at`. |
| DR-6 | Project | Calibrate the 0.35 threshold on representative data before using it for anything beyond ordering. |
| DR-7 | M1 / M6 | No branch attribute, so reviews are tenant-scoped, not branch-scoped (Day 1 D-09). |
