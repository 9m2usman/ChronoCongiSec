# M4 Day 5 — Quarantine Security Workflow & Forensic Access

> **Update 2026-11-19:**
> - **F-1** is fixed on `main` by M3: `update_memory` refuses QUARANTINED, REJECTED and SUPERSEDED.
> - The forensic-access audit event's `actor_id` is `user:<id>` (M4-F4).
> - Trust transitions used by quarantine are race-safe (M4-F5); a version change mid-quarantine is retried, not lost.
> - Recovery is documented in [recovery-workflow.md](recovery-workflow.md).

**Document ID:** AMSC-SEC-005
**Owner:** M4 — Security Engine & Incident Response Lead
**Status:** Implemented and tested in M4-owned code.
- **The M1 REST integration is pending:** M1's Day 5 branch still uses its own in-place quarantine path (§8).
- The whole-team G5 slice also needs M3 (ChroniMem) and M6 (atomic rollback).

**Date:** 2026-11-17
**Plan reference:** Doc 06 §3, Day 5, M4 row: *"Implement quarantine workflow: exclude quarantined records from retrieval queries"*. Dependency: *M3 Memory API*. Exit: *Retrieval queries omit quarantined records.*
**Builds on:** Day 1 [policy-evaluation-matrix.md](policy-evaluation-matrix.md) §7.8; Day 2 [rbac-design.md](rbac-design.md); Day 3 [trust-state-machine.md](trust-state-machine.md); Day 4 [policy-engine.md](policy-engine.md).

| Artifact | Path |
|---|---|
| Workflow, forensic access, M1-compatible surface | `backend/app/security/quarantine.py` |
| Tests | `backend/tests/security/test_quarantine_workflow.py` |

---

## 1. Requirement mapping

| Requirement | Source | Where | Evidence (test) |
|---|---|---|---|
| Only analysts/admins quarantine; server-side context | FR-018, Doc 05 §5.1, prompt §4.1 | `QuarantineWorkflow._authorize` (Day 2 RBAC) | `test_authorized_roles_*`, `test_unauthorized_roles_cannot_quarantine`, `test_spoofed_request_fields_rejected` |
| Tenant-scoped resolution; no cross-tenant disclosure | FR-001, SEC-004 | `_load` | `test_cross_tenant_quarantine_denied_and_indistinguishable` |
| Transition through the M4 trust interface, approved matrix only | TRD §15.3, Doc 06 M3 constraint | `TrustEvaluator.apply` (T-04 / T-07 / T-10 / T-16a) | `test_quarantine_from_each_state` |
| Idempotent; no duplicate transitions or evidence | prompt §4.2 | Already-quarantined short-circuit | `test_retry_after_timeout_is_idempotent`, `test_concurrent_quarantine_applies_once` |
| Explainable, attributable decision | TRD §15.3, FR-027 | `QuarantineOutcome`, `to_audit_details`, `to_quarantine_row` | `test_incident_and_evidence_refs_are_recorded` |
| Versions and provenance preserved | Doc 07 §2.5 | No content or edge writes | `test_versions_and_provenance_are_preserved` |
| **Immediate exclusion from normal retrieval** | FR-011, SEC-005, **Day 5 exit** | M3 trusted-only invariant (unchanged), proven at repository, service, agent-scoped, pagination, filter, HTTP list, HTTP detail and gateway layers | §4 tests |
| Forensic access separate, authorised, audited | FR-011, GAP-012, GAP-031 | `ForensicAccess.read` | `test_analyst_forensic_read_is_audited_before_read_*` and related |
| Fail closed; no false success | OBJ-003, prompt §5 | Outcome statuses (§6) | section F tests |
| Integration contract for M1 | Doc 06 Day 5 (M1) | §8 | M1 suite run against this module (§9) |

---

## 2. Quarantine decision flow

```text
M1 route (require analyst/admin)                         M4 QuarantineWorkflow.quarantine(context, request, persist_evidence, invalidate_cache?)
  │                                                         1. strict request (extra="forbid": no tenant/actor/role fields)
  │                                                         2. verified TenantContext + Day 2 RBAC (SECURITY_ANALYST | TENANT_ADMIN)
  │                                                         3. tenant-scoped get_record  ── missing / other tenant ──► DENIED RECORD_NOT_FOUND
  │                                                         4. effective state (Day 3, history-aware)
  │                                                            ├─ QUARANTINED ─► ALREADY_QUARANTINED (no new transition, no evidence row;
  │                                                            │                  stored state reconciled if relaxed out of band)
  │                                                            ├─ REJECTED ────► DENIED REJECTED_IS_TERMINAL
  │                                                            └─ else: Day 3 matrix rule (SUPERSEDED requires incident)
  │                                                         5. TrustEvaluator.apply(QUARANTINE)  ── stale ──► re-read, retry once
  │                                                            (state write + append-only M4 decision; reverted if the decision can't be recorded)
  │                                                         6. post-condition: stored AND effective == QUARANTINED
  │                                                         7. invalidate_cache(tenant, record)       (optional; failure ⇒ not success)
  │                                                         8. await persist_evidence(outcome)        (M1/M6 quarantines row + MEMORY_QUARANTINED audit)
  ▼                                                         ⇒ QuarantineOutcome
raise_for_outcome(outcome) → 200 / 400 / 403 / 404 / 409 / 503
```

**Evidence basis.** The Day 3 trust decision records:
- actor and role;
- `[reason_code] reason`;
- evidence references: the client's references plus `incident:<id>`, or, when no external evidence is supplied, an explicitly labelled `attestation:<reason_code>`;
- version, policy version and timestamp.

Analyst notes and the reason are stored, **never logged**.

**Containment, not a verdict.** Quarantine contains a record; it doesn't assert confirmed compromise. Confirmed malice is a separate REJECT decision (Day 3 T-13), and `reason_code` classifies the trigger. This keeps the PRD/Master-prompt distinction between a suspected threat and a confirmed incident.

---

## 3. Authorisation, tenant isolation and the transition matrix

- **Authorisation:**
  - The only inputs are M1's verified `TenantContext` and `evaluate_role_access(context, (SECURITY_ANALYST, TENANT_ADMIN))`.
  - Denied: `DEVELOPER`, `AI_DEVELOPER`, `AUDITOR`, lower-case or unknown roles, inactive or missing context.
  - Any client field named `tenant_id`, `actor_id`, `role`, `quarantined_by` or `authorized` is rejected outright (`REQUEST_INVALID`).
  - Agent principals don't exist yet (Day 1 D-04), so no agent credential can satisfy the role check.
- **Tenant isolation:**
  - A cross-tenant id and a missing id give an identical `RECORD_NOT_FOUND`, with no state, version or checksum disclosed.
  - Tenant B's analyst can't touch tenant A's records.
  - Branch rules aren't applied, because neither `TenantContext` nor the schema carries a branch (Day 1 D-09).

| From (effective) | Result | Transition |
|---|---|---|
| UNVERIFIED | QUARANTINED | T-04 |
| TRUSTED | QUARANTINED | T-07 |
| SUSPICIOUS | QUARANTINED | T-10 |
| QUARANTINED | ALREADY_QUARANTINED (idempotent) | — |
| REJECTED | DENIED `REJECTED_IS_TERMINAL`. Already more restrictive; never relabelled. | — |
| SUPERSEDED | QUARANTINED with `incident_id`; otherwise DENIED `INCIDENT_REQUIRED` | T-16a |

**No path to TRUSTED.** Nothing here can produce TRUSTED (`test_quarantine_never_produces_trusted`). Leaving quarantine is the Day 3 RELEASE_QUARANTINE or RECOVERY_RESTORE operation, which results in **UNVERIFIED**, followed by independent revalidation. An "unquarantine" request can't restore trust.

---

## 4. Proof that normal retrieval excludes quarantined records

Exclusion is **not** a new filter. It is M3's existing invariant, "normal retrieval returns only `TRUSTED`" (GAP-001/004), which is stronger than excluding the word `QUARANTINED`. Each test quarantines a record **through this workflow** and then checks a different layer:

| Layer | Test |
|---|---|
| Repository `list_records(only_trusted=True)` | `test_only_trusted_records_retrievable_and_quarantine_removes_trusted` |
| Service `retrieve_memory` (all six states present) | same |
| Agent-scoped retrieval (`agent_id=`) and normal detail (`get_memory_detail` → 404) | `test_quarantined_record_absent_from_agent_scoped_retrieval_and_detail` |
| Pagination sweep; `trust_state=QUARANTINED / quarantined / UNVERIFIED` filters → 403 | `test_filters_and_pagination_cannot_reintroduce_quarantined` |
| **HTTP** `GET /api/v1/memory` and `GET /api/v1/memory/{id}` (M3 router behind M1's real JWT/membership auth) → empty list, 404, 403 on the filter, `exclude_quarantined=false` ignored | `test_http_list_and_detail_exclude_quarantined_record` |
| Protected actions (Day 4 engine) → BLOCK `MEMORY_QUARANTINED` | `test_quarantined_memory_cannot_justify_protected_action` |
| Cache: **none exists**. Redis is only used for rate limiting; I grepped `backend/app`. The optional hook is invoked, and its failure is never reported as success. | `test_cache_invalidation_hook_called_and_failure_never_reports_success` |

**Out-of-band relaxation.** If an out-of-band write relaxes a quarantined record (M3 `transition_memory_trust_state` → TRUSTED, or `update_memory` → UNVERIFIED), the record **is** retrievable again. The test `test_out_of_band_trust_restoration_is_reconciled` demonstrates the risk. Re-quarantining reconciles the stored state back to QUARANTINED, which removes it again. The root cause is M3's (Day 3 R-1/R-2) and is listed in §10.

---

## 5. Forensic access

`ForensicAccess.read(context, record_id, reason, persist_audit=..., incident_id=None, trace_id=None)` runs these steps in order:

1. Verified context plus the Day 2 role check (SECURITY_ANALYST or TENANT_ADMIN). Otherwise **403**.
2. Strict id and incident-id format; reason of 5–500 characters. Otherwise **400**.
3. Tenant-scoped lookup. A missing or cross-tenant record gives **404**, with no audit row and no content.
4. **Persist the `FORENSIC_MEMORY_ACCESSED` audit event first.** If that fails, the result is **503** and nothing is read (a test confirms the read function is never called).
5. Read through M3's `get_memory_detail(for_forensic=True)`, and attach the M4 trust history.
6. Return a `ForensicView` with `actionable=False`. Forensic results are never agent context, and the Day 4 engine still blocks quarantined references.

Forensic reads don't change state or retrievability (tested).

**GAP-012 stays open in M3.** `get_memory_detail(for_forensic=True)` / `allow_quarantined=True` are still booleans any in-process caller can set. `ForensicAccess` is the sanctioned path, but it **cannot stop other internal callers** using the boolean. M3 needs to replace the boolean with a distinct, non-public operation (§10).

---

## 6. Failure behaviour (never a false success)

| Condition | Status | Record afterwards | `success` |
|---|---|---|---|
| Invalid request, context or role; not found; unknown state; REJECTED; missing incident for SUPERSEDED | `DENIED` | Unchanged | False |
| Repository read failure; trust-store read failure | `FAILED` | Unchanged | False |
| M4 trust decision can't be recorded | `FAILED` | **Reverted** (Day 3) | False |
| Persistent concurrent modification (after 1 retry) | `FAILED CONCURRENT_MODIFICATION` | Unchanged | False |
| Post-condition can't be verified (e.g. a lost write) | `FAILED POSTCONDITION_FAILED` | As found; no evidence row | False |
| Cache invalidation fails | `CACHE_RECONCILIATION_REQUIRED` | **QUARANTINED** | False |
| M1/M6 evidence persistence fails | `EVIDENCE_RECONCILIATION_REQUIRED` | **QUARANTINED** | False |
| `persist_evidence` not supplied | `FAILED` | Unchanged | False |
| Unexpected exception | `FAILED EVALUATION_ERROR` | Unchanged or quarantined, never relaxed | False |

`raise_for_outcome` maps outcomes to M1 errors: 403 for authorisation or context, 404 not found, 400 invalid request, 409 transition not permitted, and **503** for every FAILED or `*_RECONCILIATION_REQUIRED` status.

**Deliberate deviation, recorded for architecture review.** M1's branch (and its proposed Doc 06 note) **rolls the trust state back** when quarantine evidence persistence fails. This workflow instead **keeps the record quarantined** and reports failure, for three reasons:
- Rolling back would put a suspected-poisoned record back into agent retrieval, and fail-secure for a protective control means failing toward restriction.
- The mandatory durable evidence, the M4 trust decision (in production a persistent store is required, Day 3 R-3), already exists at that point.
- If *that* decision can't be written, the transition is reverted and nothing is claimed.

---

## 7. Concurrency and idempotency

- **Two analysts at once:** exactly one applied transition and one evidence row; the other gets ALREADY_QUARANTINED (tested with `asyncio.gather`).
- **An update racing a quarantine:** the stale version is detected by Day 3 `expected_version`, the workflow re-reads and retries once, and quarantine succeeds from the new UNVERIFIED version. Continuous races end as FAILED `CONCURRENT_MODIFICATION`.
- **Retry after a timeout:** idempotent; no second evidence row.
- **Within-process only.** These guarantees rely on the evaluator's optimistic state and version checks. Across workers they need M6's transaction boundary and row versioning (GAP-008). There is no new locking mechanism and no new dependency.

---

## 8. Integration contract for M1 (`feat/m1-day5-incident-quarantine`)

**Findings on M1's branch** (read-only; the branch was not modified):
- M1's branch **created `backend/app/security/quarantine.py`**, an M4-owned path (`ownership.md` §5), and its `M4QuarantineService`:
  - allows **REJECTED → QUARANTINED**;
  - re-quarantines with a **second quarantines row and audit event**;
  - **mutates `record.trust_state` in place**, with no M4 decision history;
  - receives only a bare `actor_id` / `actor_role` string, never the verified context.
- `_execute_quarantine_flow` rolls the state back by direct write when persistence fails (see §6).

**Compatibility surface in M4's module.** It exports the same names M1 imports: `QuarantineServiceProtocol`, `QuarantineTransitionResult`, `M4QuarantineService`, `get_default_quarantine_service` and `set_default_quarantine_service`. So a merge starts up, but **`M4QuarantineService.execute_quarantine_transition` fails closed with 503** and an explicit log line. Running M1's own `test_incident_management.py` against this module in a scratch copy gave **32 passed, 11 failed**. All 11 failures are tests expecting the legacy in-place path to return 200; they get 503, as intended.

**Required M1 change** (replace steps 3–6 of `_execute_quarantine_flow`):

```python
from backend.app.security.quarantine import QuarantineWorkflow, raise_for_outcome

workflow: QuarantineWorkflow = request.app.state.quarantine_workflow   # built once: QuarantineWorkflow(trust_evaluator, memory_repo)

async def persist(outcome):                                            # durable evidence (M1/M6), called only after the transition
    await incident_repo.create_quarantine_atomic(
        quarantine=QuarantineEntity(id=f"quar-{uuid.uuid4().hex[:12]}", created_at=outcome.timestamp, **outcome.to_quarantine_row()),
        audit_event=AuditEventEntity(..., event_type="MEMORY_QUARANTINED", details_json=outcome.to_audit_details(),
                                     trace_id=getattr(request.state, "trace_id", None)),
        incident_id=outcome.incident_id,
    )

outcome = await workflow.quarantine(
    tenant_context,
    {"record_id": clean_record_id, "reason": payload.reason, "analyst_notes": payload.analyst_notes,
     "incident_id": payload.incident_id, "trace_id": getattr(request.state, "trace_id", None)},
    persist_evidence=persist,
)
raise_for_outcome(outcome)
return MemoryQuarantineResponse(id=outcome.record_id, previous_state=outcome.previous_state, trust_state="QUARANTINED", ...)
```

Further changes for M1:
- **Remove** the in-place mutation, the `mem_repo.update_record(record)` call and the rollback block.
- The forensic route should call `ForensicAccess.read(..., persist_audit=incident_repo.record_audit_event)` instead of `get_memory_detail(for_forensic=True, allow_quarantined=True)`. The current route persists its audit *after* the read.
- The `TrustEvaluator` M1 builds must be the **same instance** the Day 4 policy engine uses, so quarantine and action checks share one history.

---

## 9. Verification (executed 2026-11-17)

Environment: Python 3.14.5, pinned requirements (`asyncpg` excluded), branch `feat/m4-security-ml`.

| Command | Result |
|---|---|
| `pytest backend/tests/security/test_quarantine_workflow.py` | **79 passed** |
| `pytest backend/tests/security` (Days 2–5) | **610 passed, 2 xfailed** |
| `pytest --ignore=backend/tests/database` (full suite) | **784 passed, 2 xfailed**; no existing test modified |
| `pytest backend/app/memory/tests -k "gap or quarantin"` | 12 passed (GAP-001..004) |
| `pytest backend/tests/database` (M6) | **Not run:** `asyncpg` can't be installed on Python 3.14 |
| M1 `test_incident_management.py` with M4's module, in a scratch copy | 32 passed, 11 failed. Expected: the legacy path now fails closed with 503. |
| Mutation check | **10 of 10** injected regressions caught |

The first run of the new tests found a **real defect**, which is now fixed: Pydantic `pattern` performs a regex *search*, so the unanchored id pattern accepted `record_id="../etc"` and `incident_id="inc 1"`.

---

## 10. Remaining dependencies and risks

| ID | Owner | Item |
|---|---|---|
| Q-1 | **M1** | Adopt §8. Until then, the REST quarantine route on M1's branch either bypasses M4 (current branch) or returns 503 (after merging this module). |
| Q-2 | **M3** | `transition_memory_trust_state` (F-2) and `update_memory` (F-1) can still relax a quarantined record so it **reappears in retrieval** (demonstrated by a test). Reconciliation happens only on the next quarantine call. M3 must route trust writes through M4 and refuse updates of QUARANTINED, REJECTED and SUPERSEDED records. |
| Q-3 | **M3** | GAP-012: replace the `for_forensic` / `allow_quarantined` booleans with a distinct operation used only by `ForensicAccess`. |
| Q-4 | M3 / M6 | Retrieval reads the stored state, not M4's history-reconciled state. Retrieval should consult `TrustEvaluator.effective_state()`, or M4 must be the only writer. |
| Q-5 | M6 | Durable trust-decision store (D-07), transactional `quarantines` + `audit_events` + `incident_evidence` writes, and row versioning (GAP-008). Atomic rollback with pre-recovery snapshot is M6's Day 5 deliverable; recovery must end UNVERIFIED (Day 3 T-17). |
| Q-6 | M7 | Quarantine isolation tests against the merged M1 route and PostgreSQL; a cache-invalidation test once any retrieval cache exists. |
| Q-7 | M1 / M6 | No branch attribute in `TenantContext` or the schema, so branch-scoped quarantine authorisation isn't enforced (Day 1 D-09). |
| Q-8 | M1 | Role vocabulary (Day 2 R-1). Unaffected here: quarantine roles are SECURITY_ANALYST and TENANT_ADMIN. |

**G5 (whole team) is not complete.** It still needs M1's route integration, M3's ChroniMem comparison endpoint and M6's atomic rollback with pre-recovery snapshot. M4's part, quarantine and retrieval exclusion, is demonstrated at the component, service and HTTP-router level.

---

## 11. Research principles applied

These are AMSC implementation decisions, informed by the sources below. None of the sources' results are claimed for AMSC.

| Principle | Source (status) | Code and test |
|---|---|---|
| Poisoned records can pass ingestion; containment must cut the path from persistence to use | [MINJA](https://arxiv.org/abs/2503.03704) (NeurIPS 2025); [MemPoison](https://arxiv.org/abs/2607.14651) (preprint) | `test_poisoning_lifecycle_contained_and_evidence_preserved`: validated, then a delayed poisoned edit, then quarantine; removed from retrieval and blocked at the gateway |
| Evaluate persistence, consequence **and** repair, not just a status flag | [MemSecBench](https://arxiv.org/abs/2607.27080) (preprint) | The lifecycle test checks retrieval, the action decision, and that both versions are preserved for forensic diff |
| Preserve provenance for investigation | [MemLineage](https://arxiv.org/abs/2605.14421) (preprint) | No edge or version writes (`test_versions_and_provenance_are_preserved`); lineage taint still blocks derived actions (Day 4) |
| Trust changes are evidence-based decisions | [TrustMem](https://aclanthology.org/2026.findings-emnlp.2419/) (Findings of EMNLP 2026) | Transition only through the Day 3 evaluator with recorded evidence |
| Authorisation continuity across derivations | AkasicMEM, cited by Doc 07 but **not found** in this project's searches. The principle is covered by MemLineage and is not attributed to AkasicMEM. | Day 4 lineage check on derived records |
| Indirect injection through retrieved content | AgentDojo (NeurIPS 2024) | Injected-memo scenarios (Day 4 suite and this lifecycle test) |
| Historical recovery is version-explicit and never auto-trusts | ChronoMem (arXiv 2607.27773), AgentRewind (arXiv 2608.14380), both preprints and distinct from AMSC's ChroniMem | Recovery and release yield UNVERIFIED (Day 3); forensic view exposes immutable versions |
| Memory & Context Poisoning; least privilege; fail securely | [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ASI06; [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) §3; [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Role allow-list; verified context; failure toward restriction |
