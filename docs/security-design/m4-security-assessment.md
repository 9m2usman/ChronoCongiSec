# M4 security assessment and acceptance checklist

**Owner:** M4, Security Engine & Incident Response
**For:** the M4 lead and reviewers of M4's code.
**Scope:** M4-owned code only: `backend/app/security/`, `backend/app/recovery/`, `backend/app/api/drift.py`, `backend/app/api/recovery.py`, `backend/tests/security/`.
**Date:** 2026-11-19. Baseline: `main` @ `cdbb4b9` (PR #16 merged), branch `feat/m4-security-ml` @ `c22a88f` plus uncommitted changes.

Every finding below was reproduced, by a failing test or a scratch reproduction, before it was fixed. Every fix was then checked by reverting it (mutation testing).

## 1. Findings in M4-owned code (this pass)

| ID | Severity | Location (current) | Root cause | Attack scenario | Fix | Verification |
|---|---|---|---|---|---|---|
| **M4-F1** | High | `policy.py` `_reserve_execution` (≈967), guard step 4b (≈1160), approval check (≈797) | Single-use was per *decision*. Each evaluation of the same proposal or approval issued a new executable decision. | Replay one proposal (same idempotency key), or reuse one approval: **2 adapter calls** (scratch reproduction) | Process-local execution ledger keyed by (tenant, idempotency key) and (tenant, approval id), reserved in the same synchronous step as grant consumption, kept regardless of outcome. A consumed approval also blocks at evaluation. | `test_m4_hardening.py` (7 tests). Disabling the ledger: 5 failures; removing the evaluation check: 2 failures. |
| **M4-F2** | Medium | `authorization.py` `Role` (53) | M4 recognised `DEVELOPER` (Doc 06 shorthand), not the canonical `AI_DEVELOPER`/`AUDITOR` (PRD FR-003, TRD §11, Doc 04/05, M1 seeds). | Product break, not escalation: real `AI_DEVELOPER` users were denied; `AUDITOR` had no defined read access. | Canonical four roles; `DEVELOPER` is unknown (no alias). Shared allow-lists `SECURITY_OPERATOR_ROLES`, `READER_ROLES`, `PROPOSER_ROLES`. AUDITOR is read-only. | `test_rbac_evaluator.py`, `test_rbac_integration.py`. Re-adding `DEVELOPER`: 7 failures; making AUDITOR an operator: 2. |
| **M4-F3** | Low | `drift.py` `list_observations` (≈345), `api/drift.py` (121) | Listing needed only authentication: any role string, even unknown, could read drift observations. | A membership with a garbage or legacy role reads tenant drift data | `READER_ROLES` required at both the route and the service | `test_drift_api.py` (route-only and service-only tests). Each layer's removal is caught. |
| **M4-F4** | Medium | `audit_identity.py` (new), `drift.py` (≈383), `quarantine.py` (≈601) | M4 audit events used bare user ids, against M4's own OD-9 contract (`user:`/`agent:`/`system:`). The audit chain is append-only, so wrong values are permanent. | Ambiguous actor in a permanent forensic record; no check on malformed ids | `user_actor()` etc. build ids from trusted context only and validate them against the OD-9 format. A malformed id raises 403 before anything is written. | `test_m4_hardening.py` (identity, drift and forensic fail-closed); `test_drift_api.py`, `test_quarantine_workflow.py` |
| **M4-F5** | High | `trust.py` `_apply` / `_apply_locked` (≈1022) | `apply` wrote back the record *copy read at evaluation start*. A concurrent change was silently overwritten; the revert path had the same flaw. | A concurrent quarantine is overwritten to TRUSTED; a concurrent new version is rolled back (`current_version` 2→1) and marked TRUSTED (scratch reproduction) | Per-record in-process lock; re-read before writing; refuse with `STALE_STATE`/`STALE_VERSION`; write the fresh copy; revert only if the record is still exactly what M4 wrote | `test_m4_hardening.py` (4 tests incl. a real threaded race). Removing the re-check: 3 failures; removing the lock: threaded test fails on 3 of 3 runs. |
| **M4-F6** | Medium | `trust.py` `NON_DURABLE_ALLOWED_ENVIRONMENTS` (417, 507) | The in-memory store was refused only when `APP_ENV == "production"` exactly. `staging`, `PRODUCTION`, `prod` or a typo accepted a non-durable trust ledger. | A misconfigured deployment runs with a ledger that is lost on restart, silently | Allow-list: only `development`/`test` (case-insensitive) may use non-durable stores; anything else raises at construction | `test_trust_store_contract.py` (13 environment cases) |
| **M4-F7** | High (missing capability) | `backend/app/recovery/orchestrator.py`, `backend/app/api/recovery.py` (new) | `owner.md` assigns recovery orchestration and `api/recovery.py` to M4; none existed. | Recovery would be ad hoc and could skip snapshot, containment, trust or audit controls | Orchestrator and routes ([recovery-workflow.md](recovery-workflow.md)) | `test_recovery.py` (56 tests). 13 mutants of security steps, all caught. |

Also fixed: two test-quality defects found by mutation testing (concurrency doubles that never yielded; a post-condition never exercised), and route checks masked by service checks (route-only tests added).

## 2. Re-validated earlier findings

| Finding | Status | Owner |
|---|---|---|
| OD-4 (ALLOW initial `execution_status`) | Resolved in M4 (2026-11-18) | M4; M6 DB rule pending |
| F-1 update resets QUARANTINED | Resolved on `main` by M3 (`a43308c`); M4 regression test active | M3 |
| F-1a unknown state → UNVERIFIED on update | Open; strict xfail | M3 |
| F-1b read-check-write race in `update_memory` | Open; documented (no concurrent repository on `main` to test) | M3 |
| F-2 public trust setter bypasses the matrix | Open; strict xfail | M3 (M4 contract in `m4-integration-contracts.md` §4) |
| Drift router not registered | Open | M1 |
| RV-1 imports of removed M3 modules | Resolved (package API) | M4 |
| `SqlDriftReviewStore` never run on PostgreSQL | Open: 5 tests skipped | Infrastructure (M7/M6) |

## 3. Checks that found nothing to fix (evidence)

| Check | Result | Evidence |
|---|---|---|
| Approval bound to exact operation and parameters | Bound via `proposal_fingerprint`: SHA-256 over tenant, principal, action id, agent, tool, operation, parameters, memory refs (id + version) and idempotency key. Tenant, expiry, self-approval and approver role are also checked. | `test_policy_engine.py::test_invalid_approvals_block` |
| Forged or tampered decision | Whole-object equality against the issued registry; any changed field → not executable | `test_fail_closed.py`, `test_policy_engine.py` |
| Concurrent use of one decision | Second use → `EXECUTION_GRANT_ALREADY_USED` | `test_fail_closed.py` |
| ML or scores grant permission | No ML input to policy; trust signals can only block; drift `is_verdict` is always False; review never changes trust | `test_trust_evaluator.py:425-438`, `test_drift_api.py:468-471` |
| Quarantine bypass | State-based idempotency (no keys to abuse); stale retry; post-condition verifies stored and effective QUARANTINED; cache and evidence failures are non-success | `test_quarantine_workflow.py`, `test_m4_hardening.py` |
| Sensitive data in logs and errors | Exception types only; DSN, password and token strings asserted absent | `test_fail_closed.py` (14 assertions) |
| Circular imports | memory, database, core and tenancy never import `security`/`recovery` | import checks, `grep` |

## 4. Threat model (M4 scope) and assumptions

| Threat | Control | Residual risk |
|---|---|---|
| Untrusted memory justifies an action | Version- and checksum-bound trust evidence; reconciliation with the M4 ledger; unknown state → BLOCK | M3's F-2 can write the stored state; M4 decisions still use the reconciled state |
| Replay or duplicate execution | Grant single-use plus the M4-F1 ledger | Process-local only; durable dedupe needs M6 UNIQUE plus Redis (M2/M7) |
| Approval misuse | Fingerprint binding, expiry, role, no self-approval, consumption | Durable consumption needs M6/M2 |
| Role confusion or escalation | Closed vocabulary, exact matching, explicit allow-lists, server-side context | Relies on M1 building the context from the membership row |
| Cross-tenant access | Tenant from context only; scoped stores; cross-tenant = not found | Database RLS not enabled (M6/M7, OD-11/18) |
| Trust-state race | M4-F5 re-check plus lock | Cross-process needs M3/M6 compare-and-set |
| Malicious restore | Verified checkpoint integrity, fingerprinted plan, snapshot first, containment, never TRUSTED | Checkpoint authenticity is SHA-256 only (GAP-011: no signature) |
| Silent failure | Every security write is checked; failures give non-success statuses | Audit on PostgreSQL unverified here |

**Assumptions:**
- M1's `TenantContext` is built from a verified JWT plus the membership row.
- The memory repository is the system of record for `trust_state`.
- M6's audit append is durable when it returns.
- Single-process locks hold within one worker.

## 5. Acceptance checklist

| Item | Status |
|---|---|
| Deterministic, fail-closed policy engine and guard | Implemented and verified (unit/contract) |
| Replay and approval-reuse protection (in process) | Implemented and verified (unit) |
| Canonical RBAC, AUDITOR read-only, default deny | Implemented and verified (unit + M1 dependency integration) |
| Trust matrix, version-bound evidence, race-safe apply | Implemented and verified (unit, incl. threaded race) |
| Durable trust decision store | **Contract provided; M6 implementation pending** |
| Quarantine workflow | Implemented and verified (unit) |
| Drift scoring and review API | Implemented and verified (unit); **PostgreSQL adapter unverified (5 skipped)** |
| Recovery orchestration and API | Implemented and verified (unit/contract); **real RewindCoordinator/PostgreSQL unverified** |
| Audit actor identity (OD-9) in M4 events | Implemented and verified |
| Router registration (drift, recovery) | **Pending (M1)** |
| M2 execution path through the guard | **Pending (M2)** |
| Real Redis failure behaviour | **Infrastructure-dependent, unverified** |
| `api/incidents.py` / `api/security.py` (listed for M4 in `owner.md`) | **Not implemented by M4.** M1 built incident APIs on its own branch per Doc 06 Day 5; ownership must be settled before M4 duplicates them. |

## 6. Scores

### 6.1 M4-owned engineering score

This scores what M4 has implemented and verified. External gaps are not deducted, but M4 gets no credit for anything unverified.

| Category | Weight | Score | Basis |
|---|---:|---:|---|
| Security architecture and design | 10% | 9.0 | Fail-closed throughout; explicit ports; documented contracts |
| RBAC and authorization | 10% | 9.3 | Canonical vocabulary, layered checks each proven alone |
| Trust evaluation and state integrity | 15% | 8.7 | Strong matrix and race fix; no durable store; sync evaluator vs async UoW unresolved; cross-process CAS absent |
| Policy engine and execution guard | 15% | 9.2 | Replay closed in process; durable dedupe is external |
| Quarantine and recovery | 10% | 8.6 | Recovery complete at contract level, never run on the real coordinator |
| Drift monitoring and incident security | 10% | 8.3 | Drift solid; M4's own SQL adapter never executed on PostgreSQL; incident-API ownership unresolved |
| Adversarial security testing | 15% | 9.3 | Reproduce, fix, mutate on every finding; threaded race; route-only tests |
| Code quality and documentation | 5% | 9.0 | pyflakes clean (one intentional import); docs mark status honestly |
| Integration contracts and readiness | 10% | 9.0 | Contracts, contract-test suite, exact wiring code |

Weighted: 0.90 + 0.93 + 1.305 + 1.38 + 0.86 + 0.83 + 1.395 + 0.45 + 0.90 = **8.95 / 10**

Not 9.5:
- no durable trust store;
- M4's PostgreSQL adapter (drift) has never run against PostgreSQL;
- recovery has never run against M6's real coordinator;
- cross-process atomicity relies on primitives other members must still provide.

### 6.2 Integrated system readiness score

| Category | Weight | Score | Basis |
|---|---:|---:|---|
| Architecture | 10% | 8 | Designs agree across M4/M6 docs |
| RBAC in the running app | 10% | 7 | M1 context real; M4 routers unregistered |
| Trust integrity end to end | 15% | 4 | No durable ledger; M3 F-2 open |
| Policy and guard on the real path | 15% | 2 | No M2 controller |
| Quarantine and recovery wired | 10% | 3 | Not registered; recovery ports missing |
| Drift wired | 10% | 4 | Router unregistered; PostgreSQL unverified |
| Adversarial testing with real infrastructure | 15% | 3 | No PostgreSQL, Redis or CI |
| Documentation | 5% | 8 | Complete for the M4 side |
| Integration completeness | 10% | 3 | Most connections pending |

Weighted: 0.8 + 0.7 + 0.6 + 0.3 + 0.3 + 0.4 + 0.45 + 0.4 + 0.3 = **4.25 / 10**. The application is **not** production-ready.
