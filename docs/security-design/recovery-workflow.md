# Recovery workflow (M4)

**Owner:** M4, Security Engine & Incident Response
**For:** reviewers of M4's recovery code, and M1, M3 and M6, who supply its ports.
**Code:** `backend/app/recovery/orchestrator.py`, `backend/app/api/recovery.py`. **Tests:** `backend/tests/security/test_recovery.py` (56).
**Spec:** TRD §18, Doc 03 §10, Doc 05 §6.3; M4 decisions OD-17, OD-21, OD-23 (`m6-integration-decisions.md`).

## Status

| Part | Status |
|---|---|
| Preview and execute orchestration, routes, post-condition checks | **Implemented; unit/contract tested** (test doubles for M3/M6 ports) |
| Run against M6's real `RewindCoordinator` on PostgreSQL | **Not verified:** needs M3's checkpoint reader, an M6 plan store and PostgreSQL |
| Router registered in the app | **Pending (M1)** |

## Who may do what

| Operation | Roles |
|---|---|
| `POST /recovery/plans/preview` | `SECURITY_ANALYST`, `TENANT_ADMIN` |
| `POST /recovery/plans/execute` | `SECURITY_ANALYST`, `TENANT_ADMIN` |
| `GET /recovery/plans/{id}` | any canonical role (incl. read-only `AUDITOR`) |

- The routes and the service each enforce roles independently; tests prove each layer alone.
- The tenant comes only from M1's verified context.
- A cross-tenant target, checkpoint or plan is indistinguishable from a missing one.

## Preview

1. **Validate the request:** strict model, extra fields forbidden, safe ids, and a reason of at least 10 characters.
2. **Load the target** (tenant-scoped).
3. **Load and verify the checkpoint:**
   - it belongs to this tenant;
   - item record ids are unique;
   - every item's `sha256(content) == checksum`;
   - the OD-17 combined hash matches `integrity_hash`.
4. **Check the target:** it must be in the checkpoint, and must not be REJECTED (terminal).
5. **Compute the blast radius** with M3's `get_descendants`. An incomplete traversal, or more than 200 records, is refused, never truncated.
6. **Classify each record:**
   - in the checkpoint → `RESTORED_TO_CHECKPOINT`;
   - not in it → `QUARANTINED_INTERMEDIARY`;
   - REJECTED → unchanged.
   - Each current version's checksum is re-verified.
7. **Collect irreversible external actions** (OD-23). If that history is unavailable, the preview is refused: honest outcome classification is mandatory.
8. **Fingerprint** the checkpoint, scope, actions, current versions and checksums, and external actions. Trust states are excluded (see Execute step 2).
9. **Record the plan** (`PREVIEWED`) and audit `RECOVERY_PREVIEWED`. If the audit fails, the plan becomes `FAILED` and the call fails.

## Execute

1. **Authorize**, verify the context, and take a per-plan in-process lock. A concurrent attempt is refused (`PLAN_NOT_EXECUTABLE`).
2. **Plan state:** it must be `PREVIEWED` or `FAILED` (a retry). The preview is recomputed, and any fingerprint difference is `PLAN_STALE`: nothing changes, and a new preview is needed.
3. **Snapshot first:** `capture_snapshot` commits the pre-recovery state before any change. It happens once per plan, and a retry reuses it.
4. **Contain:** every affected record not already QUARANTINED or REJECTED is quarantined through `TrustEvaluator.apply`. If containment fails, nothing is rolled back.
5. **Roll back** in one M6 transaction. For each restored record:
   - verify the checkpoint item;
   - append the checkpoint content as a **new** version (never move the pointer backwards);
   - compare-and-set `current_version`;
   - record actions, including `EXTERNAL_ACTION_IRREVERSIBLE` / `REQUIRES_COMPENSATION`.
   - Any exception rolls the whole transaction back.
6. **Trust:** restored records go QUARANTINED → UNVERIFIED (`RECOVERY_RESTORE`, T-17), with the plan and checkpoint as evidence.
   - They are **never TRUSTED.** Re-validation is a separate analyst `VALIDATE`, with evidence bound to the new version.
   - Intermediaries stay QUARANTINED.
7. **Post-conditions:** the content equals the checkpoint; no restored record is TRUSTED (stored or effective); intermediaries are QUARANTINED. Then mark the plan `EXECUTED` and audit `RECOVERY_EXECUTED`.

## Outcomes (never success unless verified)

| Status | HTTP | Meaning | Records |
|---|---|---|---|
| `EXECUTED` | 200 | Every step and post-condition held; audited | Restored: UNVERIFIED; intermediaries: QUARANTINED |
| `FAILED` + `PLAN_STALE` / `PLAN_ALREADY_EXECUTED` / `PLAN_NOT_EXECUTABLE` | 409 | Nothing changed | Unchanged |
| `FAILED` (snapshot, containment, rollback, store) | 503 | Rollback not committed; retryable under the same snapshot | Possibly contained (quarantined): restriction only |
| `RECONCILIATION_REQUIRED` | 500 | Rollback committed; a later step (trust restore, post-condition, plan status, audit) failed | Restricted (QUARANTINED or UNVERIFIED), never TRUSTED |

## Known limitations
- **Locks are process-local:** the plan lock and the trust lock are in-process. Across processes, M6's plan `FOR UPDATE` lock and its `SnapshotAlreadyCaptured` / `PlanAlreadyExecuted` errors are the guarantee.
- **External actions are recorded, not reversed.** They require human compensation, as the TRD requires.
- **The recovery path doesn't enforce release separation.** An analyst can recover a record they quarantined themselves. This is accepted, because recovery requires a recorded, audited plan, restores verified checkpoint content, and never yields TRUSTED.
