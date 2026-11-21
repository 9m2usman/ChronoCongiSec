# M4 integration contracts

> **Update 2026-11-21 (branch `feat/integration-verification`):**
> - **Now connected:** the M1 gateway uses M4's `PolicyEngine` and `ProtectedExecutionGuard`; M1 quarantine routes run `QuarantineWorkflow` (no fallback); forensic reads use the audited `POST /memory/{id}/forensic-access`; the M3 trust primitive is restrict-only. Wiring lives in `backend/app/security/runtime.py`.
> - **Still pending:** M2 controller; database session factory at startup (M1/M6); durable trust store, plan store, checkpoint reader and external-action reader (M6/M3).
> - The gateway-specific statements in §3 below describe the contract for M2, whose controller does not exist yet.

**Owner:** M4, Security Engine & Incident Response
**For:** M1, M2, M3, M6 and M7, who connect their side of each contract below.
**State:** `feat/m4-security-ml` working tree on 2026-11-19 (`main` @ `cdbb4b9`, which already contains PR #16).

Status vocabulary used here:

| Status | Meaning |
|---|---|
| **Verified (unit/contract)** | Implemented in M4 and tested with M4's real code; external side is a test double |
| **Contract provided; external pending** | M4's side and its tests exist; the other member has not built or connected theirs |
| **Infrastructure-dependent, unverified** | Needs PostgreSQL, Redis or CI that was not available |

Nothing in this document claims a production execution path is protected end to end. No M2 controller exists, M1 has not registered M4's routers, and no durable trust store exists.

---

## 1. M1: trusted tenant context (authentication)

| Item | Contract |
|---|---|
| Interface | `backend.app.tenancy.context.TenantContext` from `backend.app.core.dependencies.get_tenant_context` |
| Inputs M4 relies on | `tenant_id`, `user_id`, `role`, `is_active`, built server-side from the verified JWT **and** the membership row. Never from headers, query or body. |
| Role vocabulary | `TENANT_ADMIN`, `SECURITY_ANALYST`, `AI_DEVELOPER`, `AUDITOR` (PRD FR-003). Any other string, including `DEVELOPER`, is denied by M4. |
| M4 behaviour | `evaluate_role_access` is default-deny with exact matching. Allow-lists live in `authorization.py`: `SECURITY_OPERATOR_ROLES`, `READER_ROLES`, `PROPOSER_ROLES`. |
| Failure behaviour | Missing, inactive or malformed context, or an unknown role → 403. An invalid `user_id` for an audit actor → 403, and nothing is written. |
| Contract tests | `test_rbac_evaluator.py`, `test_rbac_integration.py` (real M1 JWT + `InMemoryAuthRepository`), `test_m4_hardening.py` |
| Status | **Verified (unit/integration with M1's real dependency code)** |

## 2. M1: router registration

M4 provides `backend/app/api/drift.py` and `backend/app/api/recovery.py`. Neither is registered in `backend/app/main.py`, which M1 owns. **Until it is, `/api/v1/drift/*` and `/api/v1/recovery/*` do not exist in the running app.**

```python
# backend/app/main.py (M1), inside the app factory
from backend.app.api.drift import router as drift_router
from backend.app.api.recovery import router as recovery_router
api_router.include_router(drift_router)
api_router.include_router(recovery_router)

# lifespan / startup, once M6 session factory exists:
app.state.drift_service = DriftReviewService(SqlDriftReviewStore(session_factory))
# app.state.recovery_service = RecoveryService(...)   # after §5 ports exist
```

- **Without the services**, both routers return 503 (fail closed). Tests: `test_drift_api.py`, `test_recovery.py`.
- **Status:** contract provided; M1 pending.

## 3. M2: proposal controller and execution lifecycle

| Item | Contract |
|---|---|
| Decide | `decision = await PolicyEngine.evaluate(proposal, context, approval=None)`. The proposal is the Doc 05 action-proposal dict. The tenant and principal come only from `context`. |
| Persist | `decision.to_persistence_record()` gives the `policy_decisions` columns plus `details_json`. The initial `execution_status` is `decision.initial_execution_status` (`PENDING_EXECUTION` / `PENDING_APPROVAL` / `NOT_EXECUTED`). |
| Execute | Only via `await ProtectedExecutionGuard.execute(decision, proposal, context, persist_decision=..., executor=..., approval=..., mandatory_controls=[...])`. The controller must never call an adapter directly. |
| Guard guarantees | It executes only an engine-issued, unmodified, executable ALLOW, with: <br>• mandatory controls returning exactly `True`; <br>• the decision persisted first (a raise or `False` stops it); <br>• pre-execution revalidation identical to the decision; <br>• the grant used once; <br>• one dispatch per (tenant, idempotency key) and per (tenant, approval id). |
| Outcome mapping | `ExecutionOutcome.status`: `EXECUTED` / `FAILED` / `UNKNOWN` (adapter called) or `NOT_EXECUTED` / `PENDING_APPROVAL` (not called). A timeout is `UNKNOWN`, never success. |
| Durable replay protection | The guard's ledger is **process-local**. Across processes, M2 must use: <br>• M6's UNIQUE `tool_executions.proposal_id`; <br>• a Redis idempotency lock as a `MandatoryControl`; <br>• approval consumption (an execution row exists = consumed). |
| Contract tests | `test_policy_engine.py`, `test_policy_gateway_integration.py` (guard behind a FastAPI route with a spy adapter), `test_fail_closed.py`, `test_m4_hardening.py` (replay, concurrency, retry after failure) |
| Status | **Contract provided; M2 pending.** There is no real controller to test; the spy adapter is a test double. |

## 4. M3: memory trust persistence and transitions

| Item | Contract |
|---|---|
| Authoritative transitions | Only `TrustEvaluator.apply` changes `trust_state`. M3's `transition_memory_trust_state` must stop being a public setter (finding F-2, M3-owned, strict xfail). |
| Primitive M4 needs | A compare-and-set write: `update_record_if(record, expected_state, expected_version)`. It changes `trust_state` only if both still match, and refuses unknown states. Until it exists, M4 re-reads and compares under an in-process lock (M4-F5). That is atomic within one process only. |
| Updates | `update_memory` must refuse QUARANTINED / REJECTED / SUPERSEDED (done on `main`, `a43308c`) **and unknown states** (F-1a, strict xfail). The read, check and write must be one transaction (F-1b). |
| Checkpoints (recovery) | `CheckpointReader.get_checkpoint(tenant_id, checkpoint_id) -> CheckpointView` with items `(record_id, version, checksum, content)`. M4 recomputes the OD-17 integrity hash and every item checksum. **No M3 checkpoint API exists yet.** |
| Blast radius | `get_descendants(...)` with `complete=True`. M4 refuses an incomplete traversal. |
| Contract tests | `test_trust_evaluator.py` (incl. the F-2 and F-1a xfails), `test_m4_hardening.py` (M4-F5 races), `test_recovery.py` |
| Status | **Contract provided; M3 pending** (F-2, F-1a, F-1b, checkpoint reader, CAS primitive) |

## 5. M6: durable persistence

### 5.1 Trust decision store

| Item | Contract |
|---|---|
| Protocol | `TrustDecisionStore` (`trust.py`): `is_persistent: bool`, `append(decision)`, `list_for_record(tenant_id, record_id)` |
| Required behaviour | Append-only; ordered; tenant- and record-scoped; refuses unscoped decisions; returns read-only history; round-trips every evidence field (actor, reason, codes, version, checksum, evidence summary, policy version, timestamp). |
| M4 decision (OD-9, §7.4 of `m6-integration-decisions.md`) | Persist as hash-chained audit events: `event_type = MEMORY_TRUST_TRANSITIONED`, `resource_id = record_id`, index `(tenant_id, event_type, resource_id, chain_seq)` |
| Transaction | The append must share the transaction with the `trust_state` write, or the evaluator's revert path must stay in place. A failed append is never reported as success. |
| Design gap (M4 + M6) | `TrustEvaluator` is synchronous; M6's `UnitOfWork` is async. A durable store needs an async boundary, or an async evaluator. This must be agreed before implementation. |
| Production gating | Non-durable stores are accepted only when `APP_ENV` is `development` or `test` (M4-F6). Anything else raises at construction. |
| Contract tests | `test_trust_store_contract.py`. Subclass `TrustDecisionStoreContract`, set `expect_persistent = True`, and the durable store must pass. |
| Status | **Contract provided; M6 implementation pending.** Durable persistence is **not** verified. |

### 5.2 Recovery ports

| Port | Provider | Contract |
|---|---|---|
| `RewindPort` | M6 `RewindCoordinator` (exists) | `capture_snapshot` commits once; `execute_rollback(expected_snapshot_sha256, restore)` runs the restore in one transaction with `checkpoint_item_for`, `append_version`, `compare_and_set_current_version`, `record_action`. **M6 change needed:** set `recovery_plans.status = 'EXECUTED'` together with `executed_at` (OD-21). |
| `RecoveryPlanStore` | M6 (pending) | `create`, `get`, and a `transition(expected_status, new_status, snapshot_sha256)` compare-and-set on `recovery_plans` |
| `ExternalActionReader` | M6/M2 (pending) | `tool_executions` whose proposal's `memory_refs_json` names an affected record, executed after the checkpoint. Any status counts. |
| Audit sink | M6 `tx.audit.append` | An async callable. M4 treats a raise or `False` as failure. |

- **Contract tests:** `test_recovery.py` (`ContractRewind` and `MemoryPlanStore` model the documented semantics).
- **Status:** contract provided. The orchestrator has never run against the real `RewindCoordinator` or PostgreSQL.

### 5.3 Database rules M4 asked for

These are listed in `m6-integration-decisions.md` §8: vocabularies, the cross-column decision CHECK, the forward-only `execution_status`, the execution permission trigger, approval rules, immutable proposals, the trust reset on version change, and the audit actor format.

## 6. M7: infrastructure and CI

| Need | Command | Status |
|---|---|---|
| PostgreSQL 16 for the 5 drift tests | `docker compose up -d postgres`, then `TEST_DATABASE_URL=postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres python -m pytest backend/tests/security/test_drift_postgres.py -v -rsx` (Python 3.12; the login needs CREATEDB) | **Infrastructure-dependent, unverified** |
| Redis 7 plus a pinned client | `docker compose up -d redis`; a pinned `redis==<version>` in `backend/requirements.txt` (none today) | **Infrastructure-dependent, unverified** |
| CI | Run `python -m pytest backend/tests/security -q -rsx` on every PR, plus the PostgreSQL job above | No CI workflow exists |
