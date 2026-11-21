# M4 security test gaps and integration blockers

**Owner:** M4, Security Engine & Incident Response
**For:** M1, M2, M3, M6 and M7, where named; and the M4 lead.
**Date:** 2026-11-18. Branch `feat/m4-security-ml` (all M4 work uncommitted).

## 00. Status update, 2026-11-19 (security improvement pass)

The current, authoritative state is in [m4-security-assessment.md](m4-security-assessment.md) (findings M4-F1 to M4-F7, acceptance checklist, scores) and [m4-integration-contracts.md](m4-integration-contracts.md) (what each member must connect).

Changes in this pass:
- replay protection (M4-F1);
- canonical roles (M4-F2);
- drift list role check (M4-F3);
- OD-9 audit actors (M4-F4);
- race-safe trust apply (M4-F5);
- environment gating (M4-F6);
- recovery orchestration and API (M4-F7).

Still blocked: M2 controller; M1 router registration; M3 F-2/F-1a/F-1b and checkpoint reader; M6 durable trust store and plan store; PostgreSQL, Redis and CI.

## 0. Status update, 2026-11-19 (after rebasing onto `origin/main` @ `e39f2da`)

This section supersedes the F-1 statements below and in the earlier day documents.

- **M3's refactor is merged** (PR #7). `memory/service.py` and `memory/hashing.py` are gone; the API now lives in `ingestion`, `integrity`, `retrieval` and `versioning`, re-exported from `backend.app.memory`.
  - **RV-1 is resolved:** all M4 code and tests now import from the package API (`from backend.app.memory import ...`).
- **F-1 is fixed on `main`** (M3 commit `a43308c`): `versioning.py::update_memory` refuses QUARANTINED, REJECTED and SUPERSEDED (`ValidationError`, no version written), keeps SUSPICIOUS, and resets TRUSTED to UNVERIFIED.
  - M4's former strict xfail `test_m3_update_refused_for_quarantined_record` now passes, so it is a regression test covering all three states (state, version count, M4 effective state and retrieval exclusion). Reverting M3's check makes 5 M4 tests fail.
  - The three M4 tests that used `update_memory` to launder a quarantine now assert that the update is refused, then launder through the remaining bypass (`transition_memory_trust_state`, F-2). Their reconciliation assertions are unchanged.
- **Still open in M3 code on `main`:**
  - **F-1a:** an unknown stored state falls back to `UNVERIFIED` (`versioning.py:71-73`). Pinned by the new strict xfail `test_m3_update_refused_for_unknown_stored_state`.
  - **F-1b:** the restricted-state check (`versioning.py:58`) runs on a copy read at `:50`, and `:95` writes that copy back. A quarantine committed in between is overwritten. Harmless in the single-threaded in-memory repository, a lost update on PostgreSQL unless the read is `FOR UPDATE` inside the write transaction. Not pinned by a test (no concurrent repository exists on `main`).
  - **F-2:** unchanged (`retrieval.py:149`); strict xfail `test_m3_direct_transition_path_enforces_matrix`.
- **New integration finding for M1:** `backend/app/main.py` does not register M4's drift router (`backend/app/api/drift.py`), so `/api/v1/drift/*` is unreachable in the real app. M4's tests mount the router on a test app.


| Item | Before | After | Status |
|---|---|---|---|
| OD-4: initial `execution_status` of ALLOW | strict xfail | fixed in M4 code; test passes | **Completed (M4 side)** |
| F-1: update on a QUARANTINED record (M3) | strict xfail | still xfail on this branch; mostly fixed on M3's unmerged branch, 2 residual defects | **Blocked by M3** |
| F-2: direct trust transition (M3) | strict xfail | still xfail; unfixed on every M3 branch | **Blocked by M3** |
| 5 PostgreSQL drift tests | skipped | still skipped; no PostgreSQL server reachable | **Blocked by infrastructure** |
| Real Redis failure tests | simulated only | still simulated only; no server, no client library, no merged implementation | **Blocked by infrastructure + M1/M7** |
| M2 controller integration | not available | confirmed absent on all 23 remote branches | **Blocked by M2** |

The suite went from 1075 passed / 3 xfailed to 1095 passed / 2 xfailed.
- One xfail was converted to a real passing test after the fix.
- 20 tests were added (OD-4 fail-closed cases).
- No test was deleted or weakened, and the 5 PostgreSQL skips are unchanged.

## 2. OD-4: initial execution status (fixed)

**Root cause:** `PolicyDecision.initial_execution_status` (`backend/app/security/policy.py`) returned `PENDING_APPROVAL` for REQUIRES_APPROVAL and `NOT_EXECUTED` for everything else, including a fully permitted ALLOW.
- Under the forward-only lifecycle decided for M6 (`m6-integration-decisions.md` §3.1), `NOT_EXECUTED` is terminal. A permitted action could therefore never reach `EXECUTED`.
- M1's gateway already writes `PENDING_EXECUTION` for ALLOW (`api/gateway.py:1373` @ `650fe10`), so M4 and M1 disagreed.

**Four separate concepts:**

| Concept | Where | Meaning |
|---|---|---|
| Policy decision | `policy_decisions.decision` (immutable) | ALLOW / BLOCK / REQUIRES_APPROVAL at evaluation time |
| Execution eligibility | computed, never stored: `decision_is_executable` + `ProtectedExecutionGuard` (persisted, engine-issued, revalidated, mandatory controls exactly `True`) | whether dispatch may happen *now* |
| Execution status | `policy_decisions.execution_status` (forward-only) | lifecycle position; `PENDING_EXECUTION` = permitted and persisted, **not run** |
| Tool outcome | `tool_executions.status` + status `EXECUTED` / `FAILED` / `UNKNOWN` | what the adapter did |

**Fix (M4 code only):**

| Decision | Initial `execution_status` |
|---|---|
| ALLOW that passes `decision_is_executable` | `PENDING_EXECUTION` |
| REQUIRES_APPROVAL with `policy_result = ELEVATED` | `PENDING_APPROVAL` |
| BLOCK, or any ALLOW / REQUIRES_APPROVAL that is incomplete, timed out, contradictory or tampered | `NOT_EXECUTED` (fail closed) |

**Transitions:** owned by the caller (M1 today, M2 later), enforced by M6's trigger.
```
PENDING_EXECUTION -> EXECUTED | FAILED | UNKNOWN | NOT_EXECUTED
```
`NOT_EXECUTED` is used when revalidation or a mandatory control blocks. The guard was not changed: it still never dispatches BLOCK, REQUIRES_APPROVAL, or an ALLOW that fails revalidation.

**Evidence** (`backend/tests/security/test_db_contract.py`, 86 passed):
- ALLOW → `PENDING_EXECUTION` and never `EXECUTED` (2 scenarios);
- 6 tampered ALLOW variants → `NOT_EXECUTED`;
- contradictory REQUIRES_APPROVAL → `NOT_EXECUTED`;
- all 11 BLOCK scenarios → `NOT_EXECUTED`.

Mutation check:
- restoring the old behaviour: 2 failures;
- an outcome-label-only rule: 6 failures;
- dropping the ELEVATED condition: 1 failure.

**Owners:**
- M4: done.
- M1/M2: write `PENDING_EXECUTION` only when the engine says so, and perform the transitions.
- M6: CHECK, insert rule and transition trigger (`m6-integration-decisions.md` §3.1). No migration was edited by M4.

## 3. F-1: memory update on a restricted record (M3)

**On this branch:** `backend/app/memory/service.py::update_memory` sets `trust_state = UNVERIFIED` unconditionally. A QUARANTINED, REJECTED, SUSPICIOUS or SUPERSEDED record loses its restrictive state, and a new version is written.

M4 compensates in its own decisions: `TrustEvaluator.effective_state` takes the more restrictive of the stored state and M4's ledger, so M4 still blocks. However:
- **the stored state lies:** M1's gateway, the UI and any non-M4 reader see `UNVERIFIED`, not `QUARANTINED`;
- **the quarantine disappears from the record itself.**

Test: `backend/tests/security/test_trust_evaluator.py::test_m3_update_refused_for_quarantined_record` (strict xfail, correctly failing).

**On M3's unmerged `feat/m3-async-postgres-adapter` @ `d84aded`**, `versioning.py::update_memory` refuses QUARANTINED, REJECTED and SUPERSEDED, keeps SUSPICIOUS, and resets TRUSTED to UNVERIFIED. A scratch probe against an exported copy of that branch gave **8 passed, 8 failed**. M3's own 130 tests pass.

| Probe | Result |
|---|---|
| Update refused for QUARANTINED / REJECTED / SUPERSEDED; no version written; state unchanged | pass |
| SUSPICIOUS stays SUSPICIOUS; TRUSTED → UNVERIFIED and leaves normal retrieval | pass |
| Refused update keeps a quarantined record out of retrieval; cross-tenant update refused | pass |
| **F-1a:** unknown stored state (`MOSTLY_TRUSTED`) | **fail:** becomes `UNVERIFIED` (`versioning.py:89-91` fallback) |
| **F-1b:** a quarantine committed after the state check, before the write | **fail:** overwritten to `UNVERIFIED`. The check uses a record read before `repo.transaction()`, and the write stores that stale copy. On PostgreSQL this is a lost update unless the record is read `FOR UPDATE` inside the transaction. |

**Expected secure behaviour** (consistent with TRD §17/§18 and the M4 matrix):
- refuse updates to QUARANTINED / REJECTED / SUPERSEDED, and to any unknown state;
- remediation of quarantined content goes through M4's release/recovery workflow, never through `update_memory`;
- an update never moves a record to a less restrictive state;
- the state check and the write happen under one row lock and transaction (or a compare-and-set on `trust_state` and `current_version`).

M4's current xfail calls the *sync* `service.update_memory`. When M3's async branch merges, M4 rewrites the two xfail tests for the async API (package-level imports, finding RV-1). Otherwise they would test nothing.

## 4. F-2: direct trust transition (M3)

**Defect:** `transition_memory_trust_state` (sync on this branch; async in `retrieval.py:149-174` on both new M3 branches) accepts any of the six states and assigns it.
- It applies no transition matrix, needs no evidence or authorization, and writes no audit.
- The probe on `d84aded` shows REJECTED→TRUSTED, QUARANTINED→TRUSTED, SUPERSEDED→TRUSTED, SUSPICIOUS→TRUSTED, QUARANTINED→UNVERIFIED and UNVERIFIED→TRUSTED all succeed. Only an unknown target is refused.
- It is exported from `backend.app.memory`.

**Callers:**
- no production caller on any branch;
- M3's tests use it as a setup shortcut (`backend/app/memory/tests/test_service.py`, 6 calls);
- M4's `TrustEvaluator` persists through `repository.update_record`, not this function.

**M1 also writes `trust_state` directly** (`api/incident_management.py:1647-1649`, M1's own `security/quarantine.py:131` @ `650fe10`): a third path outside the M4 matrix.

**Safest contract** (no circular import; M3 must not import `backend.app.security`, per its own docstring invariant 6):
1. M3 removes `transition_memory_trust_state` from the public package and `__all__`. M3 tests use a test-only helper.
2. M3 keeps one persistence primitive, used **only** by M4's `TrustEvaluator.apply`: a compare-and-set that changes `trust_state` only if both the state and `current_version` still equal what M4 evaluated. It applies no policy of its own and refuses unknown states.
3. M4 stays the only owner of the transition matrix (19 rules), the evidence (version and checksum bound), authorization and the trust ledger.
4. **Database backstop (M6, P0):** the trust-reset trigger and the `trust_state` CHECK in `m6-integration-decisions.md` §4.1 and §5.1.
5. **Audit:** M4 writes `MEMORY_TRUST_TRANSITIONED` for every applied transition (§7.4 there).

## 5. PostgreSQL (5 drift tests)

**Checked on this machine (2026-11-18):**
- no `psql`, `pg_ctl` or `postgres` on PATH;
- port 5432 closed;
- `TEST_DATABASE_URL` and `.env` absent;
- Docker Desktop's service `com.docker.service` is installed but **stopped**, and no `docker` CLI is on PATH.

**Nothing was started, installed or substituted.** SQLite was not used, and no credentials were invented. An earlier attempt to fetch a portable PostgreSQL in this session was refused by the permission policy, and was not retried.

**What the tests need** (M6's `INTEGRATION-GUIDE.md` §1, `docker-compose.yml`):
- PostgreSQL 16 (`docker compose up -d postgres` with `amsc` / `amsc_dev_password`), Python 3.12 (asyncpg 0.29.0 has no 3.13/3.14 wheel), and `pip install -r backend/requirements.txt`;
- `TEST_DATABASE_URL=postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres`. The login needs `CREATEDB` (the tests create and drop `amsc_test_*` databases and migrate them to `0009`) and must be a local host or one listed in `TEST_DATABASE_ALLOWED_HOSTS`;
- **command:** `python -m pytest backend/tests/security/test_drift_postgres.py -v -p no:cacheprovider -rsx`.

They never touch the database named in `DATABASE_URL`. No schema blocker is known: the tests use only `drift_observations`, `memory_records`, `tenants` and the 0009 audit chain.

## 6. Redis

**Checked:**
- no Redis server (port 6379 closed, no `redis-server`, `redis-cli` or Memurai);
- **no Redis client library in `backend/requirements.txt`**, and `import redis` fails in the test environment;
- the in-repo code (`core/dependencies.py`) ships only `InMemoryRateLimiter` and a `RateLimiterProtocol`;
- the real Redis limiter (Lua sliding window) exists only on M1's unmerged `feat/m1-day7-api-finalization`;
- `core/config.py` requires `RATE_LIMITER_BACKEND=redis` and `fail_closed` in production.

**What M4 has proven (simulated, `test_fail_closed.py`):** limiter unavailable, raising, returning non-bool, malformed or truthy-non-`True` results; lock acquire failing or raising; a database commit failure after a Redis check. Every case → no adapter call.
- **Scope:** only mandatory controls (rate limit, idempotency lock on protected actions) fail closed. Redis is never used as an authorization input. A telemetry or pub/sub outage is not a protected-action failure.

**Not proven:** behaviour against a real Redis connection (refused connection, socket timeout, a server restart mid-lock, recovery). This needs:
- M7: a Redis 7 service (`docker compose up -d redis`) and a pinned client (`redis==<version>`, a dependency decision);
- M1: the limiter and lock merged.

Planned real-Redis cases (to run when available):
1. Server down at request time → BLOCK, no adapter call, no audit claim.
2. Socket timeout on `EVAL` → same.
3. Lock acquired, Redis restarts before release → the second request can't run concurrently (re-check the persisted `PENDING_EXECUTION` and idempotency row).
4. Malformed reply → fail closed.
5. After recovery, a new request is re-evaluated in full; no cached "allowed".
6. Non-protected endpoints (telemetry, reads) keep working during the outage.

## 7. M2 controller

Searched all 23 remote branches after `git fetch --prune` (2026-11-18) for a proposal controller, execution lifecycle or adapter code by M2. Nothing exists. The only match is M1's `AgentRuntime` enum in `api/agents.py` (agent metadata).

**Status: BLOCKED — waiting for M2 implementation and integration.** M4's interim evidence uses the M4 guard with a spy adapter (`test_policy_gateway_integration.py`, `test_fail_closed.py`). That is not end-to-end.

**Integration checklist** (run against M2's real controller):
1. BLOCK never invokes the adapter.
2. REQUIRES_APPROVAL with a pending, rejected or expired approval never invokes it.
3. A trust evaluator exception or timeout → BLOCK.
4. A QUARANTINED, REJECTED, SUPERSEDED, SUSPICIOUS, UNVERIFIED, missing or cross-tenant reference → BLOCK.
5. A duplicate reference blocks the whole proposal before any lookup (`POLICY_INPUT_INVALID`).
6. Memory changed between decision and dispatch → no adapter call; `execution_status` → `NOT_EXECUTED`; audit `TOOL_EXECUTION_ABORTED`; no `tool_executions` row.
7. An adapter timeout → `UNKNOWN`, never `EXECUTED`/`SUCCESS`.
8. A retry with the same idempotency key replays the stored result. A retry with a changed payload → 409. A retry can never skip evaluation or approval.
9. The tenant always comes from M1's `TenantContext`. A body or header tenant is ignored, and the adapter receives the same tenant.
10. Only `ProtectedExecutionGuard.execute` (persist → revalidate → mandatory controls → single-use grant) calls adapters. The controller never calls an adapter directly.
11. A failed decision or audit persistence → no adapter call.
12. Initial `execution_status` comes from `PolicyDecision.initial_execution_status`; transitions follow OD-4.

## 8. Proposed regression tests for M3

Written against `feat/m3-async-postgres-adapter`. Each asserts the secure behaviour. Today 8 of the 16 fail there (F-1a, F-1b, F-2 ×6).

```python
import asyncio, pytest
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.retrieval import retrieve_memory, transition_memory_trust_state
from backend.app.memory.versioning import update_memory

T = "tenant-a-uuid-001"

def run(c): return asyncio.run(c)

def setup(state="UNVERIFIED"):
    repo = InMemoryMemoryRepository()
    rec, _ = run(ingest_memory(T, "original", repository=repo))
    repo._records[rec.id].trust_state = state
    return repo, rec.id

@pytest.mark.parametrize("state", ["QUARANTINED", "REJECTED", "SUPERSEDED", "MOSTLY_TRUSTED"])
def test_update_refused_on_restricted_or_unknown_state(state):
    repo, rid = setup(state)
    with pytest.raises(Exception):
        run(update_memory(T, rid, "rewrite", repository=repo))
    assert repo._records[rid].trust_state == state
    assert [v.version for v in run(repo.get_versions(rid, T))] == [1]

def test_quarantine_during_update_survives():
    repo, rid = setup("TRUSTED")
    original = repo.get_versions
    async def racing(record_id, tenant_id):
        repo._records[rid].trust_state = "QUARANTINED"
        return await original(record_id, tenant_id)
    repo.get_versions = racing
    try:
        run(update_memory(T, rid, "edit", repository=repo))
    except Exception:
        pass
    assert repo._records[rid].trust_state == "QUARANTINED"

def test_trust_setter_is_not_public():
    import backend.app.memory as m
    assert "transition_memory_trust_state" not in getattr(m, "__all__", ())

@pytest.mark.parametrize("start,target", [("REJECTED","TRUSTED"), ("QUARANTINED","TRUSTED"),
    ("SUPERSEDED","TRUSTED"), ("SUSPICIOUS","TRUSTED"), ("QUARANTINED","UNVERIFIED"), ("UNVERIFIED","TRUSTED")])
def test_no_arbitrary_trust_assignment(start, target):
    repo, rid = setup(start)
    with pytest.raises(Exception):
        run(transition_memory_trust_state(T, rid, target, repository=repo))   # or the CAS primitive without M4
    assert repo._records[rid].trust_state == start
```

## 9. Messages

Ready to send. Section I of the M4 report has the same text.

**To M3 — F-1 / F-2 trust paths**
> Hi M3. Two security defects in the memory trust paths, with evidence. Details and regression tests are in `docs/security-design/test-gaps-and-blockers.md` §3, §4 and §8.
>
> **F-1 (update on a restricted record).** On `main`, `service.py::update_memory` sets `UNVERIFIED` unconditionally, so a QUARANTINED, REJECTED, SUSPICIOUS or SUPERSEDED record loses its state. M4's test `backend/tests/security/test_trust_evaluator.py::test_m3_update_refused_for_quarantined_record` fails strictly. Your `feat/m3-async-postgres-adapter` (`d84aded`) fixes the main path: refuses Q/R/X, keeps SUSPICIOUS, all 130 of your tests pass. Two residual cases fail in my probe:
> - (a) an unknown stored state falls back to `UNVERIFIED` (`versioning.py:89-91`). Please refuse it instead.
> - (b) the state is checked on a record read before `repo.transaction()`. A quarantine committed in between is overwritten to `UNVERIFIED`. Please read the record `FOR UPDATE` inside the transaction, or compare-and-set on `(trust_state, current_version)`.
>
> **F-2 (direct transition).** `transition_memory_trust_state` assigns any of the six states with no matrix, evidence, authorization or audit. On `d84aded`, REJECTED/QUARANTINED/SUPERSEDED/SUSPICIOUS/UNVERIFIED→TRUSTED and QUARANTINED→UNVERIFIED all succeed. There are no production callers (only your tests), and M4 persists through `update_record`.
>
> Proposal (no circular import; you keep "no imports from security"):
> 1. Remove it from the public package and `__all__`; use a test-only helper in your tests.
> 2. Keep one compare-and-set primitive that M4's `TrustEvaluator` alone calls. It changes `trust_state` only if state and `current_version` still match, applies no policy and refuses unknown states.
> 3. M4 keeps the matrix, the evidence and the audit.
>
> Could you confirm, or propose another contract? When it merges I'll rewrite M4's two xfail tests for the async API and remove the xfails once they genuinely pass.

**To M2 — controller integration**
> Hi M2. M4's policy engine and execution guard are ready for your proposal controller. I couldn't find any controller or execution code on any branch, so end-to-end integration is BLOCKED on your implementation. The 12-point checklist is in `docs/security-design/test-gaps-and-blockers.md` §7. The essentials:
> - only `ProtectedExecutionGuard.execute` may call an adapter;
> - the initial `execution_status` comes from `PolicyDecision.initial_execution_status` (ALLOW → `PENDING_EXECUTION`, which means "not run yet");
> - a revalidation failure writes `NOT_EXECUTED` plus an audit event, not a `tool_executions` row;
> - a timeout is `UNKNOWN`, never success.
>
> When is a first version expected? I'll run the checklist against it the same day.

**To M1 — gateway alignment and direct trust writes**
> Hi M1. Three items for `feat/m1-day7-api-finalization` (`650fe10`):
> 1. **OD-4:** M4 now persists ALLOW as `PENDING_EXECUTION`, matching your `gateway.py:1373`. Thanks.
> 2. **Direct `trust_state` writes outside M4's evaluator:** `incident_management.py:1647-1649` and your `backend/app/security/quarantine.py:131`. That file also collides with M4's `backend/app/security/quarantine.py` on merge. Could quarantine go through M4's `QuarantineWorkflow` (the `M4QuarantineService` compatibility name is there for you)?
> 3. The open gateway items from `docs/security-design/m6-integration-decisions.md` §2–§3: drop `REVIEW`; honest `memory_trust` labels (incl. `REJECTED`, `SUPERSEDED`); no `BLOCKED_BY_TOCTOU` execution row; response decision = persisted decision; `user:`-prefixed `actor_id`.
>
> Also: the real Redis limiter lives only on your branch, and there is no Redis client pinned in `requirements.txt` (see the M7 note).

**To M6 — OD-4 is settled on the M4 side**
> Hi M6. OD-4 is fixed in M4's code: the engine persists ALLOW as `PENDING_EXECUTION` (only for a complete, consistent ALLOW), REQUIRES_APPROVAL as `PENDING_APPROVAL`, everything else as `NOT_EXECUTED`. That matches the insert rule and forward-only trigger in `docs/security-design/m6-integration-decisions.md` §3.1, so you can implement them. I didn't touch any migration or model. Separately, the 5 M4 PostgreSQL drift tests (`backend/tests/security/test_drift_postgres.py`) use your `backend/tests/database/helpers.py`. Could you run them with your `TEST_DATABASE_URL` the next time you run the database suite, and send me the result?

**To M7 — PostgreSQL and Redis for security tests**
> Hi M7. M4's security suite has two infrastructure gaps on developer machines and CI:
> 1. **PostgreSQL 16:** CI needs a service plus `TEST_DATABASE_URL` (login with `CREATEDB`, `CREATEROLE`) and Python 3.12, to run `backend/tests/security/test_drift_postgres.py` (5 tests) next to M6's `backend/tests/database`.
> 2. **Redis 7** (`docker compose up -d redis`) plus a pinned Redis client in `backend/requirements.txt`. None is pinned today, so no code can talk to Redis. I need both for real-outage tests of the rate limiter and idempotency lock (planned cases in `docs/security-design/test-gaps-and-blockers.md` §6).
>
> Which client version do you want to pin, and can CI provide both services?
