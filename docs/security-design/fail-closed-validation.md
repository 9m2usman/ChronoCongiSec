# M4 Day 7 — Fail-Closed Validation Across Simulated Infrastructure Failures

**Document ID:** AMSC-SEC-007
**Owner:** M4 — Security Engine & Incident Response Lead
**Date:** 2026-11-18
**Plan reference:** Doc 06 §3 Day 7, M4 row: *"Review fail-closed behavior across simulated infrastructure failures"* → *Fail-closed test suite*. Exit: *All simulated outages trigger `BLOCK`.*

**Status: PARTIALLY COMPLETE.**
- Every M4 acceptance criterion is verified at the M4 component and reference-harness level.
- The production gateway (M1/M2) still uses its own placeholder evaluator and doesn't call the M4 engine or guard.
- No PostgreSQL or Redis server was available, so database and Redis failures were simulated at the interface (§6).

| Artifact | Path |
|---|---|
| Fail-closed suite (208 tests) | `backend/tests/security/test_fail_closed.py` |
| Hardening: strict trust evidence, mandatory controls, decision integrity | `backend/app/security/policy.py` |
| Hardening: invalid store results → 503 | `backend/app/security/drift.py` |

---

## 1. Invariant under test

A protected adapter is invoked **only** if all of the following hold:

1. The engine issued an ALLOW, and that exact decision object is internally consistent.
2. Every mandatory control (Redis lock, replay check, rate limit) returned exactly `True`.
3. The decision was persisted without error.
4. A fresh re-evaluation matches.
5. The single-use grant was consumed.

Every other path, including exceptions, timeouts, `None`, unknown values and malformed evidence, ends **without** an adapter call. Each test asserts the safe result **and** that the `SpyAdapter` recorded **zero** calls.

---

## 2. Scenario matrix (all executed 2026-11-18)

| # | Failure scenario | Interface exercised | Expected | Result |
|---|---|---|---|---|
| 1 | PostgreSQL connection refused or timeout during decision persistence | **M6 `UnitOfWork` + `AuditEventRepository`** (fault-injecting session) | No execution; nothing committed | **PASS** (`AUDIT_PERSISTENCE_FAILED`, spy 0, committed 0) |
| 2 | Session/statement failure (`OperationalError` on `set_config`) | same | same | **PASS** |
| 3 | Query/flush failure (`DBAPIError`, `IntegrityError` 23503) | same | same | **PASS** |
| 4 | Post-insert refresh failure | same | same | **PASS** |
| 5 | **Commit failure** after the audit insert | same | Rolled back; no execution | **PASS** |
| 6 | `asyncio.TimeoutError` / unexpected driver exception | same | same | **PASS** |
| 7 | Persistence callable missing, not callable, or returns `False` | Guard | No execution | **PASS** |
| 8 | Healthy database (control case) | same | Persist **then** execute | **PASS** (exactly one committed audit row, then one adapter call) |
| 9 | DB failure during drift review (connect / statement / flush / commit / CAS update) | **`SqlDriftReviewStore` → M6 `UnitOfWork`** | 503; nothing committed | **PASS** |
| 10 | Trust decision store outage during quarantine | `QuarantineWorkflow` | FAILED; state reverted | **PASS** |
| 11 | Redis rate limiter refused / timeout / asyncio timeout / OS error / unexpected / M1 `SecurityDependencyError` | **M1 `RateLimiterProtocol`** via `rate_limit_control` | No execution; persistence not attempted | **PASS** (`MANDATORY_CONTROL_UNAVAILABLE`) |
| 12 | Rate limiter returns `None`, dict, `True`, string, look-alike object, `allowed=False`, `allowed="true"`, `allowed=1` | same | No execution | **PASS** (`MANDATORY_CONTROL_DENIED`) |
| 13 | **M1's real `InMemoryRateLimiter`** marked unavailable; exhausted | M1 class | No execution (second action) | **PASS** |
| 14 | Idempotency lock not acquired (`False`, `None`, `"OK"`, `1`, bytes, dict) or acquisition raising | `lock_control` | No execution | **PASS** |
| 15 | Raw control returning a truthy non-`True` value | Guard (`MandatoryControl`) | No execution | **PASS** |
| 16 | Malformed control configuration | Guard | No execution | **PASS** |
| 17 | Redis not required (policy, trust, quarantine, drift) | Engine | Unaffected | **PASS**. These components have no Redis dependency, so a Redis outage doesn't block them. |
| 18 | Trust evaluator connection error / timeout / crash | `TrustEvaluator.assess_for_action` | BLOCK, no execution | **PASS** (`MEMORY_TRUST_UNAVAILABLE`) |
| 19 | Trust result `None`, dict, wrong record, `found=False`+eligible, non-TRUSTED+eligible, missing/unknown state, missing/malformed checksum, missing or string version, missing/blank evidence id, list reason codes, truthy non-bool eligible | same | BLOCK | **PASS**. **These cases found a real weakness, now fixed (§3.1).** |
| 20 | Trust backing stores time out (decision store, versions, provenance edges) | M4 + M3 repository | BLOCK | **PASS** |
| 21 | Each non-TRUSTED state (UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED) | Engine | BLOCK, no execution | **PASS** |
| 22 | Missing / cross-tenant / trusted-outside-M4 / tampered / updated-after-validation memory | Engine | BLOCK, no execution | **PASS** |
| 23 | Agent-supplied trust claims in the proposal | Engine | Ignored → BLOCK | **PASS** |
| 24 | Exception in any policy stage (agent, tool, parameters, memory, conclusion, whole evaluation) | Engine | BLOCK | **PASS** (no secrets in the decision) |
| 25 | A mandatory check silently skipped | Engine | BLOCK `RULESET_INCOMPLETE` | **PASS** |
| 26 | Policy timeout (injected `asyncio.TimeoutError`), and a post-hoc budget overrun (injected clock) | Engine | BLOCK `POLICY_EVALUATION_TIMEOUT` | **PASS** (no real sleeps) |
| 27 | Tool permission missing, wrong type or wrong tool; permission store outage; agent directory outage | Engine | BLOCK | **PASS** |
| 28 | Parameter ceiling missing, unknown key, string limit, invalid constraints | Engine | BLOCK | **PASS** |
| 29 | Approval missing, or malformed approval evidence | Engine + guard | REQUIRES_APPROVAL never executes; malformed → BLOCK | **PASS** |
| 30 | Invalid policy configuration | Engine constructor | Refuses to start | **PASS** |
| 31 | Unknown decision objects (`None`, `"ALLOW"`, dict, enum, object, int) | Guard | No execution | **PASS** |
| 32 | **Tampered or inconsistent ALLOW**: conflicting `policy_result`, missing or extra reason codes, `TIMEOUT` status, non-eligible flag, wrong version, dropped/BLOCK/INDETERMINATE/duplicate check, ineligible memory, forged id | Guard + `decision_is_executable` | No execution | **PASS**. **These cases found a real weakness, now fixed (§3.2).** |
| 33 | **ALLOW copy with a re-targeted `tool_name`, `operation`, `agent_id`, `principal_id`, `approval_id` or `trace_id`** | Guard | No execution | **PASS** (§3.2) |
| 34 | Decision issued by a different engine instance | Guard | No execution | **PASS** |
| 35 | Dependency fails between persistence and execution | Guard revalidation | No execution | **PASS** |
| 36 | Missing / invalid / inactive / blank tenant context | Engine | BLOCK `TENANT_CONTEXT_INVALID` | **PASS** |
| 37 | Unauthorised or unknown role (`AI_DEVELOPER`, `AUDITOR`, …) | Engine (Day 2 RBAC) | BLOCK | **PASS** |
| 38 | Tenant mismatch between decision and execution | Guard revalidation | No execution | **PASS** |
| 39 | HTTP: missing token, forged `alg=none` token, `X-Tenant-ID` mismatch, revoked membership, **auth repository outage** | **M1 `get_tenant_context`** | 401/403/503; adapter 0 | **PASS** (no secrets or traceback in response) |
| 40 | HTTP: client-supplied `tenant_id` in the body | M1 + engine | Ignored | **PASS** |
| 41 | HTTP: Redis limiter unavailable / DB commit failure / DB connect failure while the decision is ALLOW | M1 + engine + guard + M6 | `NOT_EXECUTED`; adapter 0; committed 0 | **PASS** |
| 42 | Matrix of 11 failure scenarios through one invariant | Guard | Adapter never reached | **PASS** |
| 43 | Adapter timeout after dispatch | Guard | `UNKNOWN` (executed=True), never "success" | **PASS** |
| 44 | Adapter failure after dispatch | Guard | `FAILED` (executed=True), not a "safe block" | **PASS** |
| 45 | Benign, fully authorised request (control) | All | Executes exactly once with a grant bound to the decision | **PASS** |

**Secrets.** Injected exception messages contained a PostgreSQL DSN password and a Redis password. Neither appears in logs (`caplog`), decisions, outcomes or HTTP responses (asserted).

---

## 3. Weaknesses found and fixed during Day 7 (M4-owned code)

### 3.1 Trust eligibility was inferred, not proven

**Before:** `_check_memory` accepted any `ActionMemoryAssessment` with `eligible=True` and no reason codes. A faulty or substituted trust implementation returning `found=False, eligible=True`, a non-TRUSTED state, or missing checksum or evidence would have passed.

**Now:** eligibility also requires all of `found is True`, `effective_state == "TRUSTED"`, an integer version ≥ 1, a 64-hex checksum, a non-blank trust-decision id, and `reason_codes` that is a tuple. Otherwise the result is `MEMORY_TRUST_EVIDENCE_INCOMPLETE`, which blocks.

### 3.2 A modified copy of a genuine ALLOW could execute

**Before:** the guard's "issued by this engine" registry compared only the decision id and proposal fingerprint, and `decision_is_executable` didn't check internal consistency. A `dataclasses.replace` copy with, for example, `tool_name="cloud_infra"` kept the same id, fingerprint and memory snapshot, so it passed revalidation. **The `ExecutionGrant` handed to the executor would then have named a different tool.** Copies with contradictory fields (`policy_result=DENIED`, a non-PASS check) were similarly accepted.

**Now:**
- The registry stores the issued decision itself and requires **whole-object equality**, so any altered field means "not issued".
- `decision_is_executable` also requires `policy_result=PERMITTED`, exactly one PASS result for every mandatory check, and all memory evidence eligible.

### 3.3 No enforcement point for Redis-backed mandatory controls

**Before:** the guard had no way to require a distributed lock, replay check or rate limit before execution.

**Now:** `ProtectedExecutionGuard.execute(..., mandatory_controls=[...])` runs each `MandatoryControl` **before** persistence and execution, and requires the result to be **exactly `True`**. Exceptions give `MANDATORY_CONTROL_UNAVAILABLE`; any other value gives `MANDATORY_CONTROL_DENIED`.
- `rate_limit_control(limiter, ...)` wraps M1's existing `RateLimiterProtocol`, accepting only a real `RateLimitResult` with `allowed is True`.
- `lock_control(acquire)` wraps a lock or replay acquisition that returns `True`.
- No Redis client was added.

`persist_decision` explicitly returning `False` now also counts as a persistence failure.

### 3.4 Invalid drift store results caused an unhandled 500

`DriftReviewService` now validates store result types. Invalid results become a 503 `SECURITY_DEPENDENCY_UNAVAILABLE` instead of an unhandled 500.

### Mutation check of the hardening

Each change was reverted individually against the suite, and each reversion was caught:

| Mutant | Failing tests |
|---|---|
| H1 strict trust evidence | 10 |
| H2 whole-object registry | 6 |
| H3a/b/c consistency (`policy_result` / checks / memory) | 2 / 3 / 1 |
| H4 exact-`True` controls | 7 |
| H5 control exception treated as pass | 15 |
| H6 `persist()==False` ignored | 1 |
| H7 controls skipped | 33 |
| H8 / H9 drift result validation | 5 / 4 |

H2, H3 and H4 first **survived**, because overlapping defences masked each other. I added targeted tests (re-targeted fields, direct `decision_is_executable` checks, raw control values) until each one is caught independently.

---

## 4. Findings outside M4 ownership (verified read-only in scratch copies; branches not modified)

| ID | Owner | Finding | Evidence |
|---|---|---|---|
| F7-1 | **M1 / M7** | `RedisRateLimiter` (branch `feat/m1-day7-api-finalization`) **fails open** when Redis errors and `failure_policy` is anything other than the exact string `"fail_closed"`. `"FAIL_CLOSED"`, `"fail-closed"` and `"fail_open"` all return `allowed=True`. Production *settings* are forced to `fail_closed`, but the constructor parameter isn't validated. | Scratch probe: Redis down with `'FAIL_CLOSED'` → `allowed=True` |
| F7-2 | **M1 / M7** | A configured Redis client without `eval` silently falls back to the per-process counter, which isn't distributed. | Probe: `[True, False]` from local counters |
| F7-3 | **M1 / M7** | `RedisRateLimiter(redis_client=None)` reports `backend="redis"`, `is_persistent=True`, so the production identity check would accept a limiter with no Redis (GAP-006). | Probe output |
| F7-4 | **M1 / M2** | The Day 7 branch's `api/gateway.py` is **byte-identical** to the Day 4 branch. Its placeholder evaluator still ALLOWs SUPERSEDED memory, a missing amount and `"nan"` amounts, and has no grant check (Day 4 §8). It doesn't use the M4 engine, guard or quarantine workflow. | `git diff` empty; Day 4 probe |
| F7-5 | **M1** | The Day 7 branch still ships its own `security/quarantine.py` (an M4 path) with in-place mutation (Day 5 §8). | Branch file list |

**Recommended fixes:**
- **F7-1 to F7-3:** validate `failure_policy` against `{"fail_closed", "fail_open"}` and reject `fail_open` outside development; refuse construction without a client in production; derive the backend identity from the actual client.
- **F7-4 and F7-5:** adopt the Day 4 §7 and Day 5 §8 patches, passing `mandatory_controls=[rate_limit_control(limiter, ...)]` to the guard.

---

## 5. Requirement-to-test traceability

| Acceptance criterion (prompt §15) | Evidence |
|---|---|
| 1 Database failure blocks | Matrix rows 1–9, 41 |
| 2 Redis mandatory-control failure blocks | Rows 11–16, 41; row 17 shows non-dependent components aren't blocked |
| 3 Trust evaluator failure blocks | Rows 18–22 |
| 4 Policy evaluator failure blocks | Rows 24–30 |
| 5 Missing or invalid tenant context prevents action | Rows 36–40 |
| 6 Invalid evidence never produces ALLOW | Rows 19, 23, 28–29, 32–33 |
| 7 Persistence failure prevents execution | Rows 1–7, 41 |
| 8 BLOCK never invokes the adapter | Rows 21–22, 42 |
| 9 REQUIRES_APPROVAL never invokes the adapter | Rows 29, 42 |
| 10 No failure becomes ALLOW | Whole matrix; §3 mutation check |
| 11 Trusted-memory and quarantine protections intact | Day 3/5 suites; `test_retrieval_and_quarantine_invariants_hold_under_failure` |
| 12 GAP-001 to GAP-004 | 9 regression tests pass (§6) |
| 13 Benign requests still work | Rows 8, 45; HTTP benign test |
| 14 Real interfaces | M6 `UnitOfWork`/repositories, M1 auth and rate limiter, M3 repository, M4 engine/guard/trust/quarantine/drift |
| 15 No other subsystem rewritten | Only M4 files changed |

---

## 6. Verification and environment limits

**Environment:**
- Python 3.14.5.
- Pinned requirements, except `asyncpg` (0.29.0 can't build on 3.14; the scratch venv has 0.32.0 so the SQL modules import). The scratch venv predates M6's `alembic`/`greenlet` pins.
- Branch `feat/m4-security-ml` @ merge `b15e225` (contains `origin/main` `2b3f738`).

| Command | Result |
|---|---|
| `pytest backend/tests/security/test_fail_closed.py` | **208 passed** |
| `pytest backend/tests/security` (Days 2–7) | **974 passed, 5 skipped, 2 xfailed** |
| `pytest backend/app/memory/tests -k gap` | **9 passed:** GAP-001 (2), GAP-002 (1), GAP-003 (4), GAP-004 (2) |
| `pytest --ignore=backend/tests/database` (full suite) | **1148 passed, 5 skipped, 2 xfailed**; no existing test modified |
| `pytest backend/tests/database` (M6) | **Not run:** no PostgreSQL server (and the scratch venv lacks `alembic`) |

- **Skipped (5):** `test_drift_postgres.py`, which needs `TEST_DATABASE_URL`.
- **xfailed (2):** the strict markers for M3 findings F-1 and F-2.

**Not tested against real infrastructure:**
- PostgreSQL connection loss, `FOR UPDATE` blocking and audit hash-chain behaviour on a live server;
- Redis outages on a live server.

These were simulated at the interface boundary: M6's real `UnitOfWork` with a fault-injecting session, and M1's real limiter class plus protocol doubles. My Day 6 attempt to obtain a local PostgreSQL was blocked by session permission policy.

---

## 7. Research alignment

These are AMSC implementation decisions informed by the sources below. No paper's results are claimed.

| Principle | Source | Applied as |
|---|---|---|
| Evaluate every request; no implicit trust; failures never inherit earlier authorisation | [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Revalidation at execution time; a decision from another engine instance or a different tenant is refused; dependency failures map to INDETERMINATE → BLOCK |
| Fail-safe defaults; complete mediation | Saltzer & Schroeder 1975 (PRD §6.2) | Single enforcement point (guard); default BLOCK; exact-`True` controls |
| Tool misuse; identity and privilege abuse; memory and context poisoning | [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ASI02/ASI03/ASI06 | Grant bound to the exact issued decision (re-targeted tool refused); role allow-list; trust evidence must be complete |
| Secure failure handling; no sensitive data in errors | [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/); [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Secrets injected into exceptions are asserted absent from logs and responses |
| The action boundary is the real control; test actual side effects | AgentGuard `docs/EVALUATION.md` (as summarised in Doc 07 §4.1); AgentDojo (NeurIPS 2024) | Every test asserts spy calls = 0; benign controls must still execute |
| Missing trust evidence is never trust; lineage and provenance must stay verifiable | [MINJA](https://arxiv.org/abs/2503.03704), [MemPoison](https://arxiv.org/abs/2607.14651), [MemSecBench](https://arxiv.org/abs/2607.27080), [MemLineage](https://arxiv.org/abs/2605.14421), [TrustMem](https://aclanthology.org/2026.findings-emnlp.2419/), [HaluMem](https://arxiv.org/abs/2511.03506) | §3.1 strict evidence; trust-store outages block; tampered or updated memory blocks. AkasicMEM remains unverified and isn't relied on. |

---

## 8. Remaining risks and integration dependencies

| ID | Owner | Item |
|---|---|---|
| R7-1 | **M1 / M2** | **The production gateway doesn't call the M4 engine or guard**, and its placeholder has confirmed bypasses (F7-4). Until it adopts the guard, these results don't prove the production route is protected. This is the main G7 blocker. |
| R7-2 | **M1 / M7** | Redis limiter fail-open paths (F7-1 to F7-3). |
| R7-3 | **M6 / M7** | Live PostgreSQL and Redis outage tests in CI (`test_drift_postgres.py`, M6 suite, a lock/limiter against real Redis). |
| R7-4 | **M3** | F-1 / F-2 (update laundering, unguarded trust transitions); retrieval doesn't consult M4's reconciled state. |
| R7-5 | M4 / M7 | **The single-use grant registry is per process.** Cross-worker single execution relies on the mandatory lock control plus M6's `uq_tenant_idemp_key`. A lock acquired before a later failure isn't released by the guard; it expires by TTL, which fails toward blocking retries. |
| R7-6 | M4 | **`asyncio.CancelledError` is not caught.** Cancellation before the executor means no execution. Cancellation during the executor leaves the outcome to the caller, and the side effect may have occurred. |
| R7-7 | Team | **G7 needs every member's sign-off:** M2 credential containment, M3 checksum audit, M5 UI, M6 clean migrations, and M7's full integration and demo run. M4's results are one input. |
