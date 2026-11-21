# M4 Day 4 — Deterministic Policy Engine & Fail-Closed Enforcement

> **Update 2026-11-19 (finding M4-F1):** the guard also keeps a process-local execution ledger. Each (tenant, idempotency key) and each (tenant, approval id) dispatches at most once, whatever the outcome; a consumed approval blocks at evaluation (`APPROVAL_ALREADY_CONSUMED`). Durable cross-process protection remains M6's UNIQUE `tool_executions.proposal_id` plus a Redis lock (M2/M7). The default proposer role is now `AI_DEVELOPER`. See [m4-security-assessment.md](m4-security-assessment.md).

**Document ID:** AMSC-SEC-004
**Owner:** M4 — Security Engine & Incident Response Lead
**Status:**
- The policy engine and execution guard are implemented and tested in M4-owned code.
- **End-to-end protection of the production gateway is NOT yet verified.** No gateway exists on `main`. M1's unmerged gateway branch uses its own placeholder evaluator, which has confirmed bypasses (§8).

**Date:** 2026-11-17
**Plan reference:** Doc 06 §3, Day 4, M4 row: *"Enforce fail-closed policy logic: block proposals referencing tainted memory"*, `security/policy.py`. Dependencies: M2 and M3. Exit: *Tainted proposal blocked; execution prevented.*
**Builds on:** [policy-evaluation-matrix.md](policy-evaluation-matrix.md) (Day 1), [rbac-design.md](rbac-design.md) (Day 2), [trust-state-machine.md](trust-state-machine.md) (Day 3).

| Artifact | Path |
|---|---|
| Policy engine and execution guard | `backend/app/security/policy.py` |
| Action-time memory assessment (added to the Day 3 evaluator) | `backend/app/security/trust.py`: `TrustEvaluator.assess_for_action`, `ActionMemoryAssessment` |
| Unit tests | `backend/tests/security/test_policy_engine.py` |
| HTTP integration tests (test-only reference route) | `backend/tests/security/test_policy_gateway_integration.py` |
| Shared fixtures | `backend/tests/security/conftest.py` |

---

## 1. Requirement mapping

| TRD §16 / Doc 01 rule | Location | Input (server-side) | Failure → decision | Reason code(s) | Tests |
|---|---|---|---|---|---|
| Input: verified tenant context, well-formed proposal | `_evaluate_inner` (Check 0A), `normalize_proposal` | M1 `TenantContext`; Doc 05 §6.1 fields | BLOCK | `TENANT_CONTEXT_INVALID`, `POLICY_INPUT_INVALID` | `test_missing_or_invalid_tenant_context_blocks`, `test_malformed_proposals_blocked` |
| Requesting principal may propose (Day 1 POL-PRN-01) | Check 0B | `TenantContext.role` through Day 2 RBAC | BLOCK | `PRINCIPAL_ROLE_NOT_AUTHORIZED` | `test_principal_role_not_permitted_to_propose`, `test_auditor_cannot_propose` |
| **Check 1:** agent status | `_check_agent` | `AgentDirectory.get_agent` (M3 repo today) | ISOLATED → BLOCK; missing, other tenant or not ACTIVE → BLOCK | `AGENT_ISOLATED`, `AGENT_NOT_REGISTERED`, `AGENT_NOT_ACTIVE` | `test_isolated_agent_blocked` and related |
| **Check 2:** tool whitelist | `_check_tool_and_operation` | `ToolGrantDirectory.get_tool_grant` (M6) | No grant or unregistered tool → BLOCK | `TOOL_NOT_ASSIGNED`, `TOOL_NOT_REGISTERED` | `test_unassigned_tool_blocked`, `test_unregistered_tool_blocked` |
| **Check 3:** operation whitelist | same | `ToolGrant.allowed_operations` | Not listed, or `*` → BLOCK | `OPERATION_DENIED`, `OPERATION_WILDCARD_NOT_PERMITTED` | `test_unauthorized_operation_blocked`, `test_wildcard_operation_grant_not_honoured` |
| **Check 4:** parameter ceilings | `_check_parameters` | `ToolGrant.constraints` (`constraints_json`) | Above `max_*`, below `min_*`, outside `allowed_*`, invalid type, mandatory constraint missing, unknown constraint key → BLOCK | `CEILING_EXCEEDED`, `PARAMETER_BELOW_MINIMUM`, `DESTINATION_NOT_ALLOWED`, `PARAMETER_INVALID`, `POLICY_CONSTRAINT_MISSING`, `POLICY_CONFIG_INVALID` | `test_parameter_above_hard_ceiling_blocked` and related |
| **Check 5:** approval threshold | same | `approval_threshold_*`, server-resolved `ApprovalEvidence` | threshold < value ≤ max → REQUIRES_APPROVAL; invalid approval → BLOCK | `APPROVAL_THRESHOLD_EXCEEDED`, `APPROVAL_*` | `test_parameter_above_approval_threshold_requires_approval`, `test_invalid_approvals_block` |
| **Check 6:** memory trust | `_check_memory` → `TrustEvaluator.assess_for_action` | M3 records and versions; Day 3 decision history | Any reference ineligible, or the evaluator unavailable → BLOCK | `REFERENCED_UNTRUSTED_MEMORY` + specific code | `test_only_trusted_memory_passes` and related |
| ALLOW only if all pass | `_conclude` | — | Anything else → BLOCK | `ALL_CHECKS_PASSED` | `test_baseline_valid_proposal_is_allowed` |
| Fail-closed (OBJ-003, FR-016, SEC-003/004) | `_evaluate`, guard | — | Exception, timeout or missing check → BLOCK | `INTERNAL_EVALUATION_ERROR`, `POLICY_EVALUATION_TIMEOUT`, `RULESET_INCOMPLETE` | section C tests |
| Complete mediation (SEC-001), decision before execution (TRD §14) | `ProtectedExecutionGuard` | — | Adapter not called | `DECISION_NOT_EXECUTABLE`, `DECISION_NOT_ISSUED_BY_ENGINE`, `AUDIT_PERSISTENCE_FAILED`, `PRE_EXECUTION_REVALIDATION_FAILED`, `EXECUTION_GRANT_ALREADY_USED` | section D tests |

---

## 2. Decision algebra

- **Every check is always evaluated,** in TRD order, and each produces `PASS`, `BLOCK`, `REVIEW` or `INDETERMINATE`. Dependency failures are `INDETERMINATE`.
- **The decision follows Day 1 §5.2:**
  1. If any mandatory check is missing, the result is BLOCK `RULESET_INCOMPLETE`.
  2. Any `BLOCK` or `INDETERMINATE` gives BLOCK. The reason codes are the blocking checks' codes.
  3. Any `REVIEW` gives REQUIRES_APPROVAL, but only if the tool policy permits review; otherwise BLOCK `REVIEW_NOT_PERMITTED`.
  4. All `PASS` gives ALLOW, with reason codes exactly `("ALL_CHECKS_PASSED",)`.
  5. Anything else gives BLOCK.
- **Consequences:**
  - A later check, an approval or a score can never lift a BLOCK, so BLOCK always beats REQUIRES_APPROVAL (Day 1 conflict C-2 resolved).
  - All failures are reported together.
- **Determinism:** the same verified inputs and policy version always give the same outcome, reason codes, checks, fingerprint and memory evidence (tested). Only `decision_id`, `evaluated_at` and `elapsed_ms` differ between runs.

---

## 3. Fail-closed behaviour

| Failure | Behaviour |
|---|---|
| Unexpected exception anywhere in the engine | BLOCK `INTERNAL_EVALUATION_ERROR` (status `ERROR`) |
| Evaluation exceeds `timeout_seconds` (default 2 s, Doc 03 §11) | BLOCK `POLICY_EVALUATION_TIMEOUT`. Uses `asyncio.wait_for` for async ports, plus a **post-hoc elapsed check**, because synchronous ports can't be interrupted. |
| Trust evaluator raises or returns a malformed result | BLOCK `MEMORY_TRUST_UNAVAILABLE` + `REFERENCED_UNTRUSTED_MEMORY` |
| Memory repository raises (inside the trust assessment) | Same as above |
| Agent directory raises | BLOCK `AGENT_DIRECTORY_UNAVAILABLE` |
| Tool-grant directory raises | BLOCK `TOOL_GRANT_UNAVAILABLE` |
| Grant malformed, or for the wrong tool | BLOCK `POLICY_CONFIG_INVALID` |
| Constraint missing, unknown or invalid | BLOCK `POLICY_CONSTRAINT_MISSING` / `POLICY_CONFIG_INVALID`. **An unknown key blocks, so a typo can't silently disable a limit.** |
| Tenant context missing or inactive | BLOCK `TENANT_CONTEXT_INVALID`. M1 already returns 401/403 before the engine is reached on HTTP paths. |
| A mandatory check skipped by a code defect | BLOCK `RULESET_INCOMPLETE` |
| Invalid engine configuration | `PolicyConfigurationError` at construction (fail fast) |
| An unknown or malformed decision object reaches the guard | Not executed (`decision_is_executable` is False) |
| Approval can't be verified | Stays `REQUIRES_APPROVAL`, or BLOCK if the presented approval is invalid |

**Redis:** the engine doesn't use Redis. Idempotency locks and rate limits belong to M1/M7, and TRD §20 applies: a failed security-critical lock must block, while an unavailable cache falls back to PostgreSQL.

---

## 4. Memory trust at action time (Check 6)

`TrustEvaluator.assess_for_action(tenant_id, record_id, pinned_version)` is the **only** source of memory eligibility. There is no second trust evaluator. A reference is eligible only if **all** of these hold:

| Condition | Failure code(s) |
|---|---|
| Record exists in the authenticated tenant (no cross-tenant lookup is made) | `MEMORY_REFERENCE_NOT_FOUND`. Identical for a cross-tenant id and a missing id. |
| Stored state is a known value | `MEMORY_STATE_UNKNOWN` |
| Effective state (stored state reconciled with M4 history, Day 3) is `TRUSTED` | `MEMORY_UNVERIFIED` / `_SUSPICIOUS` / `_QUARANTINED` / `_REJECTED` / `_SUPERSEDED`, plus `MEMORY_STATE_HISTORY_MISMATCH` if laundered |
| Pinned version (if supplied) equals the current version | `MEMORY_VERSION_STALE` |
| Every stored version's SHA-256 recomputes | `MEMORY_INTEGRITY_VIOLATION`, or `MEMORY_INTEGRITY_UNVERIFIABLE` |
| An applied M4 TRUSTED decision exists **for this exact version and checksum** | `MEMORY_TRUST_EVIDENCE_MISSING` |
| Every ancestor is TRUSTED and the bounded traversal completes | `MEMORY_LINEAGE_TAINTED`, `_UNVERIFIED`, `_SUPERSEDED`, `_INCOMPLETE` |
| Memory bound to an agent belongs to the proposing agent (`enforce_memory_agent_binding`; matches M1's gateway rule) | `MEMORY_SCOPE_VIOLATION` |

Further behaviour:

| State | Result |
|---|---|
| `TRUSTED`, current, evidenced, clean lineage | Passes |
| `UNVERIFIED`, `SUSPICIOUS`, `QUARANTINED`, `REJECTED`, `SUPERSEDED` | BLOCK `REFERENCED_UNTRUSTED_MEMORY` + `MEMORY_<STATE>` |

- **Requirement for justification.** A tool operation configured with `requires_memory_justification` (default: `sandbox_transfer.transfer_funds`) is blocked when it cites no memory (`MEMORY_JUSTIFICATION_REQUIRED`).
- **Neutralising the M3 bypasses.** Because trust evidence must come from M4's own history:
  - **F-2:** a record set to TRUSTED through M3's unguarded `transition_memory_trust_state`, or by a direct write, **cannot justify an action**;
  - **F-1:** a quarantined record laundered by `update_memory` is still treated as QUARANTINED.

  Both are tested. This closes those bypasses **for protected actions only**. Retrieval still reads the raw stored state (Day 3 R-4).
- **Aggregate `memory_trust`:** the most restrictive state, or `NOT_REFERENCED`, `NOT_FOUND`, `UNKNOWN`, `UNAVAILABLE` or `INELIGIBLE` (TRUSTED but failing another condition). Doc 05's enum lacks several of these (D-06).
- **Pinning versions.** Doc 05's `memory_refs` are plain ids. The engine also accepts `{"record_id", "version"}` pins. Unpinned references resolve to the current version, and that exact version, checksum and evidence id are recorded (Day 1 transition rule). Pinning should become mandatory once M2 adds it (D-03).

---

## 5. Decision contract

`PolicyDecision` (frozen) contains:
- `decision_id`;
- `outcome` (`ALLOW` | `BLOCK` | `REQUIRES_APPROVAL`, the Doc 05 canonical values), `policy_result` (`PERMITTED` / `DENIED` / `ELEVATED`) and aggregate `memory_trust`;
- `reason_codes` (machine) and `reasons` (fixed human text, never containing parameter values);
- per-check `checks`;
- per-reference `memory_evidence`: id, pinned version, version, checksum, effective state, eligibility, trust decision id and codes. **No content.**
- `policy_version` (`amsc-policy/1.0.0`), `evaluated_at`, `evaluation_status` (`COMPLETE` / `TIMEOUT` / `ERROR` / `INPUT_INVALID`) and `execution_eligible`;
- `proposal_fingerprint`: SHA-256 over canonical JSON of tenant, principal, action, agent, tool, operation, parameters, references and idempotency key;
- tenant, principal and role, agent, action, tool, operation, idempotency key, trace id, approval id and elapsed time.

Helpers:
- `decision_is_executable(x)` is True **only** for an untampered, complete, current-policy ALLOW whose reason codes are exactly `ALL_CHECKS_PASSED`. Strings, dicts, enums, `None`, BLOCK, REQUIRES_APPROVAL, timed-out and modified decisions are all False (tested).
- `to_persistence_record()` maps to Doc 05 `policy_decisions` columns (`decision`, `memory_trust`, `policy_result`, `reasons_json`, `execution_status`), plus `details_json` for the `TOOL_POLICY_DECIDED` audit event.

**Parameter types:** `int`, `float` and `Decimal` only. Strings such as `"150"`, booleans and non-finite values are rejected. Day 1 suggested decimal strings for amounts; policy v1 rejects strings because the Doc 05 example uses a JSON number. Changing this needs M2's tool schema (D-11).

**Constraint vocabulary (policy v1, keys in `constraints_json`):**

| Key | Meaning |
|---|---|
| `max_<param>` | Hard ceiling → BLOCK when exceeded |
| `min_<param>` | Floor → BLOCK when below |
| `approval_threshold_<param>` | Above it → REQUIRES_APPROVAL. Must be below `max_<param>`. |
| `allowed_<param>` | Non-empty string allow-list (for example `allowed_destination_account`) |
| Anything else | `POLICY_CONFIG_INVALID` |

A constrained parameter that is missing from the proposal blocks. Constraints apply to every operation in the grant, because Doc 05 has one grant per agent and tool. Operation-scoped constraints need M2's tool schema (D-11).

---

## 6. Execution guard: making "decision before effect" structural

`ProtectedExecutionGuard.execute(decision, proposal, context, persist_decision=..., executor=...)` calls `executor` **only if every step below passes**:

1. `decision_is_executable(decision)`. REQUIRES_APPROVAL returns `PENDING_APPROVAL`; everything else returns `NOT_EXECUTED`.
2. The decision was **issued by this engine instance** and not yet used. A per-engine registry is checked, so forged or copied decision objects are refused.
3. `await persist_decision(decision)` succeeds. If persistence fails, nothing executes.
4. A **fresh evaluation** of the same proposal is ALLOW, with the same fingerprint, tenant and memory snapshot (version, checksum, effective state and trust-evidence id for each reference). This is the protection against changes between decision and execution: quarantine, agent isolation, a swapped proposal, or a re-validated new version.
5. The grant is consumed atomically. Concurrent or repeated execution of one decision runs once.
6. Executor exceptions are reported as `FAILED` and timeouts as `UNKNOWN` (`executed=True`, because the side effect may have occurred). Messages aren't propagated.

**Limit:** the registry is per process and in memory, which is right for in-process enforcement. Multiple workers still need M1/M6's durable idempotency lock and decision row as the cross-process guarantee.

---

## 7. Integration handover

**M1 (gateway route)** — replace the embedded placeholder in `feat/m1-day4-protected-gateway` `api/gateway.py`. In order:
1. Remove `DeterministicPolicyEvaluator`, `UNAUTHORIZED_PROPOSAL_ROLES` and the inline memory loop (steps 5–6).
2. Build the engine once at start-up and store it on `app.state`:
   ```python
   PolicyEngine(trust=TrustEvaluator(memory_repo, trust_store), agents=<agent directory>, tool_grants=<M6 grants>)
   ```
3. On each request:
   ```python
   decision = await engine.evaluate(body, context)
   ```
4. Persist `decision.to_persistence_record()` together with the proposal and audit event (the existing `save_proposal_atomic`).
5. Replace step 9 (TOCTOU check and adapter call) with:
   ```python
   await guard.execute(decision, body, context, persist_decision=<no-op if already persisted atomically>,
                       executor=lambda g: adapter.execute(g.operation, body.parameters, {...}),
                       mandatory_controls=[rate_limit_control(rate_limiter, f"gw:propose:{tenant_id}:{agent_id}", 100, 60)])
   ```
   *Day 7 addition:* `mandatory_controls` takes Redis-backed checks (rate limit, idempotency lock) that must return exactly `True` before persistence and execution. See [fail-closed-validation.md](fail-closed-validation.md) §3.3.
6. Return `decision.outcome.value`. This is **`REQUIRES_APPROVAL`, not `REVIEW`** (Doc 05; M1's branch uses `REVIEW`).

**M2 (proposal schema, adapters):**
- Adapters must only be reachable through `guard.execute`, and should accept the `ExecutionGrant`.
- Add version pins to `memory_refs` (D-03).
- Publish tool schemas: typed parameters, operation-scoped constraints, resource fields (D-11).

**M3:**
- Write `retrieval_events` with trace ids;
- route trust writes through M4 (Day 3 R-1, R-2);
- consult `effective_state()` in retrieval (R-4).

**M6:**
- A `ToolGrantDirectory` implementation over `agent_tool_permissions` + `tool_registrations`.
- Durable trust-decision store (D-07).
- Extra `policy_decisions` columns (`policy_version`, `reason_codes`, `checks`, `memory_evidence`, `proposal_fingerprint`), or keep them in `audit_events.details_json`.
- `approvals.expires_at`, `proposal_fingerprint`, `consumed_at` (D-06).
- Make decisions append-only, and allow a re-evaluation record (the UNIQUE `proposal_id` constraint blocks it today).

**M7:**
- Run the gateway bypass suite against M1's real route once it's wired.
- Pin `greenlet` (required by SQLAlchemy's async extension) and resolve `asyncpg` on Python 3.14.

---

## 8. Findings on M1's unmerged gateway branch (`feat/m1-day4-protected-gateway` @ `19af6d5`)

I ran M1's `DeterministicPolicyEvaluator` in isolation, from a `git archive` copy in a scratch directory. The branch itself was not modified.

| Input | M1 result | M4 engine result |
|---|---|---|
| Referenced memory `SUPERSEDED` | **ALLOW** (relabelled `TRUSTED`) | BLOCK `MEMORY_SUPERSEDED` |
| `amount` missing | **ALLOW** (defaults to 0) | BLOCK `PARAMETER_INVALID` |
| `amount: "nan"` (string) | **ALLOW** (NaN comparisons are false) | BLOCK `PARAMETER_INVALID` |
| 300 < amount ≤ max | BLOCK, hard-coded $300 | REQUIRES_APPROVAL from configured `approval_threshold_amount` |
| Unassigned tool or arbitrary operation | Evaluator ALLOW. Only the later adapter-registry lookup blocks unregistered tools; there's no per-agent grant check. | BLOCK `TOOL_NOT_ASSIGNED` / `OPERATION_DENIED` |

The branch also:
- authorises callers with a role **deny-list** (Day 2 R-3);
- reads raw `record.trust_state`, ignoring M4 history and evidence;
- raises 500 on a checksum mismatch **before** persisting any decision, so no audit record exists for that attempt.

---

## 9. Research alignment

What follows are AMSC implementation decisions, informed by these sources. None of the sources' reported results are claimed for AMSC.

| Principle applied | Source (status) | Where |
|---|---|---|
| Deterministic hard rules at the tool boundary; action-level rules block even when detection fails; no score authorises | AgentGuard `docs/EVALUATION.md`, as summarised in Doc 07 §4.1 (project-reported, synthetic) | All checks are deterministic. The destination allow-list blocks the attacker account even with trusted memory (`test_trusted_memory_does_not_authorize_attacker_destination`). |
| Test injected instructions in retrieved content; assert real side effects; keep benign utility | AgentDojo (NeurIPS 2024) | Integration scenarios assert the spy adapter was not called; benign controls must still execute |
| Poisoning through ordinary channels, delayed activation | [MINJA](https://arxiv.org/abs/2503.03704) (NeurIPS 2025); [MemPoison](https://arxiv.org/abs/2607.14651) (preprint) | `test_undetected_poisoned_memo_still_blocked_because_unverified`, `test_delayed_poisoning_of_trusted_manual_blocks_later_action` |
| Derived memory no more permissive than its source; re-check at action time | [MemLineage](https://arxiv.org/abs/2605.14421) (preprint). AkasicMEM is cited in Doc 07 but **wasn't found** in the Day 3 searches, so it isn't relied on. | Lineage check at action time (`test_poisoned_derivation_of_trusted_source_is_blocked`) |
| Complete mediation, fail-safe defaults, per-request authorisation | Saltzer & Schroeder 1975; [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Guard, default BLOCK, revalidation before execution |
| Least privilege, explicit allow-lists, deny by default | [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ASI02 / ASI03 / ASI06; [CWE-862](https://cwe.mitre.org/data/definitions/862.html) / [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Wildcard refused; unknown constraint keys refused; proposer role allow-list |

---

## 10. Verification (executed 2026-11-17)

Environment: Python 3.14.5, pinned requirements (`asyncpg` excluded), branch `feat/m4-security-ml`.

| Command | Result |
|---|---|
| `pytest backend/tests/security/test_policy_engine.py` | **165 passed** |
| `pytest backend/tests/security/test_policy_gateway_integration.py` | **24 passed** |
| `pytest --ignore=backend/tests/database` (full suite) | **705 passed, 2 xfailed** (the xfails are the Day 3 strict markers for M3's F-1/F-2); no existing test modified |
| `pytest backend/app/memory/tests -k gap` | 9 passed (GAP-001..004) |
| `pytest backend/tests/database` | **Not run:** `asyncpg` can't be installed on Python 3.14 |
| Mutation check | **13 of 13** injected regressions caught (listed in the Day 4 report) |
| Latency, in-memory, 3 trusted references, n=2000 | p50 0.30 ms, p95 0.80 ms, p99 1.14 ms. 100 concurrent evaluations: 44.7 ms total. **Excludes PostgreSQL and network**, so this does not show the TRD's 50 ms P95 target is met in deployment. |

---

## 11. Limitations and remaining risks

| ID | Owner | Risk |
|---|---|---|
| P-1 | M1 / M2 | **No production gateway uses this engine yet.** M1's branch keeps a bypassable placeholder (§8). Until M1 adopts §7, the Day 4 exit criterion is met only at the unit and reference-harness level. |
| P-2 | M6 | No `ToolGrantDirectory` implementation over the real tables; no durable decision or approval fields. Approvals can never be satisfied with the current schema, so they fail closed. |
| P-3 | M1 | No agent API-key principals. Proposals are authorised as human members whose role is `DEVELOPER`; `AI_DEVELOPER` is denied (role vocabulary, Day 2 R-1). |
| P-4 | M2 | Constraints apply per grant, not per operation. Parameter types and resource fields aren't schema-defined yet. |
| P-5 | M3 | Retrieval still reads the raw stored state. The engine compensates at the action boundary only. |
| P-6 | M4 | The grant registry is per process. Cross-worker single execution relies on M1/M6's idempotency lock. |
| P-7 | M4 | Synchronous repository calls can't be pre-empted. The post-hoc timeout converts an overrun to BLOCK, but the time is still spent. |
