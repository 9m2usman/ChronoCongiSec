# Phase 3 Implementation Report: Connected Agent Execution

**Branch:** `feat/phase-3-connected-agent-execution`
**Depends on:** PR #58 (`feat/phase-2-company-app-implementation`, Phase 2 company APIs), which is not yet merged
**Date:** 2026-11-25

## 1. What Phase 3 delivers

The existing agents can now perform real, persisted company operations, and they reach them only through the protected gateway.

```
CrewAI tool / LangGraph contract
  -> ChronoCogniSecClient.propose_tool_action   (JWT of the employee the agent acts for)
  -> POST /api/v1/gateway/actions/propose       (M2 gateway: identity, idempotency, detection)
  -> M4 PolicyEngine + ProtectedExecutionGuard  (grant, operation, approval; ALLOW only dispatches)
  -> CompanyOperationsAdapter                   (backend/app/gateway/adapters/company.py)
  -> Phase 2 company handlers                   (backend/app/api/company.py, one PostgreSQL transaction each)
  -> company_* tables, plus gateway decision, execution and audit evidence
```

The adapter does not reimplement Phase 2. It calls the Phase 2 handlers unchanged, so their workspace ownership, visibility, assignee and recipient rules apply to agents exactly as they apply to employees. On top of those rules, the adapter enforces the agent's governance on the server.

| Check (server side, fail closed) | Source of truth |
|---|---|
| Gateway execution context present (tenant, agent, proposal, trace, user, role) | Gateway executor; direct invocation is refused with 403 |
| Parameters match a strict per-operation schema; tenant, branch, user, role, agent and scope keys are rejected | `PARAMETER_SCHEMAS`, `FORBIDDEN_SCOPE_KEYS` |
| Tenant is ACTIVE | `tenants` |
| Acting employee has an ACTIVE membership, and its branch and role match the authenticated context | `memberships` |
| Agent is ACTIVE, and its governed profile is ACTIVE | `agents`, `agent_security_profiles` |
| Profile `data_scope` covers the employee's branch and every target resource's branch (`branch:<id>:*`) | `agent_security_profiles.data_scope_json` |
| Business authorization and persistence | Phase 2 handlers |

### Operations (`company_workspace` tool)

`list_workspaces`, `list_files`, `read_file`, `create_file`, `update_file`, `transfer_file`, `create_task`, `update_task_status`, `handoff_task`, `send_message`, `read_inbox`.

### Decisions

| Decision | When | Effect |
|---|---|---|
| ALLOW | Grant, operation and all M4 checks pass | The adapter executes. The result is EXECUTED, or FAILED with an honest status code if the adapter refuses |
| BLOCK | No grant, operation not granted, profile not ACTIVE, detection finding (for example a `branch_id` parameter outside the agent's branch) | Not executed. The decision and audit records are persisted |
| REQUIRES_APPROVAL (REVIEW) | `transfer_file` (new M4 `ToolPolicy.always_requires_review`) | Not executed (`PENDING_APPROVAL`). It executes only with a valid, bound, unexpired, non-self human approval, and only once |
| QUARANTINE | Not a gateway decision value in the existing contract | Not implemented in Phase 3; Phase 4 owns containment |

## 2. Changes

| File | Owner | Change |
|---|---|---|
| `backend/app/gateway/adapters/company.py` (new) | M2 directory | Protected company adapter |
| `backend/app/api/gateway.py` | M2 | (a) The executor context now also carries `user_id`, `role` and `branch_id`, taken from the authenticated context (additive). (b) **Bug fix:** `SqlAlchemyGatewayRepository.save_proposal_atomic` now flushes the proposal before inserting the decision. Previously PostgreSQL rejected every database-backed decision (`fk_policy_decisions_proposal_id_tenant`), and the error was reported as `IDEMPOTENCY_KEY_CONFLICT` or `PERSISTENCE_FAILURE`. This also affects `main`. |
| `backend/app/main.py` | M1/M7 | Registers the adapter only when a database session factory exists. Without one, M4 blocks the tool as `TOOL_NOT_REGISTERED` |
| `backend/app/security/policy.py` | M4 | `ToolPolicy.always_requires_review`, reason code `HIGH_IMPACT_APPROVAL_REQUIRED`, and the policy entry for `company_workspace:transfer_file` |
| `backend/app/database/seed.py` | M6/M7 | `company_workspace` tool registration and grants for `agent-crew-branch-004` (all operations) and `agent-crew-coord-005` (coordination operations) |
| `backend/app/api/company.py` | Phase 2 | Removes the unused `and_` import that fails CI ruff. PR #58 needs the same fix |
| `crewai_service/tools/company_tools.py` (new); `agents/branch_operations.py` and `agents/workflow_coordinator.py` | CrewAI | Gateway-only company tools added to the two existing agents whose seeded purpose covers company workflows |

## 3. Verification

The database end-to-end tests use the real FastAPI app, real PostgreSQL (migrated to head and seeded with the canonical seed), real employee logins and the real M4 engine. Assertions read the company rows and the gateway's `tool_proposals`, `policy_decisions`, `tool_executions` and `audit_events` rows back from the database. Nothing is mocked.

Examples executed in CI (`backend/tests/database/test_phase3_connected_agent_execution.py`):

- Dave (Karachi) with `agent-crew-branch-004` runs `create_file`. Result: ALLOW and EXECUTED. A `company_files` row is created with owner Dave, a version row whose checksum matches, and a `FILE_CREATED` activity row. Proposal, decision, execution (with agent provenance) and audit rows are persisted.
- Task lifecycle: `create_task`, then `update_task_status IN_PROGRESS`, then `handoff_task` to Kamran. Result: the task row is updated, task events are `CREATED, UPDATED, UPDATED`, and Kamran receives a `TASK_ASSIGNED` notification.
- `send_message` and `read_inbox`: the message is persisted, and the inbox returns only Dave's messages.
- `transfer_file` without approval: REQUIRES_APPROVAL and PENDING_APPROVAL, with no transfer row. With an approval from Sarah bound to the proposal fingerprint: EXECUTED once. Reusing the same approval is BLOCKed.
- Refused cases, each with no company rows written:
  - Agent without a grant: BLOCK (`TOOL_NOT_ASSIGNED`).
  - Operation not granted: BLOCK (`OPERATION_DENIED`).
  - Suspended profile: BLOCK.
  - Forged `user_id` or `tenant_id`: FAILED 403 (`AGENT_SUPPLIED_SCOPE_REJECTED`).
  - Forged `branch_id`: BLOCK (`BRANCH_ISOLATION_VIOLATION`).
  - Resource in another branch: FAILED 403 (`AGENT_RESOURCE_SCOPE_DENIED`).
  - Agent scope not covering the employee's branch: FAILED 403 (`AGENT_BRANCH_SCOPE_DENIED`).
  - Agent from another tenant: 404.
  - Resource in another tenant: FAILED 404, with no content leaked.
- The CrewAI Branch Operations agent's tools and the existing `LangGraphAdapterContract` executed real operations through the gateway. No LLM was called: the tool an LLM would invoke was executed directly.

CI results are recorded in the PR description.

## 4. Known limitations and follow-ups

1. **No LangGraph agents exist in the repository.** Only `LangGraphAdapterContract` exists, and it has been connected and tested. Creating a LangGraph agent would mean inventing an agent, which Phase 3 forbids.
2. **No approval-creation API.** Approvals are read from the gateway's existing `approvals_store` or `gateway_repo.get_approval`. A human approval workflow is still needed for REVIEW to be usable in the product.
3. **Adapter refusals after ALLOW.** Scope refusals by the adapter are recorded as ALLOW followed by execution FAILED 403, not as a pre-decision BLOCK, because the M4 engine has no access to resource branches. Nothing executes and the refusal is persisted, but dashboards should treat `FAILED` with status 403 as a denial.
4. **Resource-branch check.** The adapter reads a resource's branch before the Phase 2 transaction. This is safe because Phase 2 has no API that moves a workspace or task between branches. If one is added, the check must move inside the transaction.
5. **Errors after commit.** If the database fails after a Phase 2 handler commits, the adapter reports FAILED even though the operation persisted. The gateway contract has no separate "committed but unconfirmed" state.
6. **Findings for M2:**
   - `ChronoCogniSecClient` fabricates ALLOW and BLOCK decisions in TEST_DOUBLE mode without an app. The company tools refuse this path.
   - `crewai_service/framework.py` forces the native runtime even when `crewai` is installed.
   - The SQL repository maps every `IntegrityError` to "idempotency conflict", which hid the foreign-key bug above.
