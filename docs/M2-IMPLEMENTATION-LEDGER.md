# M2 Implementation Ledger

Updated: 2026-11-23

| Day | Requirement | Current state | Evidence | Remaining work |
|---|---|---|---|---|
| 1 | Proposal and execution contracts | IMPLEMENTED BUT NOT VERIFIED | `ActionProposalRequest`, `ToolExecutionResult`, and adapter protocol in `backend/app/api/gateway.py`; strict extra-field, finite-number, payload-size and depth checks exist. | Keep contract aligned with M1/M4/M6 integration tests. |
| 2 | Isolated sandbox transfer adapter | IMPLEMENTED BUT NOT VERIFIED | `SandboxTransferAdapter` is synthetic, validates transfer data, and is registered server-side only. M2 hardening makes receipts deterministic per protected proposal and removes client credential fallbacks. | Add an explicit adapter timeout configuration if a non-local adapter is introduced. |
| 3 | Runtime tool permissions | IMPLEMENTED BUT NOT VERIFIED | M4's `AgentRegistryToolGrants` consumes M1's read-only `get_agent_tool_permissions`; no duplicate permission API or persistence was added. | Permission-version/freshness metadata is not exposed by M1/M6's current contract. |
| 4 | Proposal controller and protected execution | IMPLEMENTED BUT NOT VERIFIED | Gateway calls M4 `PolicyEngine` then `ProtectedExecutionGuard`; durable repository is used before dispatch. | Concurrent durable idempotency needs a PostgreSQL/Redis integration environment. |
| 5 | Trace correlation | PARTIALLY IMPLEMENTED | Proposal, policy, execution, audit, and CrewAI telemetry carry `trace_id`; values are bounded and secrets are redacted. | W3C `traceparent` HTTP propagation is not yet an authoritative M1 trace contract. |
| 6 | Sandbox demonstration | MISSING | Demo directories exist but no M2 reproducible, authenticated three-scenario runner was found. | Blocked on a runnable authoritative seeded M1/M3/M4/M6 environment. |
| 7 | Credential containment audit | PARTIALLY IMPLEMENTED | Removed embedded fallback credentials and default CrewAI backend password; tests cover missing credential fail-closed behavior. | Final repository-wide secret scan and integration suite pending. |

## Implementation checklist

- [x] Preserve M4 as the exclusive policy and execution-guard authority.
- [x] Harden sandbox adapter validation, receipt correlation, and failed-result status mapping.
- [x] Remove agent-client credential fallback behavior.
- [x] Add focused M2 regression tests.
- [ ] Run focused and integration tests; record actual results.
- [ ] Add demo only when it can use the authoritative authenticated gateway path.
- [ ] Commit verified M2 work and push/open a PR when GitHub credentials are available.

## Current integration blockers

1. The current M1/M6 permission reader has no documented permission version, revocation timestamp, or branch scope in the grant object; M2 therefore consumes only its actual published fields and leaves M4 to fail closed on malformed/missing grants.
2. GitHub CLI on this workspace is unauthenticated, so M2 cannot inspect private PR metadata, push, or open the requested PR without a configured GitHub credential.
3. M6's durable idempotency path and M7's Redis control require an available integration database/cache to verify concurrent execution behavior.
