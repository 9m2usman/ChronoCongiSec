# M2 Credential Containment Audit

Audit date: 2026-11-23  
Scope: M2 gateway adapter and CrewAI runtime integration surfaces.

## Inspected surfaces

- `backend/app/api/gateway.py`: proposal validation, adapter registry, sandbox dispatch, execution-result normalization.
- `backend/app/security/runtime.py`: M4 engine and guard wiring (consumed, not changed).
- `backend/app/database/models/gateway.py` and `backend/app/database/repositories/gateway.py`: M6 execution-chain and idempotency interfaces (consumed, not changed).
- `crewai_service/tools/amsc_client.py`: agent-to-gateway HTTP client.
- `crewai_service/config/settings.py` and `crewai_service/.env.example`: runtime configuration.
- `crewai_service/telemetry/tracer.py`: telemetry redaction.

## Findings and fixes

| Finding | Risk | Fix | Evidence |
|---|---|---|---|
| The CrewAI client retried failed login using literal credential pairs. | A source-controlled secret and silent principal/tenant substitution. | Removed all fallback pairs; a 401 now fails closed. | `test_crewai_client_fails_closed_without_backend_credential`. |
| The CrewAI settings class supplied a default backend password. | Credential material was available without deployment configuration. | Changed the password setting to optional with no default and removed it from the example environment file. | Focused M2 test; configuration review. |
| Sandbox receipts used random transaction IDs and accepted loosely coerced transfer values. | Retry reconciliation was weak and malformed values could be obscured. | Validate account, currency, and finite positive Decimal amount; derive a deterministic synthetic transaction ID from server-only context. | Adapter success/rejection regression tests. |
| Failed adapter results were stored as `EXECUTED`. | Evidence could incorrectly represent a failed adapter as successful execution. | Map adapter `FAILED` and `TIMEOUT` result states to `FAILED` and `UNKNOWN`. | Gateway focused regression selection. |

## Security controls verified by code inspection

- The agent runtime calls the authenticated gateway client; it does not receive a `SandboxTransferAdapter` instance or adapter credential.
- The gateway invokes an adapter only from M4 `ProtectedExecutionGuard.execute`; M4 remains the sole policy decision authority.
- M1 tenant context is used for tenant authority. Client proposal data cannot supply a tenant identifier.
- M4 receives M1/M6 agent-tool grants through `AgentRegistryToolGrants`; missing or malformed grants fail closed.
- M6's tenant/idempotency unique constraint and proposal-to-execution chain are consumed by the gateway repository contract.
- Gateway audit payloads and CrewAI telemetry apply key-based secret redaction. The M2 patch avoids logging backend response bodies during authentication failures.

## Test results

- `backend/tests/unit/test_m2_gateway_adapters.py`: 5 passed.
- `backend/tests/unit/test_gateway.py -k 'happy_path or blocked or idempotency'`: 9 passed, 20 deselected.
- `crewai_service/tests/test_security_boundaries.py crewai_service/tests/test_provider_configuration.py`: 13 passed.
- Python compilation of changed M2 Python modules: passed.
- Ruff: not run because the configured Python environment has no `ruff` module/binary.

The pytest cache emitted an existing Windows cache-path warning; it did not affect test assertions.

## Remaining risks and blockers

1. The repository does not expose an authoritative W3C `traceparent` propagation contract yet; M2 preserves the existing bounded `trace_id` correlation field.
2. Redis/database-backed concurrent idempotency requires the M6/M7 integration environment and was not claimed as verified locally.
3. `crewai_service/.env` in the local workspace contains a password; it is ignored by Git and was not modified. Deployments should source it from a secret manager rather than a committed file.
4. The GitHub CLI is unauthenticated in this workspace, blocking PR inspection, branch push, and PR creation.
