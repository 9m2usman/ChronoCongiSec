# M2 Security & Credential Containment Audit

**Audit Date:** 2026-11-23  
**Auditor:** M2 — Agent Runtime & Gateway Adapters Lead  
**Scope:** M2 Gateway Adapters, Execution Guard Integration, CrewAI Runtime Security Boundaries, and Telemetry Surfaces.  

---

## 1. Scope and Inspected Surfaces

The following codebase surfaces were inspected and audited for credential exposure, authorization bypasses, injection vulnerabilities, and complete mediation compliance:

1. `backend/app/api/gateway.py`:
   - Proposal schema validation (`ActionProposalRequest`), payload bounds, finite numeric checks, memory-ref format validation.
   - Adapter registry, parameter normalization, and synthetic transaction execution (`SandboxTransferAdapter`).
   - M4 policy engine integration and execution guard dispatch.
2. `backend/app/main.py`:
   - Request context middleware, W3C `traceparent` header extraction and response injection.
3. `crewai_service/tools/amsc_client.py`:
   - Gateway proposal HTTP client, authentication header management, W3C `traceparent` injection, and error handling.
4. `crewai_service/tools/gateway_tools.py`:
   - Agent tool proposals (`propose_expense_disbursement`, `propose_customer_refund`), parameter aliasing, and active run trace propagation.
5. `crewai_service/config/settings.py` & `crewai_service/.env.example`:
   - Runtime configuration defaults, provider settings, and secret management.
6. `crewai_service/telemetry/tracer.py`:
   - Audit event logging, secret redaction, and run status transitions.
7. `demo/run_demo2.py` & `demo/blocked_action/run_demo2.py`:
   - Authoritative three-scenario demonstration verifying ALLOW, ceiling BLOCK, and poisoned memory BLOCK.

---

## 2. Findings, Vulnerability Analysis, and Remediations

| # | Component | Identified Risk | Remediation Implemented | Verification Evidence |
|---|---|---|---|---|
| **F-01** | `amsc_client.py` | **Hardcoded Credential Fallback:** Client retried failed authentication using fallback username/password pairs (`finance.agent@company.com`, `hr.agent@company.com`). | Removed all fallback credentials and hardcoded dictionaries. If valid credentials or tokens are missing, client fails closed immediately with 401 error. | `test_crewai_client_fails_closed_without_backend_credential` |
| **F-02** | `settings.py` | **Default Backend Password:** `AMSC_BACKEND_PASSWORD` had a default literal string value. | Changed setting to optional with `None` default; removed secret references from `.env.example`. | Python module inspection; settings unit tests. |
| **F-03** | `gateway.py` | **Adapter Parameter Aliasing & Type Smuggling:** Business tools sent `destination` and `amount` while adapter required `destination_account` and `amount_usd`. Inconsistent conversion could allow unvalidated fields. | Normalizer accepts aliases while enforcing strict bounded regex (`^[a-zA-Z0-9_\-\.]{3,64}$`), finite positive Decimal conversion, and positive currency checks. | `test_sandbox_transfer_accepts_parameter_aliases`, `test_sandbox_transfer_rejects_invalid_or_forbidden_requests` |
| **F-04** | `amsc_client.py` / `gateway_tools.py` | **Broken Trace Correlation:** Tools generated disconnected random trace IDs (`trace-exp-...`) on every proposal, losing logical workflow correlation with the active CrewAI task run. | Tools now inherit the active execution run's `trace_id` from `tracer` (or caller `kwargs`). `amsc_client.py` formats and injects standard W3C `traceparent` (`00-{trace_id}-{span_id}-01`). `backend/app/main.py` extracts and echoes `traceparent`. | `test_day5_trace_propagation_from_active_run_to_proposal` |
| **F-05** | `gateway.py` | **Complete Mediation Violation Risk:** Potential direct adapter invocation bypassing policy engine. | Adapters are registered in a private server-side dictionary (`_ADAPTER_REGISTRY`) inaccessible to agent clients. Gateway invokes adapters exclusively through M4 `ProtectedExecutionGuard.execute` after M4 `PolicyEngine.evaluate` returns `ALLOW`. Direct adapter invocation by agents is structurally prohibited. | `test_gateway_module_has_no_competing_policy_evaluator`, `test_day6_demo2_complete_mediation_all_scenarios_pass` |
| **F-06** | `demo/run_demo2.py` | **Missing Authoritative Demonstration:** Lack of reproducible runner demonstrating all 3 mediation scenarios with end-to-end evidence. | Created authoritative standalone runner `demo/run_demo2.py` and service CLI option `crewai_service/main.py --demo 2` exercising Scenario A (ALLOW), Scenario B (Ceiling BLOCK), and Scenario C (Poisoned Memory BLOCK). | `python demo/run_demo2.py` and `test_day6_demo2_complete_mediation_all_scenarios_pass` |
| **F-07** | `gateway.py` | **Adapter Invocation Without Context:** `SandboxTransferAdapter.execute` executed with empty context `{}` and generated mock receipts. | Enforced mandatory authorized context validation (`tenant_id`, `agent_id`, `idempotency_key`, `trace_id`); missing or partial context fails closed immediately with 403 Forbidden. Added upper limit check ($1,000,000.00). | `test_sandbox_transfer_direct_invocation_without_authorized_context_is_prevented`, `test_sandbox_transfer_amount_ceiling_and_invalid_operations` |
| **F-08** | `gateway.py` | **Missing Active Timeout Enforcement:** Gateway controller did not wrap adapter calls in `asyncio.wait_for`, risking indefinite stalls if an external adapter hangs. | Wrapped adapter execution in `asyncio.wait_for(..., timeout=adapter.timeout)`; guard cleanly records `UNKNOWN` status with 504 status code upon timeout. | `test_day4_adapter_execution_timeout_and_failure` |
| **F-09** | `main.py` / `amsc_client.py` | **W3C Traceparent Incomplete Validation & Double-Hashing:** All-zero trace IDs were accepted; 32-hex trace IDs were re-hashed into mismatched trace IDs. | Strictly validate W3C traceparent regex; reject all-zero trace and parent IDs; avoid double-hashing 32-hex trace IDs; synthesize matching W3C `traceparent` headers on responses. | `test_day5_w3c_traceparent_header_parsing_and_correlation` |

---

## 3. Security Boundary Verification

1. **Role-Based Access Control (RBAC):**
   - Non-proposer roles (e.g. `SECURITY_ANALYST`, `TENANT_ADMIN`) attempting to propose actions via `/gateway/actions/propose` are rejected by M4 policy engine with `ROLE_NOT_AUTHORIZED`.
2. **Multi-Tenant Isolation:**
   - Client requests cannot supply a tenant identifier in proposal payloads. The tenant context is extracted strictly from the validated JWT via M1 `TenantContextDep`.
   - Cross-tenant agent invocation and cross-tenant memory references fail closed with `FORBIDDEN` / `CONFUSED_DEPUTY`.
3. **Memory Trust & Integrity:**
   - Proposing actions backed by unverified, suspicious, or quarantined memories fails closed with `REFERENCED_UNTRUSTED_MEMORY` / `MEMORY_QUARANTINED`.
   - Memory cryptographic checksum mismatches fail closed (`MEMORY_CHECKSUM_MISMATCH`).
4. **Idempotency & Replay Protection:**
   - Idempotent duplicate requests return cached results without re-executing adapters.
   - Reusing an idempotency key with a mismatched payload fails closed with `409 Conflict`.
5. **Audit Telemetry & Secret Redaction:**
   - Sensitive fields (`password`, `token`, `secret`, `api_key`, `authorization`, `credit_card`) in audit payloads and execution parameters are redacted prior to persistence and logging.

---

## 4. Verification Evidence & Test Run Log

All tests passed cleanly in the local verification run:

```
backend/tests/unit/test_m2_gateway_adapters.py: 15 passed
backend/tests/unit/test_gateway.py: 29 passed
crewai_service/tests (security boundaries & provider config): 56 passed
backend/tests/unit/test_crewai_business_agents.py: 6 passed
demo/run_demo2.py: 3/3 scenarios passed (Exit code 0)
python -m crewai_service.main --demo 2: 3/3 scenarios passed (Exit code 0)
```

Repository-wide credential grep on M2 files (`crewai_service/`, `backend/app/api/gateway.py`, `backend/app/main.py`) returned zero hardcoded passwords or API keys.

---

## 5. Environment & Network Constraints

- **Local Network Isolation:** Outbound internet access is disabled in the execution environment. Git remote operations (`git push`, `gh pr create`) fail closed due to socket resolution restrictions.
- **Windows Socket Compatibility:** To prevent Windows sandbox loopback socket deadlocks during async in-process Starlette / FastAPI testing, `backend.tests.conftest` loopback patching (`_make_self_pipe` via `os.pipe`) is utilized.
- **Sandbox Git Object Write Isolation:** The sandbox environment enforces an OS-level file-system security policy (Low Mandatory Integrity Level and inherited DENY ACEs on `.git/objects`) preventing sandboxed worker subprocesses from mutating repository git objects. All code modifications, tests, and documentation are fully authored and verified in the working tree on branch `feat/m2-agent-runtime-gateway-adapters`.
