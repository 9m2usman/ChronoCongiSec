"""M2 adapter, contract, trace correlation, and credential-containment regression tests."""

from __future__ import annotations

import asyncio
import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient

from backend.app.api.gateway import (
    ActionProposalRequest,
    SandboxTransferAdapter,
    ToolAdapterRegistry,
    ToolExecutionResult,
)
from crewai_service.config.settings import CrewAISettings
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.gateway_tools import GatewayToolFactory
from demo.run_demo2 import build_demo_environment, run_demo2, DEMO_AGENT_ID, DEMO_TENANT_ID


@pytest.mark.asyncio
async def test_sandbox_transfer_is_synthetic_and_idempotent() -> None:
    adapter = SandboxTransferAdapter()
    proposal_context = {
        "tenant_id": "tenant-a-uuid-001",
        "agent_id": "agent-crew-finance-003",
        "idempotency_key": "idem-transfer-001",
        "trace_id": "trace-001",
    }
    parameters = {"destination_account": "ACC-LEGIT-123", "amount": "10.50", "currency": "USD"}

    first = await adapter.execute("transfer_funds", parameters, proposal_context)
    retry = await adapter.execute("transfer_funds", parameters, proposal_context)

    assert first.status == "SUCCESS"
    assert first.result_payload["status"] == "SETTLED_IN_SANDBOX"
    assert first.result_payload["transaction_id"] == retry.result_payload["transaction_id"]
    assert "credential" not in str(first.result_payload).lower()


@pytest.mark.asyncio
async def test_sandbox_transfer_accepts_parameter_aliases() -> None:
    """Verify Day 2 adapter supports canonical and alias parameter formats."""
    adapter = SandboxTransferAdapter()
    proposal_context = {
        "tenant_id": "tenant-a-uuid-001",
        "agent_id": "agent-crew-finance-003",
        "idempotency_key": "idem-alias-001",
        "trace_id": "trace-alias-001",
    }
    # Uses destination instead of destination_account, and amount_usd instead of amount
    parameters = {"destination": "ACC-LEGIT-456", "amount_usd": 75.25, "currency": "USD"}
    result = await adapter.execute("transfer_funds", parameters, proposal_context)

    assert result.status == "SUCCESS"
    assert result.result_payload["destination_account"] == "ACC-LEGIT-456"
    assert result.result_payload["amount"] == 75.25
    assert result.result_payload["status"] == "SETTLED_IN_SANDBOX"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "parameters",
    [
        {"destination_account": "ACC-LEGIT-123", "amount": 0, "currency": "USD"},
        {"destination_account": "ACC-LEGIT-123", "amount": "NaN", "currency": "USD"},
        {"destination_account": "ACC-ATTACKER-999", "amount": 1, "currency": "USD"},
    ],
)
async def test_sandbox_transfer_rejects_invalid_or_forbidden_requests(parameters: dict[str, object]) -> None:
    context = {
        "tenant_id": "tenant-a-uuid-001",
        "agent_id": "agent-crew-finance-003",
        "idempotency_key": "idem-reject-001",
        "trace_id": "trace-reject-001",
    }
    result = await SandboxTransferAdapter().execute("transfer_funds", parameters, context)
    assert result.status == "FAILED"
    assert result.status_code in {400, 403}


@pytest.mark.asyncio
async def test_sandbox_transfer_direct_invocation_without_authorized_context_is_prevented() -> None:
    """Verify Day 2: Direct adapter invocation without server-side authorized context fails closed (403)."""
    adapter = SandboxTransferAdapter()
    parameters = {"destination_account": "ACC-LEGIT-123", "amount": 50.00, "currency": "USD"}

    # Missing context completely
    res1 = await adapter.execute("transfer_funds", parameters, {})
    assert res1.status == "FAILED"
    assert res1.status_code == 403
    assert "Missing authorized execution context" in res1.result_payload["error"]

    # Partial / spoofed context missing required keys
    res2 = await adapter.execute("transfer_funds", parameters, {"agent_id": "agent-1"})
    assert res2.status == "FAILED"
    assert res2.status_code == 403


@pytest.mark.asyncio
async def test_sandbox_transfer_amount_ceiling_and_invalid_operations() -> None:
    """Verify Day 2: Adapter enforces upper ceiling ($1,000,000) and unsupported operations."""
    adapter = SandboxTransferAdapter()
    context = {
        "tenant_id": "tenant-a-uuid-001",
        "agent_id": "agent-crew-finance-003",
        "idempotency_key": "idem-ceil-001",
        "trace_id": "trace-ceil-001",
    }

    # Amount exceeding MAX_AMOUNT
    res_huge = await adapter.execute(
        "transfer_funds",
        {"destination_account": "ACC-LEGIT-123", "amount": 2000000.0, "currency": "USD"},
        context,
    )
    assert res_huge.status == "FAILED"
    assert res_huge.status_code == 400
    assert "up to 1000000.00" in res_huge.result_payload["error"]

    # Invalid currency format
    res_curr = await adapter.execute(
        "transfer_funds",
        {"destination_account": "ACC-LEGIT-123", "amount": 50.0, "currency": "usd"},
        context,
    )
    assert res_curr.status == "FAILED"
    assert res_curr.status_code == 400

    # Unsupported operation
    res_op = await adapter.execute(
        "unsupported_wire",
        {"destination_account": "ACC-LEGIT-123", "amount": 50.0},
        context,
    )
    assert res_op.status == "FAILED"
    assert res_op.status_code == 400
    assert "Unsupported operation" in res_op.result_payload["error"]


def test_day1_tool_execution_result_validation() -> None:
    """Verify Day 1: ToolExecutionResult enforces status, status code, duration, and payload types."""
    # Valid
    valid = ToolExecutionResult(status="SUCCESS", status_code=200, result_payload={"ok": True}, duration_ms=12)
    assert valid.status == "SUCCESS"

    # Invalid status
    with pytest.raises(ValueError, match="status must be one of"):
        ToolExecutionResult(status="NOT_A_STATUS", status_code=200, result_payload={}, duration_ms=0)

    # Invalid status code
    with pytest.raises(ValueError, match="valid HTTP status code"):
        ToolExecutionResult(status="FAILED", status_code=999, result_payload={}, duration_ms=0)

    # Negative duration
    with pytest.raises(ValueError, match="duration_ms cannot be negative"):
        ToolExecutionResult(status="FAILED", status_code=400, result_payload={}, duration_ms=-1)

    # Non-dict payload
    with pytest.raises(ValueError, match="result_payload must be a dict"):
        ToolExecutionResult(status="FAILED", status_code=400, result_payload="not-a-dict", duration_ms=0)  # type: ignore[arg-type]


def test_crewai_client_fails_closed_without_backend_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    import crewai_service.tools.amsc_client as client_module

    settings = CrewAISettings(
        EXECUTION_MODE="live",
        CHRONOCONGISEC_AUTH_TOKEN=None,
        CHRONOCONGISEC_AUTH_PASSWORD=None,
    )
    monkeypatch.setattr(client_module, "get_crewai_settings", lambda: settings)
    client = ChronoCogniSecClient()

    assert client.auth_token is None
    assert client.authenticate() is False


def test_day1_action_proposal_contract_strict_validation() -> None:
    """Verify Day 1 ActionProposalRequest Pydantic v2 validation invariants."""
    valid_payload = {
        "action_id": "act-contract-001",
        "agent_id": "agent-contract-002",
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-TEST-1", "amount": 100.0},
        "memory_refs": ["mem-test-001"],
        "idempotency_key": "idem-contract-001",
        "trace_id": "trace-contract-001",
    }
    req = ActionProposalRequest.model_validate(valid_payload)
    assert req.action_id == "act-contract-001"

    # Extra fields forbidden
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ActionProposalRequest.model_validate({**valid_payload, "extra_tenant_hack": "tenant-x"})

    # Empty or whitespace-only identifier rejected
    with pytest.raises(ValidationError, match="empty or whitespace"):
        ActionProposalRequest.model_validate({**valid_payload, "action_id": "   "})

    # Control characters in identifier rejected
    with pytest.raises(ValidationError, match="control characters"):
        ActionProposalRequest.model_validate({**valid_payload, "action_id": "act-bad\nline"})

    # Invalid characters in identifier rejected
    with pytest.raises(ValidationError, match="may only contain letters"):
        ActionProposalRequest.model_validate({**valid_payload, "action_id": "act-bad@symbol!"})

    # Invalid memory reference format
    with pytest.raises(ValidationError, match="Invalid memory reference format"):
        ActionProposalRequest.model_validate({**valid_payload, "memory_refs": ["invalid ref with spaces!"]})

    # Exceeding maximum memory references (> 50)
    with pytest.raises(ValidationError, match="too_long"):
        ActionProposalRequest.model_validate({**valid_payload, "memory_refs": [f"mem-ref-{i}" for i in range(51)]})

    # NaN / Infinity in parameters rejected
    with pytest.raises(ValidationError, match="finite"):
        ActionProposalRequest.model_validate({**valid_payload, "parameters": {"amount": float("nan")}})

    # Excessive nesting depth (> 5) rejected
    nested = {"a": {"b": {"c": {"d": {"e": {"f": "too_deep"}}}}}}
    with pytest.raises(ValidationError, match="depth"):
        ActionProposalRequest.model_validate({**valid_payload, "parameters": nested})

    # Oversized string parameter (> 8192 chars) rejected
    with pytest.raises(ValidationError, match="8192"):
        ActionProposalRequest.model_validate({**valid_payload, "parameters": {"memo": "x" * 8193}})


def test_day5_trace_propagation_from_active_run_to_proposal() -> None:
    """Verify Day 5: Agent workflow trace_id propagates directly to tool proposals without regenerating new IDs."""
    tracer = get_tracer()
    tracer.clear()

    active_trace_id = "trace-w3c-wf-4bf92f3577b34da6a3ce929d0e0e4736"
    run_record = tracer.start_run(
        agent_id="agent-crew-finance-003",
        agent_role="Finance Operations Specialist",
        task_id="task-trace-test",
        workflow_id="wf-trace-test",
        trace_id=active_trace_id,
    )

    captured_proposal = {}

    class MockClient:
        def propose_tool_action(self, **kwargs: object) -> dict[str, object]:
            captured_proposal.update(kwargs)
            return {
                "decision": "ALLOW",
                "proposal_id": "prop-mock-001",
                "execution_status": "EXECUTED",
                "result": {"transaction_id": "tx-mock-001"},
            }

    factory = GatewayToolFactory(client=MockClient())
    tool_func = factory.create_expense_proposal_tool(agent_id="agent-crew-finance-003")
    tool_func(destination_account="ACC-TEST-99", amount=120.0, memory_refs=["mem-ref-1"])

    # Assert proposal inherited the active run's trace_id
    assert captured_proposal.get("trace_id") == active_trace_id
    assert captured_proposal.get("agent_id") == "agent-crew-finance-003"
    assert captured_proposal.get("parameters", {}).get("destination_account") == "ACC-TEST-99"


def test_day6_demo2_complete_mediation_all_scenarios_pass() -> None:
    """Verify Day 6: Demo 2 runs all three scenarios (Authorized, Ceiling Violation, Poisoned Memory) and succeeds."""
    exit_code = run_demo2(live=False)
    assert exit_code == 0


def test_day3_tool_permissions_assignment_enforcement() -> None:
    """Verify Day 3: Unassigned tools and unauthorized operations fail closed before adapter dispatch."""
    app, agent_repo, memory_repo, gateway_repo, auth_token, trusted_mem_id, _ = build_demo_environment()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    # 1. Unassigned tool -> BLOCK with TOOL_NOT_ASSIGNED
    unassigned_res = client.post(
        "/api/v1/gateway/actions/propose",
        headers=headers,
        json={
            "action_id": "act-unassigned-001",
            "agent_id": DEMO_AGENT_ID,
            "tool_name": "unassigned_external_api",
            "operation": "execute_query",
            "parameters": {"query": "SELECT 1"},
            "memory_refs": [trusted_mem_id],
            "idempotency_key": "idem-unassigned-001",
            "trace_id": "trace-unassigned-001",
        },
    )
    assert unassigned_res.status_code == 200
    data_unassigned = unassigned_res.json()
    assert data_unassigned["decision"] == "BLOCK"
    assert data_unassigned["execution_status"] == "NOT_EXECUTED"
    assert "TOOL_NOT_ASSIGNED" in data_unassigned["reason_codes"]
    assert data_unassigned["result"] is None

    # 2. Unauthorized operation on assigned tool -> BLOCK with OPERATION_DENIED
    wrong_op_res = client.post(
        "/api/v1/gateway/actions/propose",
        headers=headers,
        json={
            "action_id": "act-wrong-op-001",
            "agent_id": DEMO_AGENT_ID,
            "tool_name": "sandbox_transfer",
            "operation": "unauthorized_wire",
            "parameters": {"destination_account": "ACC-SUPPLIER-401", "amount": 50.0},
            "memory_refs": [trusted_mem_id],
            "idempotency_key": "idem-wrong-op-001",
            "trace_id": "trace-wrong-op-001",
        },
    )
    assert wrong_op_res.status_code == 200
    data_wrong_op = wrong_op_res.json()
    assert data_wrong_op["decision"] == "BLOCK"
    assert data_wrong_op["execution_status"] == "NOT_EXECUTED"
    assert "OPERATION_DENIED" in data_wrong_op["reason_codes"]
    assert data_wrong_op["result"] is None

    # 3. Operational limit exceeded -> BLOCK with CEILING_EXCEEDED (grant max_amount is 500)
    limit_res = client.post(
        "/api/v1/gateway/actions/propose",
        headers=headers,
        json={
            "action_id": "act-limit-001",
            "agent_id": DEMO_AGENT_ID,
            "tool_name": "sandbox_transfer",
            "operation": "transfer_funds",
            "parameters": {"destination_account": "ACC-SUPPLIER-401", "amount": 750.0},
            "memory_refs": [trusted_mem_id],
            "idempotency_key": "idem-limit-001",
            "trace_id": "trace-limit-001",
        },
    )
    assert limit_res.status_code == 200
    data_limit = limit_res.json()
    assert data_limit["decision"] == "BLOCK"
    assert data_limit["execution_status"] == "NOT_EXECUTED"
    assert "CEILING_EXCEEDED" in data_limit["reason_codes"]
    assert data_limit["result"] is None


def test_day4_adapter_execution_timeout_and_failure() -> None:
    """Verify Day 4: Adapter timeouts return UNKNOWN (504) and exceptions return FAILED (500)."""
    app, agent_repo, memory_repo, gateway_repo, auth_token, trusted_mem_id, _ = build_demo_environment()

    # Create slow adapter that exceeds timeout
    class SlowTimeoutAdapter:
        tool_name = "sandbox_transfer"
        allowed_operations = ("transfer_funds", "get_balance")
        timeout = 0.05

        async def execute(self, operation: str, parameters: dict, context: dict) -> ToolExecutionResult:
            await asyncio.sleep(0.5)
            return ToolExecutionResult("SUCCESS", 200, {"status": "LATE"}, 500)

    # Create throwing adapter
    class FailingAdapter:
        tool_name = "sandbox_transfer"
        allowed_operations = ("transfer_funds", "get_balance")
        timeout = 5.0

        async def execute(self, operation: str, parameters: dict, context: dict) -> ToolExecutionResult:
            raise RuntimeError("Underlying banking provider network failure")

    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    # Test Timeout Adapter
    tool_reg_timeout = ToolAdapterRegistry()
    tool_reg_timeout.register("sandbox_transfer", SlowTimeoutAdapter())
    app.state.tool_registry = tool_reg_timeout
    # Clear cached enforcement so tool_registry changes take effect
    app.state._gateway_enforcement = None

    client = TestClient(app)
    timeout_res = client.post(
        "/api/v1/gateway/actions/propose",
        headers=headers,
        json={
            "action_id": "act-timeout-test-01",
            "agent_id": DEMO_AGENT_ID,
            "tool_name": "sandbox_transfer",
            "operation": "transfer_funds",
            "parameters": {"destination_account": "ACC-SUPPLIER-401", "amount": 50.0},
            "memory_refs": [trusted_mem_id],
            "idempotency_key": "idem-timeout-test-01",
            "trace_id": "trace-timeout-test-01",
        },
    )
    assert timeout_res.status_code == 200
    data_to = timeout_res.json()
    assert data_to["decision"] == "ALLOW"
    assert data_to["execution_status"] == "UNKNOWN"
    assert "timed out" in data_to["result"]["error"].lower()

    # Test Exception / Failing Adapter
    tool_reg_failing = ToolAdapterRegistry()
    tool_reg_failing.register("sandbox_transfer", FailingAdapter())
    app.state.tool_registry = tool_reg_failing
    app.state._gateway_enforcement = None

    fail_res = client.post(
        "/api/v1/gateway/actions/propose",
        headers=headers,
        json={
            "action_id": "act-fail-test-01",
            "agent_id": DEMO_AGENT_ID,
            "tool_name": "sandbox_transfer",
            "operation": "transfer_funds",
            "parameters": {"destination_account": "ACC-SUPPLIER-401", "amount": 50.0},
            "memory_refs": [trusted_mem_id],
            "idempotency_key": "idem-fail-test-01",
            "trace_id": "trace-fail-test-01",
        },
    )
    assert fail_res.status_code == 200
    data_fail = fail_res.json()
    assert data_fail["decision"] == "ALLOW"
    assert data_fail["execution_status"] == "FAILED"
    assert "exception" in data_fail["result"]["error"].lower()


def test_day5_w3c_traceparent_header_parsing_and_correlation() -> None:
    """Verify Day 5: W3C traceparent headers are strictly parsed, validated, and echoed or synthesized on response."""
    app, _, _, _, _, _, _ = build_demo_environment()
    client = TestClient(app)

    # 1. Valid incoming traceparent is accepted and echoed consistently
    valid_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    res1 = client.get("/health", headers={"traceparent": valid_tp})
    assert res1.status_code == 200
    assert res1.headers.get("X-Trace-ID") == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert res1.headers.get("traceparent") == valid_tp

    # 2. Invalid all-zeros trace_id is ignored per W3C specification, falling back to X-Trace-ID
    invalid_zeros_tp = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
    res2 = client.get("/health", headers={"traceparent": invalid_zeros_tp, "X-Trace-ID": "trace-valid-fallback"})
    assert res2.status_code == 200
    resp_tid = res2.headers.get("X-Trace-ID")
    assert resp_tid == "trace-valid-fallback"
    resp_tp = res2.headers.get("traceparent")
    assert resp_tp is not None
    assert not resp_tp.startswith("00-00000000000000000000000000000000")

    # 3. Caller provides X-Trace-ID without traceparent -> response synthesizes matching W3C traceparent
    res3 = client.get("/health", headers={"X-Trace-ID": "4bf92f3577b34da6a3ce929d0e0e4736"})
    assert res3.status_code == 200
    tid3 = res3.headers.get("X-Trace-ID")
    assert tid3 == "4bf92f3577b34da6a3ce929d0e0e4736"
    tp3 = res3.headers.get("traceparent")
    assert tp3 is not None
    assert tp3.startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")


