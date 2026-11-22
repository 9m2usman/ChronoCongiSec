"""Tests for ChronoCogniSec Live System Repairs.

Validates the four core repair areas:
1. Enterprise Backend Authentication (token handling, refresh on 401, header propagation)
2. Escalation Tool Argument Handling (validation, aliases, informative errors)
3. Structured Output Parsing & Single Source of Truth Consistency
4. Provider Rate Limiting & Error Handling (request pacing, 429 backoff, fast fail on permanent errors)
"""

import json
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from crewai_service.agents.customer_support import SupportResolutionOutput
from crewai_service.agents.finance_operations import ExpenseAuditOutput
from crewai_service.agents.hr_operations import HRResolutionOutput
from crewai_service.config.provider import GeminiLLMAdapter, ProviderExecutionError
from crewai_service.framework import NativeTask
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.escalation_tools import EscalationToolFactory
from crewai_service.tools.gateway_tools import GatewayToolFactory


# ==============================================================================
# 1. Enterprise Backend Authentication Tests
# ==============================================================================

def test_client_authenticate_success():
    """Verify authenticate() posts to /auth/login and stores JWT and tenant ID."""
    client = ChronoCogniSecClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "mock-jwt-token-12345",
        "token_type": "bearer",
        "tenant_id": "tenant-a-uuid-001",
    }

    with patch.object(client, "_is_test_double_mode", return_value=False):
        with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
            success = client.authenticate(force_refresh=True)
            assert success is True
            assert client.auth_token == "mock-jwt-token-12345"
            assert client.tenant_id == "tenant-a-uuid-001"
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert "/auth/login" in call_url


def test_client_send_request_injects_auth_header():
    """Verify _send_request() injects Authorization Bearer and X-Tenant-ID headers."""
    client = ChronoCogniSecClient()
    client.auth_token = "valid-test-token"
    client.tenant_id = "tenant-a-uuid-001"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"agents": []}

    with patch.object(client, "_is_test_double_mode", return_value=False):
        with patch("httpx.Client.request", return_value=mock_resp) as mock_req:
            res = client._send_request("GET", "/agents")
            assert res is not None
            assert res.status_code == 200
            assert res.json() == {"agents": []}
            mock_req.assert_called_once()
            headers = mock_req.call_args[1].get("headers", {})
            assert headers.get("Authorization") == "Bearer valid-test-token"
            assert headers.get("X-Tenant-ID") == "tenant-a-uuid-001"


def test_client_send_request_refreshes_token_on_401():
    """Verify _send_request() automatically re-authenticates and retries on HTTP 401."""
    client = ChronoCogniSecClient()
    client.auth_token = "stale-expired-token"

    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.text = "Token expired"

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"status": "success_after_refresh"}

    auth_resp = MagicMock()
    auth_resp.status_code = 200
    auth_resp.json.return_value = {
        "access_token": "fresh-refreshed-token",
        "tenant_id": "tenant-a-uuid-001",
    }

    with patch.object(client, "_is_test_double_mode", return_value=False):
        with patch("httpx.Client.request", side_effect=[resp_401, resp_200]) as mock_req:
            with patch("httpx.Client.post", return_value=auth_resp):
                res = client._send_request("GET", "/protected-resource")
                assert res is not None
                assert res.status_code == 200
                assert res.json() == {"status": "success_after_refresh"}
                assert client.auth_token == "fresh-refreshed-token"
                assert mock_req.call_count == 2


def test_client_fail_closed_on_connection_error():
    """Verify ChronoCogniSecClient fails closed safely on network or connection errors."""
    client = ChronoCogniSecClient()
    with patch.object(client, "_is_test_double_mode", return_value=False):
        with patch("httpx.Client.request", side_effect=httpx.ConnectError("Connection refused")):
            res = client.propose_tool_action(
                agent_id="agent-001",
                tool_name="disburse_funds",
                operation="execute",
                parameters={"amount": 100},
            )
            assert res.get("decision") == "BLOCK"
            reasons = res.get("reasons", [])
            assert any("unreachable" in r.lower() or "failure" in r.lower() for r in reasons)


# ==============================================================================
# 2. Escalation Tool Argument Handling Tests
# ==============================================================================

def test_escalation_tool_requires_case_id_and_reason():
    """Verify escalation tool rejects invocation when required arguments are missing."""
    client = ChronoCogniSecClient()
    factory = EscalationToolFactory(client=client)
    esc_tool = factory.create_escalation_tool(agent_id="test-agent", agent_role="Test Specialist")

    # Missing both case_id and reason
    result = esc_tool()
    assert "ERROR: escalate_to_human_supervisor rejected: missing required arguments" in result
    assert "case_id" in result
    assert "reason" in result

    # Missing reason
    result2 = esc_tool(case_id="case-101")
    assert "ERROR: escalate_to_human_supervisor rejected: missing required arguments" in result2
    assert "reason" in result2


def test_escalation_tool_resolves_argument_aliases():
    """Verify escalation tool successfully resolves ticket_id and issue aliases."""
    client = ChronoCogniSecClient()
    factory = EscalationToolFactory(client=client)
    esc_tool = factory.create_escalation_tool(agent_id="test-agent", agent_role="Customer Support Specialist")

    result = esc_tool(ticket_id="tkt-999", issue="Suspected account takeover")
    assert "ESCALATION RECEIPT" in result
    assert "tkt-999" in result
    assert "HUMAN_REVIEW" in result


def test_escalation_tool_resolves_request_id_and_details_aliases():
    """Verify escalation tool resolves request_id and details for HR cases."""
    client = ChronoCogniSecClient()
    factory = EscalationToolFactory(client=client)
    esc_tool = factory.create_escalation_tool(agent_id="test-agent", agent_role="HR Operations Specialist")

    result = esc_tool(request_id="hr-req-888", details="Severe harassment grievance", severity="CRITICAL")
    assert "ESCALATION RECEIPT" in result
    assert "hr-req-888" in result
    assert "CRITICAL" in result


# ==============================================================================
# 3. Structured Output Parsing & Single Source of Truth Tests
# ==============================================================================

def test_structured_output_parses_json_with_fences_and_text():
    """Verify _parse_structured_output extracts balanced JSON within markdown fences and prose."""
    task = NativeTask(
        description="Audit expense",
        expected_output="Valid JSON",
        output_pydantic=ExpenseAuditOutput,
    )
    raw_response = (
        "Here is my analysis of the expense item:\n"
        "```json\n"
        "{\n"
        '  "expense_id": "exp-101",\n'
        '  "audit_status": "PROPOSAL_SUBMITTED",\n'
        '  "amount_usd": 150.00,\n'
        '  "gateway_proposal_id": "prop-101",\n'
        '  "gateway_decision": "ALLOW",\n'
        '  "dual_custody_required": false,\n'
        '  "explanation": "Valid expense under policy.",\n'
        '  "memory_references": ["mem-fin-001"]\n'
        "}\n"
        "```\n"
        "Please let me know if further review is needed."
    )
    parsed = task._parse_structured_output(raw_response, ExpenseAuditOutput)
    assert isinstance(parsed, ExpenseAuditOutput)
    assert parsed.expense_id == "exp-101"
    assert parsed.gateway_decision == "ALLOW"
    assert parsed.amount_usd == 150.00


def test_structured_output_normalizes_field_aliases():
    """Verify _parse_structured_output maps common field aliases like ticket_number or cost."""
    task = NativeTask(
        description="Process ticket",
        expected_output="Valid JSON",
        output_pydantic=SupportResolutionOutput,
    )
    raw_response = json.dumps({
        "ticket_number": "tkt-alias-123",
        "category": "TECHNICAL_SUPPORT",
        "urgency": "HIGH",
        "resolution": "Reset customer session credentials.",
        "action": "RESOLVED_WITH_POLICY",
        "references": ["mem-supp-001"],
    })
    parsed = task._parse_structured_output(raw_response, SupportResolutionOutput)
    assert isinstance(parsed, SupportResolutionOutput)
    assert parsed.ticket_id == "tkt-alias-123"
    assert parsed.classification == "TECHNICAL_SUPPORT"
    assert parsed.priority == "HIGH"
    assert parsed.resolution_text == "Reset customer session credentials."


def test_decision_and_status_consistency_enforcement():
    """Verify consistency invariant: an escalation must NEVER be displayed as an approval."""
    hr_output = HRResolutionOutput(
        request_id="hr-req-777",
        employee_id="emp-01",
        request_type="DISCIPLINARY_DISPUTE",
        status="ESCALATED_FOR_HUMAN_REVIEW",
        policy_reference="HR-POL-001",
        explanation="Escalated due to disciplinary nature.",
        escalated=True,
        escalation_reason="Consequential employment decision",
    )
    assert hr_output.escalated is True
    assert hr_output.status == "ESCALATED_FOR_HUMAN_REVIEW"
    assert "APPROVED" not in hr_output.status


# ==============================================================================
# 4. Provider Rate Limiting & Retry Tests
# ==============================================================================

def test_gemini_adapter_request_pacing():
    """Verify GeminiLLMAdapter._pace_request enforces the minimum interval between requests."""
    adapter = GeminiLLMAdapter(api_key="mock-key-for-pacing-test", model="gemini-3.5-flash-lite")
    adapter._pace_seconds = 0.2

    start = time.time()
    adapter._pace_request()
    adapter._pace_request()
    elapsed = time.time() - start
    assert elapsed >= 0.18


def test_gemini_adapter_retries_on_429_and_succeeds():
    """Verify GeminiLLMAdapter retries on HTTP 429 with backoff and returns valid result."""
    adapter = GeminiLLMAdapter(api_key="mock-key-for-retry-test", model="gemini-3.5-flash-lite")
    adapter._pace_seconds = 0.0

    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "0.01"}
    resp_429.text = "Resource exhausted: rate limit exceeded"
    resp_429.json.return_value = {
        "error": {
            "code": 429,
            "message": "Resource exhausted",
            "details": [{"retryDelay": "0.01s"}],
        }
    }

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Processed after rate limit backoff"}]
                }
            }
        ]
    }

    with patch("httpx.Client.post", side_effect=[resp_429, resp_200]) as mock_post:
        result = adapter.complete("Test prompt")
        assert result == "Processed after rate limit backoff"
        assert mock_post.call_count == 2


def test_gemini_adapter_fails_fast_on_permanent_client_errors():
    """Verify GeminiLLMAdapter does NOT retry permanent 400, 401, or 403 errors."""
    adapter = GeminiLLMAdapter(api_key="mock-key-for-fail-fast", model="gemini-3.5-flash-lite")
    adapter._pace_seconds = 0.0

    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.headers = {}
    resp_401.text = "API key not valid"
    resp_401.json.return_value = {"error": {"code": 401, "message": "API key not valid"}}

    with patch("httpx.Client.post", return_value=resp_401) as mock_post:
        with pytest.raises(ProviderExecutionError) as exc_info:
            adapter.complete("Test prompt")
        assert "HTTP 401" in str(exc_info.value)
        assert mock_post.call_count == 1


# ==============================================================================
# 5. Advanced Robustness, Unwrapping & Consistency Tests
# ==============================================================================

def test_escalation_tool_unpacks_json_string_and_dict_string():
    """Verify escalation tool unpacks when LLM passes JSON or Python dict string as first argument."""
    client = ChronoCogniSecClient()
    factory = EscalationToolFactory(client=client)
    esc_tool = factory.create_escalation_tool(agent_id="test-agent", agent_role="Customer Support Specialist")

    # Case 1: JSON serialized dict string
    raw_json_str = json.dumps({"case_id": "case-json-123", "reason": "Suspected identity theft"})
    res1 = esc_tool(case_id=raw_json_str)
    assert "ESCALATION RECEIPT" in res1
    assert "case-json-123" in res1
    assert "HUMAN_REVIEW" in res1

    # Case 2: Python single-quoted dict string
    raw_dict_str = "{'case_id': 'case-dict-456', 'reason': 'Customer account compromise', 'severity': 'HIGH'}"
    res2 = esc_tool(case_id=raw_dict_str)
    assert "ESCALATION RECEIPT" in res2
    assert "case-dict-456" in res2
    assert "HIGH" in res2


def test_propose_expense_disbursement_unpacks_json_and_sanitizes_dollar_amounts():
    """Verify gateway tool sanitizes dollar signs and unpacks JSON payload."""
    client = ChronoCogniSecClient()
    factory = GatewayToolFactory(client=client)
    expense_tool = factory.create_expense_proposal_tool(agent_id="agent-fin-001")

    # Test dollar-formatted string amount "$195.50"
    with patch.object(client, "propose_tool_action") as mock_propose:
        mock_propose.return_value = {
            "decision": "ALLOW",
            "proposal_id": "prop-test-01",
            "execution_status": "EXECUTED",
            "reasons": ["Valid expense"],
            "result": {"transaction_id": "tx-123"},
        }
        res = expense_tool(
            destination_account="acc-vendor-99",
            amount="$195.50",
            currency="USD",
            memo="Conference reimbursement",
        )
        assert "GATEWAY APPROVAL [ALLOW]" in res
        assert mock_propose.call_count == 1
        call_params = mock_propose.call_args[1]["parameters"]
        assert call_params["amount"] == 195.50

    # Test JSON string payload in first argument
    with patch.object(client, "propose_tool_action") as mock_propose2:
        mock_propose2.return_value = {
            "decision": "ALLOW",
            "proposal_id": "prop-test-02",
            "execution_status": "EXECUTED",
            "reasons": ["Valid expense"],
            "result": {"transaction_id": "tx-456"},
        }
        json_payload = json.dumps({
            "destination_account": "acc-hardware-55",
            "amount": 250.00,
            "currency": "USD",
            "memo": "Office equipment",
        })
        res2 = expense_tool(destination_account=json_payload)
        assert "GATEWAY APPROVAL [ALLOW]" in res2
        assert mock_propose2.call_count == 1
        call_params2 = mock_propose2.call_args[1]["parameters"]
        assert call_params2["destination"] == "acc-hardware-55"
        assert call_params2["amount"] == 250.00


def test_memory_tools_unpack_json_and_alias_kwargs():
    """Verify memory tools handle json/dict string arguments and alias keyword args."""
    from crewai_service.tools.memory_tools import TrustedMemoryToolFactory

    client = ChronoCogniSecClient()
    factory = TrustedMemoryToolFactory(client=client)

    # 1. Support FAQ tool
    supp_tool = factory.create_support_faq_tool()
    res1 = supp_tool(query_topic="{'topic': 'refund_policy'}")
    assert "mem-supp-faq-001" in res1

    res2 = supp_tool(query="return_timeframe")
    assert "mem-supp-faq-001" in res2

    # 2. HR Policy tool
    hr_tool = factory.create_hr_policy_tool()
    res3 = hr_tool(policy_area="{'area': 'annual_leave'}")
    assert "mem-hr-pol-001" in res3

    # 3. Finance Procedure tool
    fin_tool = factory.create_finance_procedure_tool()
    res4 = fin_tool(expense_category="{'category': 'travel_meals'}")
    assert "mem-fin-proc-001" in res4


def test_react_tool_arg_parsing_handles_single_quotes_and_formatting():
    """Verify NativeAgent._parse_tool_args parses various malformed LLM outputs."""
    from crewai_service.framework import NativeAgent

    agent = NativeAgent(role="Test Role", goal="Test Goal", backstory="Test Backstory")

    # Single-quoted dict
    parsed1 = agent._parse_tool_args("{'case_id': 'tkt-test-99', 'reason': 'unresolved issue'}")
    assert isinstance(parsed1, dict)
    assert parsed1["case_id"] == "tkt-test-99"
    assert parsed1["reason"] == "unresolved issue"

    # Markdown fence wrapped
    parsed2 = agent._parse_tool_args("```json\n{\"destination\": \"acc-1\", \"amount\": 50}\n```")
    assert isinstance(parsed2, dict)
    assert parsed2["destination"] == "acc-1"
    assert parsed2["amount"] == 50

    # Key=value fallback
    parsed3 = agent._parse_tool_args("ticket_id=tkt-555, reason=abusive language")
    assert isinstance(parsed3, dict)
    assert parsed3.get("ticket_id") == "tkt-555"


def test_structured_output_dynamic_fact_extraction():
    """Verify _parse_structured_output extracts dynamic task facts without hardcoded demo fallbacks."""
    # Description contains dynamic ticket ID
    task = NativeTask(
        description="Review customer inquiry for Ticket ID: TKT-UNIQUE-98765 from user alice@example.com.",
        expected_output="Valid JSON output",
        output_pydantic=SupportResolutionOutput,
    )
    # LLM response omits ticket_id entirely
    llm_output = (
        '{"classification": "GENERAL_INQUIRY", "priority": "MEDIUM", '
        '"status": "RESOLVED_WITH_POLICY", "resolution_text": "Provided general FAQ answers.", '
        '"policy_references": ["mem-supp-faq-001"], "escalated": false}'
    )
    parsed = task._parse_structured_output(llm_output, SupportResolutionOutput)
    assert isinstance(parsed, SupportResolutionOutput)
    # Must extract the dynamic ticket ID from task.description, NOT hardcoded 'tkt-support-101'
    assert parsed.ticket_id == "TKT-UNIQUE-98765"


def test_single_source_of_truth_status_consistency():
    """Verify single source of truth: approval is impossible for escalated disciplinary requests."""
    task = NativeTask(
        description="Process request HR-REQ-999 for employee EMP-LHR-888 regarding Disciplinary Investigation.",
        expected_output="Valid JSON output",
        output_pydantic=HRResolutionOutput,
    )
    # LLM incorrectly returns APPROVED for a disciplinary case
    raw_llm = json.dumps({
        "request_id": "HR-REQ-999",
        "employee_id": "EMP-LHR-888",
        "request_type": "DISCIPLINARY_INVESTIGATION",
        "status": "APPROVED",
        "policy_reference": "mem-hr-pol-001",
        "explanation": "Proceeding with disciplinary action.",
        "escalated": False,
        "escalation_reason": None,
    })
    parsed = task._parse_structured_output(raw_llm, HRResolutionOutput)
    assert isinstance(parsed, HRResolutionOutput)
    # Consistency enforcement must normalize status away from APPROVED
    assert parsed.status == "ESCALATED_FOR_HUMAN_REVIEW"
    assert parsed.escalated is True
    assert "Consequential" in (parsed.escalation_reason or "")


def test_gemini_adapter_retry_delay_from_error_message():
    """Verify GeminiLLMAdapter extracts numeric delay from error message strings on 429."""
    adapter = GeminiLLMAdapter(api_key="mock-key-for-regex-test", model="gemini-3.5-flash-lite")
    adapter._pace_seconds = 0.0

    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {}
    resp_429.text = "Quota exceeded for quota metric 'Generate Content API requests'. Please retry after 0.05s."
    resp_429.json.return_value = {
        "error": {
            "code": 429,
            "message": "Quota exceeded for quota metric. Please retry after 0.05s.",
        }
    }

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "Recovered from 429"}]}}]
    }

    with patch("httpx.Client.post", side_effect=[resp_429, resp_200]) as mock_post:
        with patch("time.sleep") as mock_sleep:
            res = adapter.complete("Test retry delay parsing")
            assert res == "Recovered from 429"
            assert mock_post.call_count == 2
            mock_sleep.assert_called_once()
            # Verify sleep was called with backoff delay computed from the extracted 0.05s
            sleep_arg = mock_sleep.call_args[0][0]
            assert sleep_arg >= 0.05

