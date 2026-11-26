"""Phase 3 CrewAI company tools: fail-closed and honest-reporting guarantees.

Real execution through the gateway and PostgreSQL is verified in
``backend/tests/database/test_phase3_connected_agent_execution.py``. These tests
run in the CrewAI job (no backend) and prove the tools never fabricate results.
"""

import inspect
import json

import pytest

from crewai_service.agents.branch_operations import build_branch_operations_agent
from crewai_service.agents.workflow_coordinator import build_workflow_coordinator_agent
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.company_tools import (
    BRANCH_OPERATIONS_COMPANY_OPERATIONS,
    COORDINATOR_COMPANY_OPERATIONS,
    CompanyWorkspaceToolFactory,
    summarize_receipt,
)

SCOPE_ARGUMENTS = {"tenant_id", "branch_id", "user_id", "role", "agent_id", "acting_user_id", "scope"}


class _RecordingClient(ChronoCogniSecClient):
    def __init__(self):
        super().__init__()
        self.proposals = []

    def propose_tool_action(self, **kwargs):  # pragma: no cover - must never be reached
        self.proposals.append(kwargs)
        return super().propose_tool_action(**kwargs)


def test_tools_refuse_simulated_gateway_in_test_double_mode():
    client = _RecordingClient()  # TEST_DOUBLE settings, no in-process app
    tools = {t.name: t for t in CompanyWorkspaceToolFactory(client, "agent-crew-branch-004")
             .create_tools(BRANCH_OPERATIONS_COMPANY_OPERATIONS)}
    out = json.loads(tools["company_create_file"].run(workspace_id="ws-1", name="a.txt", content="x"))
    assert out["completed"] is False and out["decision"] == "BLOCK"
    assert out["error_code"] == "GATEWAY_UNAVAILABLE"
    assert client.proposals == []


@pytest.mark.parametrize("operations", [BRANCH_OPERATIONS_COMPANY_OPERATIONS, COORDINATOR_COMPANY_OPERATIONS])
def test_no_tool_accepts_authorization_scope_arguments(operations):
    for t in CompanyWorkspaceToolFactory(_RecordingClient(), "agent-x").create_tools(operations):
        params = set(inspect.signature(t.func).parameters)
        assert not params & SCOPE_ARGUMENTS, (t.name, params)


def test_unknown_operation_is_rejected():
    with pytest.raises(ValueError):
        CompanyWorkspaceToolFactory(_RecordingClient(), "agent-x").create_tools(["drop_database"])


def test_agent_id_is_required():
    with pytest.raises(ValueError):
        CompanyWorkspaceToolFactory(_RecordingClient(), "")


def test_existing_agents_offer_their_company_tools():
    branch = build_branch_operations_agent(client=_RecordingClient())
    coord = build_workflow_coordinator_agent(client=_RecordingClient())
    branch_names = {t.name for t in branch.tools}
    coord_names = {t.name for t in coord.tools}
    assert {f"company_{op}" for op in BRANCH_OPERATIONS_COMPANY_OPERATIONS} <= branch_names
    assert {f"company_{op}" for op in COORDINATOR_COMPANY_OPERATIONS} <= coord_names
    assert "company_create_file" not in coord_names and "company_transfer_file" not in coord_names


@pytest.mark.parametrize("receipt,completed", [
    ({"decision": "ALLOW", "execution_status": "EXECUTED", "result": {"result": {"id": "f1"}}}, True),
    ({"decision": "ALLOW", "execution_status": "FAILED", "result": {"error": "x", "error_code": "Y"}}, False),
    ({"decision": "ALLOW", "execution_status": "UNKNOWN", "result": {"error": "timeout"}}, False),
    ({"decision": "REQUIRES_APPROVAL", "execution_status": "PENDING_APPROVAL"}, False),
    ({"decision": "BLOCK", "execution_status": "NOT_EXECUTED", "reasons": ["no"]}, False),
    ({}, False),
])
def test_only_allowed_and_executed_is_reported_complete(receipt, completed):
    summary = summarize_receipt(receipt)
    assert summary["completed"] is completed
    if not completed:
        assert "result" not in summary
