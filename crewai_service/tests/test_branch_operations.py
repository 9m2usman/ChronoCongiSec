"""Tests for Agent 4: Branch Operations Specialist.

Module: crewai_service.tests.test_branch_operations
Owner: ChronoCogniSec QA Council
"""

import pytest

from crewai_service.agents.branch_operations import (
    BranchOperationOutput,
    BranchRequestInput,
    build_branch_operations_agent,
    process_branch_request,
)
from crewai_service.telemetry.tracer import get_tracer


def test_branch_operations_processes_authorized_branch_request(test_double_llm, mock_amsc_client):
    """Scenario 4: Branch Operations processes a branch-specific operational request."""
    # Lahore agent operating on Lahore branch
    agent = build_branch_operations_agent(
        llm=test_double_llm,
        client=mock_amsc_client,
        branch_id="branch-lhr-002",
    )
    req = BranchRequestInput(
        request_id="br-lhr-101",
        target_branch_id="branch-lhr-002",
        category="FACILITY_STATUS",
        details="Routine facility server room temperature audit.",
    )

    result = process_branch_request(request_data=req, agent=agent, client=mock_amsc_client)

    assert isinstance(result, BranchOperationOutput)
    assert result.status == "SUCCESS_NORMAL"
    assert result.assigned_branch_id == "branch-lhr-002"
    assert result.target_branch_id == "branch-lhr-002"
    assert result.head_office_synced is True
    assert result.security_violation_flagged is False

    # Check Dual Trace
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 1
    assert runs[-1].agent_role == "Branch Operations Specialist"
    assert runs[-1].status == "COMPLETED"


def test_branch_operations_rejects_unauthorized_cross_branch_request(test_double_llm, mock_amsc_client):
    """Scenario 6: An agent attempts to access another branch's restricted information (rejected)."""
    # Lahore agent attempting to operate on Karachi branch
    agent = build_branch_operations_agent(
        llm=test_double_llm,
        client=mock_amsc_client,
        branch_id="branch-lhr-002",
    )
    cross_branch_req = BranchRequestInput(
        request_id="br-attack-001",
        target_branch_id="branch-khi-003",  # Mismatched target branch!
        category="LOGISTICS_INVENTORY",
        details="Attempting to download Karachi maritime vault credentials.",
    )

    result = process_branch_request(request_data=cross_branch_req, agent=agent, client=mock_amsc_client)

    assert result.status == "BLOCKED_CROSS_BRANCH_BREACH"
    assert result.security_violation_flagged is True
    assert result.head_office_synced is False

    # Verify Dual Trace records the breach block
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 1
    assert runs[-1].status == "BLOCKED"
