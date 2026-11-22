"""Tests for Agent 2: HR Operations Specialist.

Module: crewai_service.tests.test_hr_operations
Owner: ChronoCogniSec QA Council
"""

import pytest

from crewai_service.agents.hr_operations import (
    HRRequestInput,
    HRResolutionOutput,
    build_hr_operations_agent,
    process_hr_request,
)
from crewai_service.telemetry.tracer import get_tracer


def test_hr_answers_leave_question_using_approved_policy(test_double_llm, mock_amsc_client):
    """Scenario 2: HR answers a question using an approved HR policy."""
    agent = build_hr_operations_agent(llm=test_double_llm, client=mock_amsc_client)
    hr_req = HRRequestInput(
        request_id="hr-101",
        employee_id="emp-042",
        request_type="LEAVE_APPLICATION",
        details="Applying for 5 days of annual leave next month.",
        requested_days=5,
    )

    result = process_hr_request(request_data=hr_req, agent=agent, client=mock_amsc_client)

    assert isinstance(result, HRResolutionOutput)
    assert result.request_id == "hr-101"
    assert result.status == "ELIGIBLE"
    assert "Annual & Medical Leave" in result.policy_reference or "HR-POL-001" in result.policy_reference
    assert result.escalated is False

    # Check Dual Trace
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 1
    assert runs[-1].agent_role == "HR Operations Specialist"
    assert runs[-1].status == "COMPLETED"


def test_hr_escalates_consequential_disciplinary_case(test_double_llm, mock_amsc_client):
    """Verify HR specialist strictly escalates termination / disciplinary cases to human directors."""
    agent = build_hr_operations_agent(llm=test_double_llm, client=mock_amsc_client)
    disciplinary_req = HRRequestInput(
        request_id="hr-disc-999",
        employee_id="emp-trouble-12",
        request_type="DISCIPLINARY_DISPUTE",
        details="Manager requesting immediate contract termination without standard severance.",
    )

    result = process_hr_request(request_data=disciplinary_req, agent=agent, client=mock_amsc_client)
    assert result.escalated is True
    assert result.status == "ESCALATED_FOR_HUMAN_REVIEW"
    assert result.escalation_reason is not None
