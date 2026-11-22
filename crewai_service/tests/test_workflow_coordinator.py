"""Tests for Agent 5: Enterprise Workflow Coordinator.

Module: crewai_service.tests.test_workflow_coordinator
Owner: ChronoCogniSec QA Council
"""

import pytest

from crewai_service.agents.branch_operations import BranchRequestInput
from crewai_service.agents.customer_support import SupportTicketInput
from crewai_service.agents.finance_operations import ExpenseAuditInput
from crewai_service.agents.hr_operations import HRRequestInput
from crewai_service.agents.workflow_coordinator import (
    EnterpriseWorkflowInput,
    EnterpriseWorkflowReport,
    build_workflow_coordinator_agent,
    execute_enterprise_workflow,
)
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.workflows.flows import EnterpriseLifecycleFlow


def test_workflow_coordinator_delegates_to_specialists_and_consolidates(test_double_llm, mock_amsc_client):
    """Scenario 5: Workflow Coordinator delegates work to at least two specialist agents and consolidates their outputs."""
    wf_input = EnterpriseWorkflowInput(
        workflow_id="wf-multi-001",
        initiative_title="Annual Multi-Branch Audit Initiative",
        description="Coordinating customer support return SLA and regional branch facility inspection.",
        support_ticket=SupportTicketInput(
            ticket_id="tkt-wf-1",
            customer_id="cust-wf-1",
            issue_description="Customer inquiry on product return eligibility.",
            urgency="LOW",
        ),
        branch_request=BranchRequestInput(
            request_id="br-wf-1",
            target_branch_id="branch-lhr-002",
            category="FACILITY_STATUS",
            details="Annual server room hardware check.",
        ),
    )

    report = execute_enterprise_workflow(
        workflow_input=wf_input,
        client=mock_amsc_client,
    )

    assert isinstance(report, EnterpriseWorkflowReport)
    assert report.workflow_id == "wf-multi-001"
    assert len(report.specialists_engaged) >= 2
    assert "Customer Support Specialist" in report.specialists_engaged
    assert "Branch Operations Specialist" in report.specialists_engaged
    assert report.support_summary is not None
    assert report.branch_summary is not None
    assert report.all_security_controls_satisfied is True

    # Check Dual Trace correlation
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 3  # Support, Branch, and Coordinator runs
    agent_roles = {r.agent_role for r in runs}
    assert "Customer Support Specialist" in agent_roles
    assert "Branch Operations Specialist" in agent_roles
    assert "Enterprise Workflow Coordinator" in agent_roles


def test_enterprise_lifecycle_flow_kickoff_executes_successfully(test_double_llm, mock_amsc_client):
    """Verify CrewAI Flow controller (@start, @listen) completes end-to-end flow."""
    wf_input = EnterpriseWorkflowInput(
        workflow_id="wf-flow-777",
        initiative_title="Regional Staff Expansion & Logistics Deployment",
        description="Initiative approving HR staff onboarding and regional branch facility readiness.",
        hr_request=HRRequestInput(
            request_id="hr-flow-01",
            employee_id="emp-new-88",
            request_type="ONBOARDING",
            details="New developer joining Lahore engineering cluster.",
        ),
        branch_request=BranchRequestInput(
            request_id="br-flow-02",
            target_branch_id="branch-lhr-002",
            category="FACILITY_STATUS",
            details="Workstation allocation check.",
        ),
    )

    flow = EnterpriseLifecycleFlow(workflow_input=wf_input, client=mock_amsc_client)
    report = flow.kickoff()

    assert isinstance(report, EnterpriseWorkflowReport)
    assert report.workflow_id == "wf-flow-777"
    assert report.status == "COMPLETED_CONSOLIDATED"
    assert report.hr_summary is not None
    assert report.branch_summary is not None
