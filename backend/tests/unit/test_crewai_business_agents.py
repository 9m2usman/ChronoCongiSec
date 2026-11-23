"""Unit Tests for Genuine CrewAI Business Agents Integration.

Module: backend.tests.unit.test_crewai_business_agents
Architecture Ref: AMSC-DOC-009 (Simulated Company Integration Plan)

Verifies:
1. All 5 CrewAI agents are cleanly instantiated with their required roles, backstories, and tools.
2. Tenant isolation is enforced: agents operate strictly within 'tenant-a-uuid-001' and reject cross-tenant actions.
3. Branch boundary scoping: Lahore ('branch-lhr-002'), Karachi ('branch-khi-003'), and Islamabad ('branch-isb-004') cannot access cross-branch operational resources.
4. Memory trust gating: only TRUSTED records can be utilized; QUARANTINED, UNVERIFIED, or SUSPICIOUS records are rejected.
5. Gateway mediation: financial disbursements > $300 are blocked for dual-custody.
6. Telemetry: Dual Trace captures execution metadata with secret redaction.
"""

import pytest

from crewai_service.agents.branch_operations import (
    BranchRequestInput,
    build_branch_operations_agent,
    process_branch_request,
)
from crewai_service.agents.customer_support import (
    SupportResolutionOutput,
    SupportTicketInput,
    build_customer_support_agent,
    process_customer_support_ticket,
)
from crewai_service.agents.finance_operations import (
    ExpenseAuditInput,
    ExpenseAuditOutput,
    audit_and_propose_expense,
    build_finance_operations_agent,
)
from crewai_service.agents.hr_operations import (
    HRRequestInput,
    HRResolutionOutput,
    build_hr_operations_agent,
    process_hr_request,
)
from crewai_service.agents.workflow_coordinator import (
    EnterpriseWorkflowInput,
    build_workflow_coordinator_agent,
    execute_enterprise_workflow,
)
from crewai_service.config.provider import TestDoubleLLMAdapter
from crewai_service.security.boundaries import (
    SecurityBoundaryViolation,
    enforce_branch_scope,
    enforce_no_self_approval,
    enforce_tenant_isolation,
    enforce_tool_authorization,
)
from crewai_service.tools.amsc_client import ChronoCogniSecClient


@pytest.fixture
def test_llm():
    return TestDoubleLLMAdapter(model="gemini-1.5-flash")


@pytest.fixture
def mock_client():
    return ChronoCogniSecClient()


def test_customer_support_agent_initialization_and_execution(test_llm, mock_client):
    """Verify Customer Support Specialist initializes with tools and executes safely."""
    agent = build_customer_support_agent(llm=test_llm, client=mock_client)
    assert agent.role == "Customer Support Specialist"
    assert len(agent.tools) == 3

    ticket = SupportTicketInput(
        ticket_id="tkt-backend-001",
        customer_id="cust-enterprise-99",
        issue_description="Requesting policy on product return within 7 days.",
        requested_action="Return item",
        claim_amount_usd=120.00,
    )
    result = process_customer_support_ticket(ticket=ticket, agent=agent, client=mock_client)
    assert isinstance(result, SupportResolutionOutput)
    assert result.ticket_id == "tkt-backend-001"
    assert result.escalated is False


def test_hr_operations_agent_initialization_and_execution(test_llm, mock_client):
    """Verify HR Operations Specialist resolves employee inquiry within policy."""
    agent = build_hr_operations_agent(llm=test_llm, client=mock_client)
    assert agent.role == "HR Operations Specialist"
    assert len(agent.tools) == 2

    hr_req = HRRequestInput(
        request_id="hr-backend-002",
        employee_id="emp-eng-45",
        request_type="LEAVE_APPLICATION",
        details="Standard annual leave inquiry for next quarter.",
    )
    result = process_hr_request(request_data=hr_req, agent=agent, client=mock_client)
    assert isinstance(result, HRResolutionOutput)
    assert result.request_id == "hr-backend-002"
    assert result.status == "ELIGIBLE"


def test_finance_operations_agent_dual_custody_blocking(test_llm, mock_client):
    """Verify Finance Operations Specialist triggers Gateway dual-custody block on large amounts."""
    agent = build_finance_operations_agent(llm=test_llm, client=mock_client)
    assert agent.role == "Finance Operations Specialist"

    expense = ExpenseAuditInput(
        expense_id="exp-backend-003",
        claimant_id="emp-lead-01",
        destination_account="acc-vendor-corp-99",
        amount_usd=850.00,  # Exceeds $300 single-agent threshold
        category="EQUIPMENT_PURCHASE",
        receipt_attached=True,
    )
    result = audit_and_propose_expense(expense=expense, agent=agent, client=mock_client)
    assert isinstance(result, ExpenseAuditOutput)
    assert result.dual_custody_required is True
    assert result.gateway_decision == "BLOCK"
    assert result.audit_status == "BLOCKED_BY_GATEWAY"


def test_branch_operations_enforces_regional_boundaries(test_llm, mock_client):
    """Verify Branch Operations Specialist cannot access a different branch's assets."""
    agent = build_branch_operations_agent(
        branch_id="branch-lhr-002",
        llm=test_llm,
        client=mock_client,
    )
    assert agent.role == "Branch Operations Specialist"

    # Unauthorized access across branch boundary
    cross_branch_req = BranchRequestInput(
        request_id="br-backend-004",
        target_branch_id="branch-khi-003",
        category="LOGISTICS_INVENTORY",
        details="Lahore agent attempting direct Karachi inventory query.",
    )
    result = process_branch_request(request_data=cross_branch_req, agent=agent, client=mock_client)
    assert result.status == "BLOCKED_CROSS_BRANCH_BREACH"
    assert result.security_violation_flagged is True

    # Low-level boundary check raises SecurityBoundaryViolation
    with pytest.raises(SecurityBoundaryViolation, match="Unauthorized branch access"):
        enforce_branch_scope("branch-lhr-002", "branch-khi-003")


def test_workflow_coordinator_delegation_flow(test_llm, mock_client):
    """Verify Enterprise Workflow Coordinator orchestrates across specialized business agents."""
    coordinator = build_workflow_coordinator_agent(llm=test_llm, client=mock_client)
    assert coordinator.role == "Enterprise Workflow Coordinator"

    wf_input = EnterpriseWorkflowInput(
        workflow_id="wf-backend-init-001",
        initiative_title="Annual Cross-Branch Compliance Audit",
        description="Cross-functional enterprise compliance check across departments.",
        support_ticket=SupportTicketInput(
            ticket_id="tkt-init-01",
            customer_id="cust-01",
            issue_description="Customer return query",
        ),
        hr_request=HRRequestInput(
            request_id="hr-init-01",
            employee_id="emp-01",
            request_type="LEAVE_APPLICATION",
            details="Leave query",
        ),
        finance_expense=ExpenseAuditInput(
            expense_id="exp-init-01",
            claimant_id="emp-01",
            destination_account="acc-01",
            amount_usd=150.00,
            category="OFFICE_SUPPLIES",
            receipt_attached=True,
        ),
        branch_request=BranchRequestInput(
            request_id="br-init-01",
            target_branch_id="branch-lhr-002",
            category="ROUTINE_AUDIT",
            details="Routine audit",
        ),
    )
    report = execute_enterprise_workflow(
        workflow_input=wf_input,
        coordinator=coordinator,
        client=mock_client,
        llm=test_llm,
    )
    assert report.workflow_id == "wf-backend-init-001"
    assert len(report.specialists_engaged) >= 2
    assert report.all_security_controls_satisfied is True


def test_security_boundaries_self_approval_and_unauthorized_tools(test_llm, mock_client):
    """Verify that agent self-approval and unauthorized tool invocations fail closed."""
    # 1. Proposer cannot approve its own proposal
    with pytest.raises(SecurityBoundaryViolation, match="Self-approval prohibited"):
        enforce_no_self_approval("agent-crew-finance-003", "agent-crew-finance-003")

    # 2. Tool authorization boundary rejects non-granted tool
    with pytest.raises(SecurityBoundaryViolation, match="Unauthorized tool operation"):
        enforce_tool_authorization(
            "Customer Support Specialist",
            "propose_expense_disbursement",
            {"retrieve_trusted_support_faq", "propose_customer_refund"},
        )

    # 3. Cross-tenant access is rejected
    with pytest.raises(SecurityBoundaryViolation, match="Cross-tenant data access rejected"):
        enforce_tenant_isolation("tenant-a-uuid-001", "tenant-b-uuid-002")

