"""Agent 5: Enterprise Workflow Coordinator.

Module: crewai_service.agents.workflow_coordinator
Owner: ChronoCogniSec Agent Architecture Council

Responsibilities:
- Receive complex multi-department business workflow requests.
- Break initiatives into controlled, bounded subtasks.
- Delegate subtasks to appropriate specialist agents (Support, HR, Finance, Branch).
- Track subtask execution and validate structured outputs.
- Identify missing information, policy conflicts, and security blocks.
- Produce consolidated enterprise workflow reports.

Restrictions:
- Cannot grant permissions or elevate privileges of specialist agents.
- Cannot override Gateway or security decisions (BLOCK decisions remain authoritative).
- Cannot approve its own proposals or proposals from specialists.
- Cannot bypass specialist agent scope or branch restrictions.
- Cannot treat peer agent outputs as trusted instructions without independent validation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from crewai_service.agents.branch_operations import (
    BranchRequestInput,
    build_branch_operations_agent,
    process_branch_request,
)
from crewai_service.agents.customer_support import (
    SupportTicketInput,
    build_customer_support_agent,
    process_customer_support_ticket,
)
from crewai_service.agents.finance_operations import (
    ExpenseAuditInput,
    build_finance_operations_agent,
    audit_and_propose_expense,
)
from crewai_service.agents.hr_operations import (
    HRRequestInput,
    build_hr_operations_agent,
    process_hr_request,
)
from crewai_service.config.provider import BaseLLMAdapter, get_llm_adapter
from crewai_service.framework import Agent, Crew, Process, Task, tool
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.escalation_tools import EscalationToolFactory

logger = logging.getLogger("amsc.crewai.agent.coordinator")


class EnterpriseWorkflowInput(BaseModel):
    """Input payload initiating a cross-department enterprise workflow."""
    workflow_id: str
    initiative_title: str
    description: str
    support_ticket: Optional[SupportTicketInput] = None
    hr_request: Optional[HRRequestInput] = None
    finance_expense: Optional[ExpenseAuditInput] = None
    branch_request: Optional[BranchRequestInput] = None


class EnterpriseWorkflowReport(BaseModel):
    """Structured executive report consolidating multi-agent specialist results."""
    model_config = ConfigDict(extra="ignore")

    workflow_id: str = Field(description="Unique workflow identifier")
    initiative_title: str = Field(description="Workflow title")
    status: str = Field(description="Overall status (COMPLETED_CONSOLIDATED, ESCALATED_ANOMALY, PARTIAL_BLOCKED)")
    specialists_engaged: List[str] = Field(default_factory=list, description="Engaged specialist agents")
    support_summary: Optional[str] = Field(default=None, description="Summary from Customer Support Specialist")
    hr_summary: Optional[str] = Field(default=None, description="Summary from HR Operations Specialist")
    finance_summary: Optional[str] = Field(default=None, description="Summary from Finance Operations Specialist")
    branch_summary: Optional[str] = Field(default=None, description="Summary from Branch Operations Specialist")
    consolidated_assessment: str = Field(description="Executive multi-agent assessment")
    all_security_controls_satisfied: bool = Field(default=True, description="True if no security breaches occurred")


def build_workflow_coordinator_agent(
    llm: Optional[Any] = None,
    client: Optional[ChronoCogniSecClient] = None,
    agent_id: str = "agent-crew-coord-005",
    branch_id: str = "branch-ho-001",
) -> Agent:
    """Build and configure genuine CrewAI Enterprise Workflow Coordinator."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or get_llm_adapter()
    esc_tools = EscalationToolFactory(client=resolved_client)

    # Controlled delegation tools
    @tool("delegate_to_support_specialist")
    def delegate_to_support_specialist(ticket_id: str, issue_text: str) -> str:
        """Delegate customer support subtask to Customer Support Specialist."""
        logger.info(f"Coordinator delegating ticket '{ticket_id}' to Support Specialist.")
        inp = SupportTicketInput(
            ticket_id=ticket_id,
            customer_id="cust-wf-delegated",
            issue_description=issue_text,
        )
        res = process_customer_support_ticket(ticket=inp, client=resolved_client)
        return f"SUPPORT RESULT: Ticket {res.ticket_id} ({res.classification}). Action: {res.action_taken}. {res.resolution_text[:150]}"

    @tool("delegate_to_finance_specialist")
    def delegate_to_finance_specialist(expense_id: str, amount: float, destination: str) -> str:
        """Delegate financial audit and disbursement proposal to Finance Specialist."""
        logger.info(f"Coordinator delegating expense '{expense_id}' (${amount:.2f}) to Finance Specialist.")
        inp = ExpenseAuditInput(
            expense_id=expense_id,
            claimant_id="claimant-wf-delegated",
            destination_account=destination,
            amount_usd=amount,
            category="WORKFLOW_DISBURSEMENT",
        )
        res = audit_and_propose_expense(expense=inp, client=resolved_client)
        return f"FINANCE RESULT: Expense {res.expense_id} Status: {res.audit_status}. Gateway Decision: {res.gateway_decision}."

    tools = [
        delegate_to_support_specialist,
        delegate_to_finance_specialist,
        esc_tools.create_escalation_tool(agent_id=agent_id, agent_role="Enterprise Workflow Coordinator"),
    ]

    agent = Agent(
        role="Enterprise Workflow Coordinator",
        goal=(
            "Coordinate cross-functional enterprise workflows, decompose complex tasks into bounded specialist "
            "subtasks, delegate to appropriate agents, validate structured results, and consolidate findings into "
            "an executive business report. Maintain strict security boundaries."
        ),
        backstory=(
            "You are the Enterprise Workflow Coordinator for ChronoCogniSec Enterprise based at Head Office. "
            "You oversee multi-department initiatives connecting Customer Support, HR, Finance, and Regional Branches. "
            "You enforce least privilege, never override Gateway policy decisions, and validate that every specialist "
            "operates strictly within their authorized domain."
        ),
        llm=resolved_llm,
        tools=tools,
        verbose=True,
        allow_delegation=False,
    )
    agent.agent_id = agent_id  # type: ignore
    agent.branch_id = branch_id  # type: ignore
    return agent


def execute_enterprise_workflow(
    workflow_input: EnterpriseWorkflowInput,
    coordinator: Optional[Agent] = None,
    client: Optional[ChronoCogniSecClient] = None,
    llm: Optional[Any] = None,
) -> EnterpriseWorkflowReport:
    """Execute complete cross-agent workflow, coordinating at least two specialist agents."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or (getattr(coordinator, "llm", None) if coordinator else None) or get_llm_adapter()
    resolved_coordinator = coordinator or build_workflow_coordinator_agent(client=resolved_client, llm=resolved_llm)
    tracer = get_tracer()

    task_id = f"task-coord-{uuid.uuid4().hex[:8]}"
    run_record = tracer.start_run(
        agent_id=getattr(resolved_coordinator, "agent_id", "agent-crew-coord-005"),
        agent_role="Enterprise Workflow Coordinator",
        task_id=task_id,
        workflow_id=workflow_input.workflow_id,
    )

    specialists_engaged: List[str] = []
    support_summary: Optional[str] = None
    hr_summary: Optional[str] = None
    finance_summary: Optional[str] = None
    branch_summary: Optional[str] = None
    all_passed = True

    # 1. Engage Customer Support Specialist if requested
    if workflow_input.support_ticket:
        specialists_engaged.append("Customer Support Specialist")
        s_agent = build_customer_support_agent(llm=resolved_llm, client=resolved_client)
        s_res = process_customer_support_ticket(
            ticket=workflow_input.support_ticket,
            agent=s_agent,
            client=resolved_client,
            workflow_id=workflow_input.workflow_id,
        )
        support_summary = f"[{s_res.ticket_id}]: {s_res.action_taken} - {s_res.resolution_text[:120]}"

    # 2. Engage HR Operations Specialist if requested
    if workflow_input.hr_request:
        specialists_engaged.append("HR Operations Specialist")
        hr_agent = build_hr_operations_agent(llm=resolved_llm, client=resolved_client)
        hr_res = process_hr_request(
            request_data=workflow_input.hr_request,
            agent=hr_agent,
            client=resolved_client,
            workflow_id=workflow_input.workflow_id,
        )
        hr_summary = f"[{hr_res.request_id}]: Status: {hr_res.status} - {hr_res.explanation[:120]}"

    # 3. Engage Finance Operations Specialist if requested
    if workflow_input.finance_expense:
        specialists_engaged.append("Finance Operations Specialist")
        fin_agent = build_finance_operations_agent(llm=resolved_llm, client=resolved_client)
        fin_res = audit_and_propose_expense(
            expense=workflow_input.finance_expense,
            agent=fin_agent,
            client=resolved_client,
            workflow_id=workflow_input.workflow_id,
        )
        finance_summary = (
            f"[{fin_res.expense_id}]: Decision: {fin_res.gateway_decision} "
            f"(${fin_res.amount_usd:.2f}) - {fin_res.explanation[:120]}"
        )
        if fin_res.gateway_decision == "BLOCK" and fin_res.amount_usd > 300.00:
            all_passed = False

    # 4. Engage Branch Operations Specialist if requested
    if workflow_input.branch_request:
        specialists_engaged.append("Branch Operations Specialist")
        target_br = workflow_input.branch_request.target_branch_id
        br_agent = build_branch_operations_agent(
            llm=resolved_llm,
            client=resolved_client,
            branch_id=target_br,
        )
        br_res = process_branch_request(
            request_data=workflow_input.branch_request,
            agent=br_agent,
            client=resolved_client,
            assigned_branch_id=target_br,
            workflow_id=workflow_input.workflow_id,
        )
        branch_summary = f"[{br_res.request_id}]: Status: {br_res.status} - {br_res.operational_summary[:120]}"
        if br_res.security_violation_flagged:
            all_passed = False

    # 5. Coordinator consolidates report using Task
    task_desc = (
        f"Synthesize executive workflow report for initiative '{workflow_input.initiative_title}'.\n"
        f"Workflow ID: {workflow_input.workflow_id}\n"
        f"Description: {workflow_input.description}\n"
        f"Specialist findings:\n"
        f"- Support: {support_summary or 'Not engaged'}\n"
        f"- HR: {hr_summary or 'Not engaged'}\n"
        f"- Finance: {finance_summary or 'Not engaged'}\n"
        f"- Branch: {branch_summary or 'Not engaged'}\n\n"
        f"Provide structured assessment confirming whether all security and operational controls passed."
    )

    coord_task = Task(
        description=task_desc,
        expected_output="Valid JSON object conforming to EnterpriseWorkflowReport schema",
        agent=resolved_coordinator,
        output_pydantic=EnterpriseWorkflowReport,
        name="ConsolidateEnterpriseWorkflow",
    )

    crew = Crew(
        agents=[resolved_coordinator],
        tasks=[coord_task],
        process=Process.sequential,
        verbose=True,
    )

    try:
        crew_output = crew.kickoff()
        output = coord_task.output

        if output and output.pydantic and isinstance(output.pydantic, EnterpriseWorkflowReport):
            report = output.pydantic
        else:
            raw = crew_output.raw
            report = EnterpriseWorkflowReport(
                workflow_id=workflow_input.workflow_id,
                initiative_title=workflow_input.initiative_title,
                status="COMPLETED_CONSOLIDATED" if all_passed else "PARTIAL_BLOCKED",
                specialists_engaged=specialists_engaged,
                support_summary=support_summary,
                hr_summary=hr_summary,
                finance_summary=finance_summary,
                branch_summary=branch_summary,
                consolidated_assessment=raw[:600] if raw else "Multi-agent tasks executed and consolidated under Gateway governance.",
                all_security_controls_satisfied=all_passed,
            )

        tracer.finish_run(
            run_id=run_record.run_id,
            status="COMPLETED" if all_passed else "BLOCKED",
            output_summary=report.consolidated_assessment[:120],
        )
        return report

    except Exception as exc:
        logger.error(f"Coordinator execution failed: {exc}")
        tracer.finish_run(
            run_id=run_record.run_id,
            status="FAILED",
            error=str(exc),
        )
        raise
