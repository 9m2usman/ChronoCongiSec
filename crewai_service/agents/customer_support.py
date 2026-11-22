"""Agent 1: Customer Support Specialist.

Module: crewai_service.agents.customer_support
Owner: ChronoCogniSec Agent Architecture Council

Responsibilities:
- Receive synthetic customer support tickets.
- Understand customer issues and classify/prioritize cases.
- Retrieve relevant trusted company knowledge.
- Synthesize policy-grounded support responses.
- Propose refund/credit action proposals to Gateway when approved.
- Escalate unresolved, suspicious, or sensitive cases.

Restrictions:
- Cannot invent company policies.
- Cannot directly modify trusted company memory.
- Cannot access another tenant's records.
- Cannot execute unauthorized external communications.
- Cannot bypass Gateway authorization.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from crewai_service.config.provider import BaseLLMAdapter, get_llm_adapter
from crewai_service.framework import Agent, Crew, Process, Task
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.escalation_tools import EscalationToolFactory
from crewai_service.tools.gateway_tools import GatewayToolFactory
from crewai_service.tools.memory_tools import TrustedMemoryToolFactory

logger = logging.getLogger("amsc.crewai.agent.support")


class SupportTicketInput(BaseModel):
    """Input payload for customer support ticket investigation."""
    ticket_id: str
    customer_id: str
    issue_description: str
    requested_action: Optional[str] = None
    claim_amount_usd: Optional[float] = None
    urgency: str = "MEDIUM"


class SupportResolutionOutput(BaseModel):
    """Structured resolution output for customer support tickets."""
    model_config = ConfigDict(extra="ignore")

    ticket_id: str = Field(description="Ticket identifier")
    classification: str = Field(description="Issue category (e.g. BILLING, HARDWARE, POLICY, TECHNICAL)")
    priority: str = Field(description="Case priority (LOW, MEDIUM, HIGH, CRITICAL)")
    resolution_text: str = Field(description="Official customer response text")
    action_taken: str = Field(description="Summary of action performed or proposed")
    gateway_proposal_id: Optional[str] = Field(default=None, description="Gateway proposal ID if action proposed")
    escalated: bool = Field(default=False, description="Whether case was escalated to human supervisor")
    escalation_reason: Optional[str] = Field(default=None, description="Reason for escalation if applicable")
    memory_references: List[str] = Field(default_factory=list, description="IDs of trusted memory records utilized")


def build_customer_support_agent(
    llm: Optional[Any] = None,
    client: Optional[ChronoCogniSecClient] = None,
    agent_id: str = "agent-crew-support-001",
    branch_id: str = "branch-ho-001",
) -> Agent:
    """Build and configure genuine CrewAI Customer Support Specialist."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or get_llm_adapter()

    # Provision restricted tools
    mem_tools = TrustedMemoryToolFactory(client=resolved_client)
    gw_tools = GatewayToolFactory(client=resolved_client)
    esc_tools = EscalationToolFactory(client=resolved_client)

    tools = [
        mem_tools.create_support_faq_tool(),
        gw_tools.create_support_refund_tool(agent_id=agent_id),
        esc_tools.create_escalation_tool(agent_id=agent_id, agent_role="Customer Support Specialist"),
    ]

    agent = Agent(
        role="Customer Support Specialist",
        goal=(
            "Investigate customer tickets, retrieve trusted knowledge, synthesize accurate policy-grounded "
            "support answers, classify/prioritize, escalate unresolved or sensitive cases, and prepare refund "
            "proposals via Gateway when an approved workflow requires one."
        ),
        backstory=(
            "You are the Senior Customer Support Specialist at ChronoCogniSec Enterprise. You provide authoritative "
            "assistance to enterprise clients grounded strictly in trusted company memory and official policies. "
            "You never invent policies or hallucinate non-existent terms. If an issue requires a financial refund "
            "or credit, you prepare an action proposal to the Security Gateway rather than executing payments directly. "
            "If a case involves suspected fraud, policy ambiguities, or abusive behavior, you immediately escalate "
            "to a human supervisor."
        ),
        llm=resolved_llm,
        tools=tools,
        verbose=True,
        allow_delegation=False,
    )
    agent.agent_id = agent_id  # type: ignore
    agent.branch_id = branch_id  # type: ignore
    return agent


def process_customer_support_ticket(
    ticket: SupportTicketInput,
    agent: Optional[Agent] = None,
    client: Optional[ChronoCogniSecClient] = None,
    workflow_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> SupportResolutionOutput:
    """Execute customer support ticket lifecycle through CrewAI Agent & Task."""
    resolved_agent = agent or build_customer_support_agent(client=client)
    tracer = get_tracer()

    task_id = f"task-supp-{uuid.uuid4().hex[:8]}"
    run_record = tracer.start_run(
        agent_id=getattr(resolved_agent, "agent_id", "agent-crew-support-001"),
        agent_role="Customer Support Specialist",
        task_id=task_id,
        workflow_id=workflow_id,
        trace_id=trace_id,
    )

    task_description = (
        f"Investigate synthetic customer support ticket '{ticket.ticket_id}'.\n"
        f"Customer ID: {ticket.customer_id}\n"
        f"Urgency: {ticket.urgency}\n"
        f"Issue Description: {ticket.issue_description}\n"
        f"Requested Action: {ticket.requested_action or 'Information and resolution'}\n"
        f"Claim Amount (USD): {ticket.claim_amount_usd or 0.0}\n\n"
        f"Instructions:\n"
        f"1. Retrieve trusted support FAQ policies using 'retrieve_trusted_support_faq'.\n"
        f"2. Check if the customer's request is eligible under official 14-day return and refund policy.\n"
        f"3. If a refund is warranted under policy and <= $300, submit a Gateway proposal via 'propose_customer_refund'.\n"
        f"4. If the ticket is ambiguous, abusive, fraudulent, or requires human intervention, call 'escalate_to_human_supervisor' with JSON: {{\"case_id\": \"{ticket.ticket_id}\", \"reason\": \"<specific justification>\", \"severity\": \"HIGH\"}}.\n"
        f"5. Prepare structured resolution output strictly conforming to the SupportResolutionOutput schema."
    )

    task = Task(
        description=task_description,
        expected_output="Valid JSON object conforming to SupportResolutionOutput schema",
        agent=resolved_agent,
        output_pydantic=SupportResolutionOutput,
        name="SupportTicketInvestigation",
    )

    crew = Crew(
        agents=[resolved_agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    try:
        crew_output = crew.kickoff()
        output = task.output

        has_escalation_call = any(t.tool_name == "escalate_to_human_supervisor" for t in run_record.tool_invocations)

        # Determine structured result
        if output and output.pydantic and isinstance(output.pydantic, SupportResolutionOutput):
            res = output.pydantic
            if run_record.gateway_proposal_ids and not res.gateway_proposal_id:
                res.gateway_proposal_id = run_record.gateway_proposal_ids[-1]
            if run_record.memory_references:
                res.memory_references = list(set(res.memory_references + run_record.memory_references))
        else:
            # Deterministic parsing from raw text
            raw = crew_output.raw
            prop_id = run_record.gateway_proposal_ids[-1] if run_record.gateway_proposal_ids else None
            res = SupportResolutionOutput(
                ticket_id=ticket.ticket_id,
                classification="BILLING" if ticket.claim_amount_usd else "GENERAL_SUPPORT",
                priority=ticket.urgency,
                resolution_text=raw[:500] if raw else "Resolved under policy",
                action_taken="PROPOSED_GATEWAY_ACTION" if prop_id else ("ESCALATED_TO_SUPERVISOR" if has_escalation_call else "RESOLVED_WITH_POLICY"),
                gateway_proposal_id=prop_id,
                escalated=has_escalation_call,
                escalation_reason="Human review requested" if has_escalation_call else None,
                memory_references=run_record.memory_references or ["mem-supp-faq-001"],
            )

        # Enforce consistency as single source of truth
        if has_escalation_call or res.escalated:
            res.escalated = True
            res.action_taken = "ESCALATED_TO_SUPERVISOR"
            if not res.escalation_reason:
                res.escalation_reason = "Customer support case escalated to human supervisor"
        else:
            res.escalated = False
            if res.action_taken == "ESCALATED_TO_SUPERVISOR":
                res.action_taken = "PROPOSED_GATEWAY_ACTION" if res.gateway_proposal_id else "RESOLVED_WITH_POLICY"

        if res.gateway_proposal_id and res.gateway_proposal_id not in run_record.gateway_proposal_ids:
            tracer.record_gateway_decision(
                run_id=run_record.run_id,
                proposal_id=res.gateway_proposal_id,
                decision="REVIEW" if res.escalated else "ALLOW",
            )
        for m_ref in res.memory_references:
            tracer.record_memory_reference(run_record.run_id, m_ref)

        tracer.finish_run(
            run_id=run_record.run_id,
            status="COMPLETED" if not res.escalated else "ESCALATED",
            output_summary=res.resolution_text[:120],
        )
        return res

    except Exception as exc:
        logger.error(f"Customer Support agent execution encountered exception: {exc}")
        tracer.finish_run(
            run_id=run_record.run_id,
            status="FAILED",
            error=str(exc),
        )
        raise
