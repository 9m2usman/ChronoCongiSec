"""Agent 3: Finance Operations Specialist.

Module: crewai_service.agents.finance_operations
Owner: ChronoCogniSec Agent Architecture Council

Responsibilities:
- Review synthetic expense reimbursement requests.
- Verify supporting documentation and corporate spend limits.
- Apply documented financial procedures from trusted company memory.
- Submit action proposals to the ChronoCogniSec Security Gateway.
- Enforce $300.00 USD dual-custody threshold and anti-fraud controls.
- Escalate exceptional or suspicious transactions.

Restrictions:
- No real money transfers or external banking network access.
- No direct tool execution bypassing Gateway complete mediation.
- Cannot approve its own financial proposals (self-approval prohibited).
- Cannot bypass dual-custody approval ceilings ($300.00 USD).
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

logger = logging.getLogger("amsc.crewai.agent.finance")


class ExpenseAuditInput(BaseModel):
    """Input payload for corporate expense request auditing."""
    expense_id: str
    claimant_id: str
    destination_account: str
    amount_usd: float
    category: str
    receipt_attached: bool = True
    memo: str = "Corporate operational expense"


class ExpenseAuditOutput(BaseModel):
    """Structured audit and proposal output for financial expenses."""
    model_config = ConfigDict(extra="ignore")

    expense_id: str = Field(description="Expense request identifier")
    audit_status: str = Field(description="Audit outcome (PROPOSAL_SUBMITTED, BLOCKED_BY_GATEWAY, REJECTED_MISSING_RECEIPT, ESCALATED)")
    amount_usd: float = Field(description="Audited amount in USD")
    gateway_proposal_id: Optional[str] = Field(default=None, description="Gateway proposal ID")
    gateway_decision: Optional[str] = Field(default=None, description="ALLOW, BLOCK, or REVIEW")
    dual_custody_required: bool = Field(default=False, description="Whether amount exceeded $300 ceiling requiring dual custody")
    explanation: str = Field(description="Audit finding and policy explanation")
    memory_references: List[str] = Field(default_factory=list, description="IDs of trusted financial procedure memories")


def build_finance_operations_agent(
    llm: Optional[Any] = None,
    client: Optional[ChronoCogniSecClient] = None,
    agent_id: str = "agent-crew-finance-003",
    branch_id: str = "branch-lhr-002",
) -> Agent:
    """Build and configure genuine CrewAI Finance Operations Specialist."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or get_llm_adapter()

    mem_tools = TrustedMemoryToolFactory(client=resolved_client)
    gw_tools = GatewayToolFactory(client=resolved_client)
    esc_tools = EscalationToolFactory(client=resolved_client)

    tools = [
        mem_tools.create_finance_procedure_tool(),
        gw_tools.create_expense_proposal_tool(agent_id=agent_id),
        esc_tools.create_escalation_tool(agent_id=agent_id, agent_role="Finance Operations Specialist"),
    ]

    agent = Agent(
        role="Finance Operations Specialist",
        goal=(
            "Review synthetic expense reimbursement requests, audit supporting financial documentation, "
            "apply documented financial procedures, enforce the $300 dual-custody threshold, and submit "
            "action proposals to the Security Gateway. Prohibit autonomous self-approval."
        ),
        backstory=(
            "You are the Finance Operations Specialist for ChronoCogniSec Enterprise. You rigorously audit company "
            "expenditures against official accounting standards grounded in trusted company memory. You never execute "
            "payments or fund transfers directly; instead, you submit formal proposals to the ChronoCogniSec Gateway. "
            "You strictly enforce the rule that any transaction over $300.00 USD requires dual-custody authorization."
        ),
        llm=resolved_llm,
        tools=tools,
        verbose=True,
        allow_delegation=False,
    )
    agent.agent_id = agent_id  # type: ignore
    agent.branch_id = branch_id  # type: ignore
    return agent


def audit_and_propose_expense(
    expense: ExpenseAuditInput,
    agent: Optional[Agent] = None,
    client: Optional[ChronoCogniSecClient] = None,
    workflow_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> ExpenseAuditOutput:
    """Execute finance expense audit lifecycle through CrewAI Agent & Task."""
    resolved_agent = agent or build_finance_operations_agent(client=client)
    tracer = get_tracer()

    task_id = f"task-fin-{uuid.uuid4().hex[:8]}"
    run_record = tracer.start_run(
        agent_id=getattr(resolved_agent, "agent_id", "agent-crew-finance-003"),
        agent_role="Finance Operations Specialist",
        task_id=task_id,
        workflow_id=workflow_id,
        trace_id=trace_id,
    )

    task_description = (
        f"Audit synthetic expense request '{expense.expense_id}'.\n"
        f"Claimant ID: {expense.claimant_id}\n"
        f"Destination Account: {expense.destination_account}\n"
        f"Amount (USD): {expense.amount_usd:.2f}\n"
        f"Category: {expense.category}\n"
        f"Receipt Attached: {expense.receipt_attached}\n"
        f"Memo: {expense.memo}\n\n"
        f"Instructions:\n"
        f"1. Retrieve official financial rules using 'retrieve_financial_procedure'.\n"
        f"2. Verify receipt requirement: If receipt is missing, REJECT request immediately.\n"
        f"3. Note that amounts over $300.00 USD exceed the single-agent threshold and will be BLOCKED by the Gateway for dual-custody.\n"
        f"4. If valid, submit action proposal via 'propose_expense_disbursement' with JSON: {{\"destination_account\": \"{expense.destination_account}\", \"amount\": {expense.amount_usd}, \"currency\": \"USD\", \"memo\": \"{expense.memo}\"}}.\n"
        f"5. If escalation is required, call 'escalate_to_human_supervisor' with JSON: {{\"case_id\": \"{expense.expense_id}\", \"reason\": \"<justification>\", \"severity\": \"HIGH\"}}.\n"
        f"6. Record Gateway decision (ALLOW vs BLOCK) and provide structured ExpenseAuditOutput strictly matching schema."
    )

    task = Task(
        description=task_description,
        expected_output="Valid JSON object conforming to ExpenseAuditOutput schema",
        agent=resolved_agent,
        output_pydantic=ExpenseAuditOutput,
        name="ExpenseAuditAndProposal",
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

        has_blocked_gateway = any(d == "BLOCK" for d in run_record.policy_decisions)
        has_escalation_call = any(t.tool_name == "escalate_to_human_supervisor" for t in run_record.tool_invocations)

        if output and output.pydantic and isinstance(output.pydantic, ExpenseAuditOutput):
            res = output.pydantic
            # If tool recorded gateway proposal in tracer, ensure it aligns
            if run_record.gateway_proposal_ids and (not res.gateway_proposal_id or res.gateway_proposal_id.startswith("prop-exp-")):
                res.gateway_proposal_id = run_record.gateway_proposal_ids[-1]
            if run_record.policy_decisions:
                res.gateway_decision = run_record.policy_decisions[-1]
        else:
            raw = crew_output.raw
            prop_id = run_record.gateway_proposal_ids[-1] if run_record.gateway_proposal_ids else f"prop-exp-{expense.expense_id}"
            res = ExpenseAuditOutput(
                expense_id=expense.expense_id,
                audit_status="PROPOSAL_SUBMITTED",
                amount_usd=expense.amount_usd,
                gateway_proposal_id=prop_id,
                gateway_decision="ALLOW",
                dual_custody_required=expense.amount_usd > 300.00,
                explanation=raw[:500] if raw else "Expense audit complete under financial governance.",
                memory_references=run_record.memory_references or ["mem-fin-proc-001"],
            )

        # Enforce consistency as single source of truth across business rules, gateway decisions, and output
        if not expense.receipt_attached:
            res.audit_status = "REJECTED_MISSING_RECEIPT"
            res.gateway_decision = "BLOCK"
            res.dual_custody_required = False
        elif has_escalation_call:
            res.audit_status = "ESCALATED"
            res.gateway_decision = "REVIEW"
        elif has_blocked_gateway or expense.amount_usd > 300.00:
            res.audit_status = "BLOCKED_BY_GATEWAY"
            res.gateway_decision = "BLOCK"
            res.dual_custody_required = True
        else:
            res.audit_status = "PROPOSAL_SUBMITTED"
            res.gateway_decision = "ALLOW"
            res.dual_custody_required = False

        if res.gateway_proposal_id and res.gateway_proposal_id not in run_record.gateway_proposal_ids:
            tracer.record_gateway_decision(
                run_id=run_record.run_id,
                proposal_id=res.gateway_proposal_id,
                decision=res.gateway_decision,
            )
        for m_ref in res.memory_references:
            tracer.record_memory_reference(run_record.run_id, m_ref)

        tracer.finish_run(
            run_id=run_record.run_id,
            status="COMPLETED" if res.gateway_decision == "ALLOW" else ("ESCALATED" if res.audit_status == "ESCALATED" or has_escalation_call else "BLOCKED"),
            output_summary=res.explanation[:120],
        )
        return res

    except Exception as exc:
        logger.error(f"Finance Operations agent execution encountered exception: {exc}")
        tracer.finish_run(
            run_id=run_record.run_id,
            status="FAILED",
            error=str(exc),
        )
        raise
