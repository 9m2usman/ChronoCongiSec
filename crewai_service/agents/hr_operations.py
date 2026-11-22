"""Agent 2: HR Operations Specialist.

Module: crewai_service.agents.hr_operations
Owner: ChronoCogniSec Agent Architecture Council

Responsibilities:
- Answer questions using approved HR policies (leave, benefits, conduct).
- Process synthetic employee HR requests.
- Identify missing information and explain applicable company procedures.
- Escalate sensitive, disciplinary, or exceptional personnel cases.

Restrictions:
- Cannot make consequential employment decisions autonomously (e.g. termination, suspension).
- Cannot expose confidential employee PII or compensation records.
- Cannot access unrelated personnel records or other tenant data.
- Cannot change permissions or approve its own actions.
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
from crewai_service.tools.memory_tools import TrustedMemoryToolFactory

logger = logging.getLogger("amsc.crewai.agent.hr")


class HRRequestInput(BaseModel):
    """Input payload for HR operations request processing."""
    request_id: str
    employee_id: str
    request_type: str  # LEAVE_APPLICATION, BENEFITS_INQUIRY, ONBOARDING, DISCIPLINARY_DISPUTE
    details: str
    requested_days: Optional[int] = None


class HRResolutionOutput(BaseModel):
    """Structured resolution output for HR requests."""
    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(description="HR request identifier")
    employee_id: str = Field(description="Employee identifier")
    request_type: str = Field(description="Category of HR operation")
    status: str = Field(description="Status (ELIGIBLE, INFORMATION_REQUIRED, ESCALATED_FOR_HUMAN_REVIEW)")
    policy_reference: str = Field(description="Documented company HR policy cited")
    explanation: str = Field(description="Clear explanation of the policy and outcome")
    escalated: bool = Field(default=False, description="Whether case required human review")
    escalation_reason: Optional[str] = Field(default=None, description="Reason for escalation")
    memory_references: List[str] = Field(default_factory=list, description="IDs of trusted HR memories utilized")


def build_hr_operations_agent(
    llm: Optional[Any] = None,
    client: Optional[ChronoCogniSecClient] = None,
    agent_id: str = "agent-crew-hr-002",
    branch_id: str = "branch-isb-004",
) -> Agent:
    """Build and configure genuine CrewAI HR Operations Specialist."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or get_llm_adapter()

    mem_tools = TrustedMemoryToolFactory(client=resolved_client)
    esc_tools = EscalationToolFactory(client=resolved_client)

    tools = [
        mem_tools.create_hr_policy_tool(),
        esc_tools.create_escalation_tool(agent_id=agent_id, agent_role="HR Operations Specialist"),
    ]

    agent = Agent(
        role="HR Operations Specialist",
        goal=(
            "Answer employee questions using approved company procedures, process synthetic HR requests, "
            "identify missing information, and escalate sensitive personnel or disciplinary matters to human supervisors."
        ),
        backstory=(
            "You are the HR Operations Specialist for ChronoCogniSec Enterprise. You guide staff through official "
            "employment handbooks, leave entitlements, and onboarding procedures grounded strictly in trusted company memory. "
            "You never make consequential employment decisions autonomously (such as termination, demotion, or salary changes) "
            "and strictly protect employee privacy by escalating complex or sensitive disputes to human HR directors."
        ),
        llm=resolved_llm,
        tools=tools,
        verbose=True,
        allow_delegation=False,
    )
    agent.agent_id = agent_id  # type: ignore
    agent.branch_id = branch_id  # type: ignore
    return agent


def process_hr_request(
    request_data: HRRequestInput,
    agent: Optional[Agent] = None,
    client: Optional[ChronoCogniSecClient] = None,
    workflow_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> HRResolutionOutput:
    """Execute HR request processing through CrewAI Agent & Task."""
    resolved_agent = agent or build_hr_operations_agent(client=client)
    tracer = get_tracer()

    task_id = f"task-hr-{uuid.uuid4().hex[:8]}"
    run_record = tracer.start_run(
        agent_id=getattr(resolved_agent, "agent_id", "agent-crew-hr-002"),
        agent_role="HR Operations Specialist",
        task_id=task_id,
        workflow_id=workflow_id,
        trace_id=trace_id,
    )

    task_description = (
        f"Process synthetic HR request '{request_data.request_id}'.\n"
        f"Employee ID: {request_data.employee_id}\n"
        f"Request Type: {request_data.request_type}\n"
        f"Requested Days: {request_data.requested_days or 'N/A'}\n"
        f"Details: {request_data.details}\n\n"
        f"Instructions:\n"
        f"1. Retrieve official HR policies using 'retrieve_hr_policy_knowledge'.\n"
        f"2. Check request against documented annual leave (22 days) and medical leave rules.\n"
        f"3. If the request involves termination, disciplinary action, or compensation modifications, "
        f"strictly ESCALATE using 'escalate_to_human_supervisor' as autonomous action is forbidden.\n"
        f"4. Provide structured HRResolutionOutput."
    )

    task = Task(
        description=task_description,
        expected_output="Valid JSON object conforming to HRResolutionOutput schema",
        agent=resolved_agent,
        output_pydantic=HRResolutionOutput,
        name="HRRequestEvaluation",
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

        if output and output.pydantic and isinstance(output.pydantic, HRResolutionOutput):
            res = output.pydantic
        else:
            raw = crew_output.raw
            is_disciplinary = "disciplin" in request_data.request_type.lower() or "terminat" in request_data.details.lower()
            is_escalated = is_disciplinary or "escalat" in raw.lower()
            res = HRResolutionOutput(
                request_id=request_data.request_id,
                employee_id=request_data.employee_id,
                request_type=request_data.request_type,
                status="ESCALATED_FOR_HUMAN_REVIEW" if is_escalated else "ELIGIBLE",
                policy_reference="AMSC-HR-POL-001 (Annual & Medical Leave Guidelines)",
                explanation=raw[:500],
                escalated=is_escalated,
                escalation_reason="Consequential employment decision requires human HR director review" if is_escalated else None,
                memory_references=["mem-hr-pol-001"],
            )

        for m_ref in res.memory_references:
            tracer.record_memory_reference(run_record.run_id, m_ref)

        tracer.finish_run(
            run_id=run_record.run_id,
            status="COMPLETED" if not res.escalated else "ESCALATED",
            output_summary=res.explanation[:120],
        )
        return res

    except Exception as exc:
        logger.error(f"HR Operations agent execution encountered exception: {exc}")
        tracer.finish_run(
            run_id=run_record.run_id,
            status="FAILED",
            error=str(exc),
        )
        raise
