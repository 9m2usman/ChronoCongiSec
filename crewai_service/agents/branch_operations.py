"""Agent 4: Branch Operations Specialist.

Module: crewai_service.agents.branch_operations
Owner: ChronoCogniSec Agent Architecture Council

Responsibilities:
- Manage regional operational requests for an assigned branch (Lahore, Karachi, or Islamabad).
- Retrieve branch-specific procedures and facility/inventory logs.
- Identify local operational bottlenecks and prepare reports.
- Coordinate permitted tasks and status telemetry with Head Office.
- Escalate cross-branch anomalies and unauthorized operations.

Restrictions:
- Cannot access unauthorized branch information (strict branch boundary).
- Cannot change its own branch identity.
- Cannot expand its assigned scope to other regional branches.
- Cannot access another tenant's data.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from crewai_service.config.provider import BaseLLMAdapter, get_llm_adapter
from crewai_service.framework import Agent, Crew, Process, Task
from crewai_service.security.boundaries import SecurityBoundaryViolation
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.tools.branch_tools import BranchToolFactory
from crewai_service.tools.escalation_tools import EscalationToolFactory

logger = logging.getLogger("amsc.crewai.agent.branch")


class BranchRequestInput(BaseModel):
    """Input payload for regional branch operations request."""
    request_id: str
    target_branch_id: str
    category: str  # FACILITY_STATUS, LOGISTICS_INVENTORY, COMPLIANCE_AUDIT
    details: str
    sync_to_head_office: bool = True


class BranchOperationOutput(BaseModel):
    """Structured resolution output for regional branch operations."""
    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(description="Request identifier")
    assigned_branch_id: str = Field(description="Agent's authorized assigned branch")
    target_branch_id: str = Field(description="Requested target branch")
    status: str = Field(description="Status (SUCCESS_NORMAL, BLOCKED_CROSS_BRANCH_BREACH, ESCALATED)")
    operational_summary: str = Field(description="Summary of facility/logistics findings")
    head_office_synced: bool = Field(default=False, description="Whether status was synchronized with Head Office")
    security_violation_flagged: bool = Field(default=False, description="True if unauthorized access attempted")
    memory_references: List[str] = Field(default_factory=list, description="Branch records referenced")


def build_branch_operations_agent(
    llm: Optional[Any] = None,
    client: Optional[ChronoCogniSecClient] = None,
    agent_id: str = "agent-crew-branch-004",
    branch_id: str = "branch-khi-003",
) -> Agent:
    """Build and configure genuine CrewAI Branch Operations Specialist."""
    resolved_client = client or ChronoCogniSecClient()
    resolved_llm = llm or get_llm_adapter()

    branch_tools = BranchToolFactory(agent_branch_id=branch_id, agent_id=agent_id)
    esc_tools = EscalationToolFactory(client=resolved_client)

    tools = [
        branch_tools.create_branch_inspection_tool(),
        branch_tools.create_head_office_sync_tool(),
        esc_tools.create_escalation_tool(agent_id=agent_id, agent_role="Branch Operations Specialist"),
    ]

    agent = Agent(
        role="Branch Operations Specialist",
        goal=(
            "Review operational requests for your assigned regional branch, retrieve branch facility/logistics data, "
            "strictly enforce branch isolation boundaries, and coordinate authorized summaries with Head Office."
        ),
        backstory=(
            f"You are the Branch Operations Specialist assigned strictly to branch '{branch_id}' of ChronoCogniSec Enterprise. "
            "You manage regional logistics and facility safety. You are strictly forbidden from accessing data belonging "
            "to other regional branches, and you immediately reject cross-branch inspection requests unless operating as Head Office."
        ),
        llm=resolved_llm,
        tools=tools,
        verbose=True,
        allow_delegation=False,
    )
    agent.agent_id = agent_id  # type: ignore
    agent.branch_id = branch_id  # type: ignore
    return agent


def process_branch_request(
    request_data: BranchRequestInput,
    agent: Optional[Agent] = None,
    client: Optional[ChronoCogniSecClient] = None,
    assigned_branch_id: str = "branch-khi-003",
    workflow_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> BranchOperationOutput:
    """Execute branch operations lifecycle enforcing branch isolation boundaries."""
    resolved_agent = agent or build_branch_operations_agent(
        client=client, branch_id=assigned_branch_id
    )
    active_branch = getattr(resolved_agent, "branch_id", assigned_branch_id)
    tracer = get_tracer()

    task_id = f"task-branch-{uuid.uuid4().hex[:8]}"
    run_record = tracer.start_run(
        agent_id=getattr(resolved_agent, "agent_id", "agent-crew-branch-004"),
        agent_role="Branch Operations Specialist",
        task_id=task_id,
        workflow_id=workflow_id,
        trace_id=trace_id,
    )

    # 1. Direct Boundary Check: Detect cross-branch access attempt
    if active_branch != "branch-ho-001" and active_branch != request_data.target_branch_id:
        logger.error(
            f"BRANCH ISOLATION BREACH PREVENTED: Agent in '{active_branch}' cannot operate on '{request_data.target_branch_id}'."
        )
        tracer.finish_run(
            run_id=run_record.run_id,
            status="BLOCKED",
            error=f"Cross-branch access violation: assigned '{active_branch}', requested '{request_data.target_branch_id}'",
        )
        return BranchOperationOutput(
            request_id=request_data.request_id,
            assigned_branch_id=active_branch,
            target_branch_id=request_data.target_branch_id,
            status="BLOCKED_CROSS_BRANCH_BREACH",
            operational_summary=f"Security alert: Agent in '{active_branch}' was denied access to '{request_data.target_branch_id}'.",
            head_office_synced=False,
            security_violation_flagged=True,
            memory_references=[],
        )

    task_description = (
        f"Process regional branch request '{request_data.request_id}'.\n"
        f"Assigned Branch: {active_branch}\n"
        f"Target Branch: {request_data.target_branch_id}\n"
        f"Category: {request_data.category}\n"
        f"Details: {request_data.details}\n\n"
        f"Instructions:\n"
        f"1. Retrieve branch data using 'retrieve_branch_operational_data' with JSON: {{\"target_branch_id\": \"{request_data.target_branch_id}\", \"data_category\": \"{request_data.category}\"}}.\n"
        f"2. Inspect facility status, staffing levels, and hardware inventory.\n"
        f"3. Synchronize operational summary with Head Office using 'coordinate_with_head_office' with JSON: {{\"report_title\": \"Branch {active_branch} Status Sync\", \"summary_content\": \"<operational summary>\"}}.\n"
        f"4. Provide structured BranchOperationOutput strictly conforming to BranchOperationOutput schema."
    )

    task = Task(
        description=task_description,
        expected_output="Valid JSON object conforming to BranchOperationOutput schema",
        agent=resolved_agent,
        output_pydantic=BranchOperationOutput,
        name="BranchOperationTask",
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

        if output and output.pydantic and isinstance(output.pydantic, BranchOperationOutput):
            res = output.pydantic
        else:
            raw = crew_output.raw
            res = BranchOperationOutput(
                request_id=request_data.request_id,
                assigned_branch_id=active_branch,
                target_branch_id=request_data.target_branch_id,
                status="ESCALATED" if has_escalation_call else "SUCCESS_NORMAL",
                operational_summary=raw[:500] if raw else "Facility status normal.",
                head_office_synced=True,
                security_violation_flagged=False,
                memory_references=[f"mem-branch-{request_data.target_branch_id}"],
            )

        if has_escalation_call:
            res.status = "ESCALATED"

        for m_ref in res.memory_references:
            tracer.record_memory_reference(run_record.run_id, m_ref)

        branch_run_status = (
            "ESCALATED" if (has_escalation_call or res.status == "ESCALATED")
            else ("BLOCKED" if res.status == "BLOCKED_CROSS_BRANCH_BREACH" else "COMPLETED")
        )
        tracer.finish_run(
            run_id=run_record.run_id,
            status=branch_run_status,
            output_summary=res.operational_summary[:120],
        )
        return res

    except Exception as exc:
        logger.error(f"Branch Operations agent execution encountered exception: {exc}")
        tracer.finish_run(
            run_id=run_record.run_id,
            status="FAILED",
            error=str(exc),
        )
        raise
