"""Incident Escalation & Human Review Tools.

Module: crewai_service.tools.escalation_tools
Owner: ChronoCogniSec Incident Response Council

Enforces Safe Autonomy:
- Agents cannot make consequential decisions (e.g. employee termination, unauthorized budget overrides).
- Sensitive, suspicious, or unresolvable cases are formally escalated to human supervisors.
- Records incidents in ChronoCogniSec's incident repository with evidence provenance.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional
import uuid

from crewai_service.framework import tool
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient

logger = logging.getLogger("amsc.crewai.tools.escalation")


class EscalationToolFactory:
    """Factory creating escalation tools bound to ChronoCogniSec Incident API."""

    def __init__(self, client: Optional[ChronoCogniSecClient] = None) -> None:
        self.client = client or ChronoCogniSecClient()
        self.tracer = get_tracer()

    def create_escalation_tool(self, agent_id: str, agent_role: str) -> Any:
        client = self.client
        tracer = self.tracer

        @tool(
            "escalate_to_human_supervisor",
            description=(
                "Escalate an unresolved, sensitive, or high-risk case to an authorized human supervisor. "
                "Required JSON parameters: 'case_id' (string identifier of ticket/request/case), "
                "'reason' (string detailed justification for escalation). "
                "Optional parameters: 'severity' ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), 'evidence_refs' (list of strings)."
            ),
        )
        def escalate_to_human_supervisor(
            case_id: str = "",
            reason: str = "",
            severity: str = "MEDIUM",
            evidence_refs: Optional[List[str]] = None,
            **kwargs: Any,
        ) -> str:
            """Escalate an unresolved, sensitive, or high-risk case to an authorized human supervisor."""
            # If case_id contains serialized JSON or Python dict, unwrap parameters safely
            if isinstance(case_id, str) and case_id.strip().startswith("{") and not reason:
                raw_dict = None
                try:
                    import json
                    raw_dict = json.loads(case_id.strip())
                except Exception:
                    try:
                        import ast
                        raw_dict = ast.literal_eval(case_id.strip())
                    except Exception:
                        pass
                if isinstance(raw_dict, dict):
                    case_id = raw_dict.get("case_id") or raw_dict.get("ticket_id") or raw_dict.get("request_id") or raw_dict.get("expense_id") or ""
                    reason = raw_dict.get("reason") or raw_dict.get("explanation") or raw_dict.get("details") or ""
                    severity = raw_dict.get("severity") or severity
                    if not evidence_refs and "evidence_refs" in raw_dict:
                        evidence_refs = raw_dict["evidence_refs"]

            # Support parameter aliases across different specialist contexts
            resolved_case_id = (
                case_id
                or kwargs.get("ticket_id")
                or kwargs.get("request_id")
                or kwargs.get("expense_id")
                or kwargs.get("case")
                or kwargs.get("id")
            )
            resolved_reason = (
                reason
                or kwargs.get("explanation")
                or kwargs.get("details")
                or kwargs.get("message")
                or kwargs.get("issue")
                or kwargs.get("description")
                or kwargs.get("summary")
            )
            resolved_severity = (severity or kwargs.get("urgency", "MEDIUM")).upper()
            if resolved_severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                resolved_severity = "MEDIUM"

            # Strict validation of required arguments
            missing_fields = []
            if not resolved_case_id or not str(resolved_case_id).strip():
                missing_fields.append("case_id")
            if not resolved_reason or not str(resolved_reason).strip():
                missing_fields.append("reason")

            if missing_fields:
                error_msg = (
                    f"ERROR: escalate_to_human_supervisor rejected: missing required arguments {missing_fields}. "
                    f"You must call this tool with Action Input JSON containing both 'case_id' and 'reason'. "
                    f"Example: Action Input: {{\"case_id\": \"case-123\", \"reason\": \"Detailed justification\", \"severity\": \"HIGH\"}}"
                )
                logger.warning(f"Agent [{agent_role}] escalation rejected: {error_msg}")
                return error_msg

            resolved_case_id = str(resolved_case_id).strip()
            resolved_reason = str(resolved_reason).strip()

            logger.warning(
                f"Agent [{agent_role}] initiating escalation for case '{resolved_case_id}': {resolved_reason} (Severity: {resolved_severity})."
            )
            incident_id = f"inc-esc-{uuid.uuid4().hex[:8]}"
            refs = evidence_refs or kwargs.get("memory_references") or kwargs.get("memory_refs") or []
            evidence_items = [
                {
                    "evidence_type": "LOG_ENTRY",
                    "resource_id": str(r_id),
                    "metadata": {"source": "agent_escalation", "case_id": resolved_case_id},
                }
                for r_id in refs
            ]

            # Determine threat classification
            classification = "UNAUTHORIZED_TOOL"
            reason_lower = resolved_reason.lower()
            if "prompt injection" in reason_lower or "injection" in reason_lower:
                classification = "PROMPT_INJECTION"
            elif "memory" in reason_lower or "trust" in reason_lower:
                classification = "UNTRUSTED_MEMORY_ACTION"

            # Submit incident to platform
            client.report_incident(
                title=f"Agent Escalation: Case {resolved_case_id} [{resolved_severity}]",
                classification=classification,
                severity=resolved_severity,
                agent_id=agent_id,
                affected_record_id=str(refs[0]) if refs else None,
                evidence=evidence_items,
            )

            # Record in tracer
            run_records = tracer.list_runs()
            if run_records:
                tracer.finish_run(
                    run_id=run_records[-1].run_id,
                    status="ESCALATED",
                    output_summary=f"Case {resolved_case_id} escalated to human supervisor: {resolved_reason}",
                )

            return (
                f"ESCALATION RECEIPT [{incident_id}]: Case '{resolved_case_id}' has been placed in HUMAN_REVIEW queue. "
                f"Severity: {resolved_severity}. Reason: {resolved_reason}. Bounded agent execution terminated safely."
            )

        return escalate_to_human_supervisor
