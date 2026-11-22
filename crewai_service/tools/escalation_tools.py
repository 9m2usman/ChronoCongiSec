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

        @tool("escalate_to_human_supervisor")
        def escalate_to_human_supervisor(
            case_id: str,
            reason: str,
            severity: str = "MEDIUM",
            evidence_refs: Optional[List[str]] = None,
            **kwargs: Any,
        ) -> str:
            """Escalate an unresolved, sensitive, or high-risk case to an authorized human supervisor."""
            logger.warning(
                f"Agent [{agent_role}] initiating escalation for case '{case_id}': {reason} (Severity: {severity})."
            )
            incident_id = f"inc-esc-{uuid.uuid4().hex[:8]}"
            refs = evidence_refs or []
            evidence_items = [
                {
                    "evidence_type": "LOG_ENTRY",
                    "resource_id": r_id,
                    "metadata": {"source": "agent_escalation", "case_id": case_id},
                }
                for r_id in refs
            ]

            # Determine threat classification
            classification = "UNAUTHORIZED_TOOL"
            reason_lower = reason.lower()
            if "prompt injection" in reason_lower or "injection" in reason_lower:
                classification = "PROMPT_INJECTION"
            elif "memory" in reason_lower or "trust" in reason_lower:
                classification = "UNTRUSTED_MEMORY_ACTION"

            # Submit incident to platform
            client.report_incident(
                title=f"Agent Escalation: Case {case_id} [{severity}]",
                classification=classification,
                severity=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                agent_id=agent_id,
                affected_record_id=refs[0] if refs else None,
                evidence=evidence_items,
            )

            # Record in tracer
            run_records = tracer.list_runs()
            if run_records:
                tracer.finish_run(
                    run_id=run_records[-1].run_id,
                    status="ESCALATED",
                    output_summary=f"Case {case_id} escalated to human supervisor: {reason}",
                )

            return (
                f"ESCALATION RECEIPT [{incident_id}]: Case '{case_id}' has been placed in HUMAN_REVIEW queue. "
                f"Severity: {severity}. Reason: {reason}. Bounded agent execution terminated safely."
            )

        return escalate_to_human_supervisor
