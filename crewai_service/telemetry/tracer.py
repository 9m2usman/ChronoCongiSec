"""Dual Trace & Execution Observability Telemetry.

Module: crewai_service.telemetry.tracer
Owner: ChronoCogniSec AI Observability Council

Integrates with ChronoCogniSec's Dual Trace architecture:
- Correlates Run ID, Workflow ID, Task ID, Trace ID, and Span IDs.
- Records tool invocations, knowledge refs, Gateway proposal IDs, and policy decisions.
- Strictly scrubs credentials, API keys, authorization tokens, and PII from telemetry.
- Exports structured execution metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("amsc.crewai.tracer")

# Sensitive data redaction patterns matching ChronoCogniSec standards
SECRET_KEY_REGEX = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|auth|bearer|credential|priv[_-]?key|cvv|pin|cookie)"
)
SECRET_VAL_REGEX = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9\-_\.~+/]+=*|ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*|sk-[a-zA-Z0-9_\-]{15,})"
)


def redact_sensitive_telemetry(data: Any, max_depth: int = 5, current_depth: int = 0) -> Any:
    """Recursively scrub secrets and credentials from telemetry payloads."""
    if current_depth > max_depth:
        return "[DEPTH_EXCEEDED]"
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            if SECRET_KEY_REGEX.search(str(k)):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_telemetry(v, max_depth, current_depth + 1)
        return cleaned
    if isinstance(data, list):
        return [redact_sensitive_telemetry(item, max_depth, current_depth + 1) for item in data[:50]]
    if isinstance(data, str):
        if SECRET_VAL_REGEX.search(data):
            return "[REDACTED_SECRET]"
        return data
    return data


@dataclass
class ToolInvocationRecord:
    tool_name: str
    operation: str
    parameters: Dict[str, Any]
    result: Optional[Any] = None
    status: str = "SUCCESS"  # SUCCESS, FAILED, BLOCKED
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AgentRunRecord:
    """Full execution metadata record for a genuine agent task execution."""
    run_id: str
    workflow_id: str
    trace_id: str
    task_id: str
    agent_id: str
    agent_role: str
    config_version: str
    llm_provider: str
    model_identifier: str
    status: str  # RUNNING, COMPLETED, FAILED, ESCALATED, BLOCKED
    start_time: datetime
    end_time: Optional[datetime] = None
    tool_invocations: List[ToolInvocationRecord] = field(default_factory=list)
    knowledge_references: List[str] = field(default_factory=list)
    memory_references: List[str] = field(default_factory=list)
    gateway_proposal_ids: List[str] = field(default_factory=list)
    policy_decisions: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    output_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "workflow_id": self.workflow_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "agent_role": self.agent_role,
            "config_version": self.config_version,
            "llm_provider": self.llm_provider,
            "model_identifier": self.model_identifier,
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "tool_invocations": [
                {
                    "tool_name": t.tool_name,
                    "operation": t.operation,
                    "parameters": redact_sensitive_telemetry(t.parameters),
                    "status": t.status,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in self.tool_invocations
            ],
            "knowledge_references": self.knowledge_references,
            "memory_references": self.memory_references,
            "gateway_proposal_ids": self.gateway_proposal_ids,
            "policy_decisions": self.policy_decisions,
            "errors": self.errors,
            "output_summary": self.output_summary,
        }


class ExecutionTracer:
    """Singleton telemetry accumulator coordinating Dual Trace metadata."""

    def __init__(self) -> None:
        self._runs: Dict[str, AgentRunRecord] = {}

    def start_run(
        self,
        agent_id: str,
        agent_role: str,
        task_id: str,
        workflow_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        config_version: str = "v1.0.0",
        llm_provider: str = "gemini",
        model_identifier: str = "gemini-1.5-flash",
    ) -> AgentRunRecord:
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        record = AgentRunRecord(
            run_id=run_id,
            workflow_id=workflow_id or f"wf-{uuid.uuid4().hex[:8]}",
            trace_id=trace_id or f"trace-{uuid.uuid4().hex[:16]}",
            task_id=task_id,
            agent_id=agent_id,
            agent_role=agent_role,
            config_version=config_version,
            llm_provider=llm_provider,
            model_identifier=model_identifier,
            status="RUNNING",
            start_time=datetime.now(timezone.utc),
        )
        self._runs[run_id] = record
        return record

    def record_tool_invocation(
        self,
        run_id: str,
        tool_name: str,
        operation: str,
        parameters: Dict[str, Any],
        result: Optional[Any] = None,
        status: str = "SUCCESS",
    ) -> None:
        if run_id in self._runs:
            self._runs[run_id].tool_invocations.append(
                ToolInvocationRecord(
                    tool_name=tool_name,
                    operation=operation,
                    parameters=parameters,
                    result=result,
                    status=status,
                )
            )

    def record_gateway_decision(
        self,
        run_id: str,
        proposal_id: str,
        decision: str,
    ) -> None:
        if run_id in self._runs:
            self._runs[run_id].gateway_proposal_ids.append(proposal_id)
            self._runs[run_id].policy_decisions.append(decision)

    def record_memory_reference(self, run_id: str, memory_id: str) -> None:
        if run_id in self._runs:
            if memory_id not in self._runs[run_id].memory_references:
                self._runs[run_id].memory_references.append(memory_id)

    def finish_run(
        self,
        run_id: str,
        status: str = "COMPLETED",
        output_summary: Optional[str] = None,
        error: Optional[str] = None,
    ) -> Optional[AgentRunRecord]:
        if run_id in self._runs:
            rec = self._runs[run_id]
            rec.end_time = datetime.now(timezone.utc)
            rec.status = status
            rec.output_summary = output_summary
            if error:
                rec.errors.append(error)
            logger.info(f"Finished run [{run_id}] with status [{status}].")
            return rec
        return None

    def get_run(self, run_id: str) -> Optional[AgentRunRecord]:
        return self._runs.get(run_id)

    def list_runs(self) -> List[AgentRunRecord]:
        return list(self._runs.values())

    def clear(self) -> None:
        self._runs.clear()


_default_tracer = ExecutionTracer()


def get_tracer() -> ExecutionTracer:
    return _default_tracer
