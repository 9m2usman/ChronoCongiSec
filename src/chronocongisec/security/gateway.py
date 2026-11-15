"""Framework-independent, fail-closed tool governance gateway."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from .audit import AuditUnavailable


class AuditSink(Protocol):
    def append(self, event: dict[str, Any]) -> dict[str, Any]: ...


class GatewayDenied(PermissionError):
    """A tool proposal was denied by deterministic gateway policy."""


@dataclass(frozen=True)
class AgentPrincipal:
    tenant_id: str
    agent_id: str
    capabilities: frozenset[str]


@dataclass(frozen=True)
class MemoryEvidence:
    memory_id: str
    tenant_id: str
    trust_state: str


@dataclass(frozen=True)
class ToolProposal:
    tool_name: str
    arguments: dict[str, Any]
    trace_id: str = field(default_factory=lambda: str(uuid4()))
    memory_evidence: tuple[MemoryEvidence, ...] = ()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_capabilities: frozenset[str]
    validate_arguments: Callable[[dict[str, Any]], None]
    handler: Callable[[dict[str, Any]], Any]
    enabled: bool = True


@dataclass(frozen=True)
class ExecutionOutcome:
    trace_id: str
    executed: bool
    result: Any = None
    denial_reason: str | None = None
    audit_complete: bool = True


class ToolGovernanceGateway:
    """Only this gateway receives the server-owned tool registry and handlers.

    Agent runtimes should receive a proposal client, never this registry or
    adapter handlers. Identity must be resolved by a trusted authentication
    layer before calling execute().
    """

    def __init__(self, audit_sink: AuditSink, tools: tuple[ToolSpec, ...] = ()) -> None:
        self._audit = audit_sink
        self._tools = {tool.name: tool for tool in tools}

    def register_tool(self, tool: ToolSpec) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def _record(self, event: dict[str, Any], required: bool) -> bool:
        try:
            self._audit.append(event)
            return True
        except Exception:
            if required:
                raise AuditUnavailable("Gateway audit unavailable; operation blocked")
            return False

    def execute(self, principal: AgentPrincipal, proposal: ToolProposal) -> ExecutionOutcome:
        timestamp = datetime.now(timezone.utc).isoformat()
        spec = self._tools.get(proposal.tool_name)
        reason: str | None = None

        if not principal.tenant_id or not principal.agent_id:
            reason = "invalid_agent_identity"
        elif spec is None or not spec.enabled:
            reason = "unknown_or_disabled_tool"
        elif not spec.required_capabilities.issubset(principal.capabilities):
            reason = "missing_capability"
        elif any(item.tenant_id != principal.tenant_id for item in proposal.memory_evidence):
            reason = "cross_tenant_memory_reference"
        elif any(item.trust_state != "TRUSTED" for item in proposal.memory_evidence):
            reason = "untrusted_or_quarantined_memory"

        if reason is None:
            try:
                spec.validate_arguments(proposal.arguments)
            except Exception:
                reason = "invalid_tool_arguments"

        decision = {
            "event_type": "TOOL_POLICY_DECISION",
            "timestamp": timestamp,
            "trace_id": proposal.trace_id,
            "tenant_id": principal.tenant_id,
            "agent_id": principal.agent_id,
            "tool_name": proposal.tool_name,
            "decision": "DENY" if reason else "ALLOW",
            "reason": reason,
            "memory_refs": [item.memory_id for item in proposal.memory_evidence],
        }

        # A decision must be durably recorded before an adapter can run.
        self._record(decision, required=True)
        if reason:
            raise GatewayDenied(reason)

        try:
            result = spec.handler(dict(proposal.arguments))
        except Exception as exc:
            self._record({
                "event_type": "TOOL_EXECUTION_ERROR",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trace_id": proposal.trace_id,
                "tenant_id": principal.tenant_id,
                "agent_id": principal.agent_id,
                "tool_name": proposal.tool_name,
                "error_type": type(exc).__name__,
            }, required=False)
            raise

        # The action has happened; report audit degradation honestly rather
        # than pretending it can be rolled back or silently reporting success.
        audit_complete = self._record({
            "event_type": "TOOL_EXECUTION_RESULT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": proposal.trace_id,
            "tenant_id": principal.tenant_id,
            "agent_id": principal.agent_id,
            "tool_name": proposal.tool_name,
            "result_type": type(result).__name__,
        }, required=False)

        return ExecutionOutcome(
            trace_id=proposal.trace_id,
            executed=True,
            result=result,
            audit_complete=audit_complete,
        )
