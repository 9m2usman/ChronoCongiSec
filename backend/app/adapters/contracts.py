"""Framework-Neutral Agent Integration Contracts (Phase 1 §5).

Follows Phase 0 Architecture:
- Complete mediation through Protected Gateway
- Strict credential and database isolation: agents never access DB directly
- Correlated observation telemetry with W3C traceparent headers
- Reusable contracts for CrewAI, LangGraph, AutoGen, and Custom Python agents
"""

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
import uuid

logger = logging.getLogger("amsc.adapters.contracts")


@dataclass
class ActionProposal:
    action_id: str
    agent_id: str
    tool_name: str
    operation: str
    parameters: Dict[str, Any]
    memory_refs: List[str] = field(default_factory=list)
    idempotency_key: Optional[str] = None
    trace_id: Optional[str] = None


@dataclass
class ActionReceipt:
    action_id: str
    proposal_id: str
    decision: str  # ALLOW, BLOCK, REQUIRES_APPROVAL
    memory_trust: str
    policy_result: str
    reasons: List[str]
    execution_status: str  # EXECUTED, NOT_EXECUTED, PENDING_APPROVAL, UNKNOWN
    result: Optional[Dict[str, Any]] = None


@runtime_checkable
class AgentRuntimeAdapterProtocol(Protocol):
    """Protocol that all framework adapters must satisfy."""

    runtime_name: str

    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        """Submit action proposal through the protected gateway. Fail-closed."""
        ...

    async def emit_observation(
        self,
        event_type: str,
        event_category: str,
        agent_id: str,
        trace_id: str,
        payload: Dict[str, Any],
        client: Any,
        outcome: str = "SUCCESS",
    ) -> Dict[str, Any]:
        """Emit structured observation event with trace correlation."""
        ...

    async def fetch_trusted_knowledge(
        self,
        client: Any,
        category: Optional[str] = None,
        branch_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch verified enterprise baseline knowledge or trusted memory."""
        ...


class AgentIntegrationContract(ABC):
    """Abstract base class establishing standard integration boundaries."""

    def __init__(self, runtime_name: str) -> None:
        self.runtime_name = runtime_name

    @abstractmethod
    def build_w3c_trace_headers(self, trace_id: Optional[str] = None) -> Dict[str, str]:
        """Generate canonical W3C traceparent headers for request correlation."""
        pass

    @abstractmethod
    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        pass


class CrewAIAdapterContract(AgentIntegrationContract):
    """Adapter contract for CrewAI business agents."""

    def __init__(self) -> None:
        super().__init__(runtime_name="CREWAI")

    def build_w3c_trace_headers(self, trace_id: Optional[str] = None) -> Dict[str, str]:
        tid = trace_id or uuid.uuid4().hex
        if re.fullmatch(r"[0-9a-fA-F]{32}", tid):
            w3c_tid = tid.lower()
        else:
            w3c_tid = hashlib.sha256(tid.encode("utf-8")).hexdigest()[:32]
        span_id = uuid.uuid4().hex[:16]
        return {
            "X-Trace-ID": tid,
            "traceparent": f"00-{w3c_tid}-{span_id}-01",
        }

    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        res = client.propose_tool_action(
            agent_id=proposal.agent_id,
            tool_name=proposal.tool_name,
            operation=proposal.operation,
            parameters=proposal.parameters,
            memory_refs=proposal.memory_refs,
            action_id=proposal.action_id,
            idempotency_key=proposal.idempotency_key,
            trace_id=proposal.trace_id,
        )
        return ActionReceipt(
            action_id=res.get("action_id", proposal.action_id),
            proposal_id=res.get("proposal_id", ""),
            decision=res.get("decision", "BLOCK"),
            memory_trust=res.get("memory_trust", "UNVERIFIED"),
            policy_result=res.get("policy_result", "DENIED"),
            reasons=res.get("reasons", []),
            execution_status=res.get("execution_status", "NOT_EXECUTED"),
            result=res.get("result"),
        )

    async def emit_observation(
        self,
        event_type: str,
        event_category: str,
        agent_id: str,
        trace_id: str,
        payload: Dict[str, Any],
        client: Any,
        outcome: str = "SUCCESS",
    ) -> Dict[str, Any]:
        if hasattr(client, "emit_observation_event"):
            return client.emit_observation_event(
                event_type=event_type,
                event_category=event_category,
                agent_id=agent_id,
                trace_id=trace_id,
                payload=payload,
                outcome=outcome,
            )
        return {"status": "SKIPPED"}


class LangGraphAdapterContract(AgentIntegrationContract):
    """Specification contract for LangGraph state graph tool execution nodes."""

    def __init__(self) -> None:
        super().__init__(runtime_name="LANGGRAPH")

    def build_w3c_trace_headers(self, trace_id: Optional[str] = None) -> Dict[str, str]:
        tid = trace_id or uuid.uuid4().hex
        w3c_tid = hashlib.sha256(tid.encode("utf-8")).hexdigest()[:32]
        span_id = uuid.uuid4().hex[:16]
        return {"X-Trace-ID": tid, "traceparent": f"00-{w3c_tid}-{span_id}-01"}

    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        """Translates LangGraph tool call into canonical AMSC action proposal."""
        res = client.propose_tool_action(
            agent_id=proposal.agent_id,
            tool_name=proposal.tool_name,
            operation=proposal.operation,
            parameters=proposal.parameters,
            memory_refs=proposal.memory_refs,
            action_id=proposal.action_id,
            idempotency_key=proposal.idempotency_key,
            trace_id=proposal.trace_id,
        )
        return ActionReceipt(
            action_id=res.get("action_id", proposal.action_id),
            proposal_id=res.get("proposal_id", ""),
            decision=res.get("decision", "BLOCK"),
            memory_trust=res.get("memory_trust", "UNVERIFIED"),
            policy_result=res.get("policy_result", "DENIED"),
            reasons=res.get("reasons", []),
            execution_status=res.get("execution_status", "NOT_EXECUTED"),
            result=res.get("result"),
        )


class AutoGenAdapterContract(AgentIntegrationContract):
    """Specification contract for AutoGen ConversableAgent tool calls."""

    def __init__(self) -> None:
        super().__init__(runtime_name="AUTOGEN")

    def build_w3c_trace_headers(self, trace_id: Optional[str] = None) -> Dict[str, str]:
        tid = trace_id or uuid.uuid4().hex
        w3c_tid = hashlib.sha256(tid.encode("utf-8")).hexdigest()[:32]
        span_id = uuid.uuid4().hex[:16]
        return {"X-Trace-ID": tid, "traceparent": f"00-{w3c_tid}-{span_id}-01"}

    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        res = client.propose_tool_action(
            agent_id=proposal.agent_id,
            tool_name=proposal.tool_name,
            operation=proposal.operation,
            parameters=proposal.parameters,
            memory_refs=proposal.memory_refs,
            action_id=proposal.action_id,
            idempotency_key=proposal.idempotency_key,
            trace_id=proposal.trace_id,
        )
        return ActionReceipt(
            action_id=res.get("action_id", proposal.action_id),
            proposal_id=res.get("proposal_id", ""),
            decision=res.get("decision", "BLOCK"),
            memory_trust=res.get("memory_trust", "UNVERIFIED"),
            policy_result=res.get("policy_result", "DENIED"),
            reasons=res.get("reasons", []),
            execution_status=res.get("execution_status", "NOT_EXECUTED"),
            result=res.get("result"),
        )


class CustomPythonAgentContract(AgentIntegrationContract):
    """Specification contract for custom direct HTTP/ASGI Python agents."""

    def __init__(self) -> None:
        super().__init__(runtime_name="CUSTOM_PYTHON")

    def build_w3c_trace_headers(self, trace_id: Optional[str] = None) -> Dict[str, str]:
        tid = trace_id or uuid.uuid4().hex
        w3c_tid = hashlib.sha256(tid.encode("utf-8")).hexdigest()[:32]
        span_id = uuid.uuid4().hex[:16]
        return {"X-Trace-ID": tid, "traceparent": f"00-{w3c_tid}-{span_id}-01"}

    async def propose_action(
        self,
        proposal: ActionProposal,
        client: Any,
    ) -> ActionReceipt:
        res = client.propose_tool_action(
            agent_id=proposal.agent_id,
            tool_name=proposal.tool_name,
            operation=proposal.operation,
            parameters=proposal.parameters,
            memory_refs=proposal.memory_refs,
            action_id=proposal.action_id,
            idempotency_key=proposal.idempotency_key,
            trace_id=proposal.trace_id,
        )
        return ActionReceipt(
            action_id=res.get("action_id", proposal.action_id),
            proposal_id=res.get("proposal_id", ""),
            decision=res.get("decision", "BLOCK"),
            memory_trust=res.get("memory_trust", "UNVERIFIED"),
            policy_result=res.get("policy_result", "DENIED"),
            reasons=res.get("reasons", []),
            execution_status=res.get("execution_status", "NOT_EXECUTED"),
            result=res.get("result"),
        )
