"""Dual Trace and Observability API (AMSC-DOC-005 Section 5, M1 Day 6).

Canonical Route:
- GET /api/v1/traces/{id}/dual-trace
- GET /api/v1/traces (Trace Listing)

Owner: M1 — Platform Backend & API Integration Lead
Integrates:
- M2: Agent Runtime & Gateway Execution Telemetry
- M3: Memory Retrieval & Provenance Evidence
- M5: Dual Trace Frontend Workstation Contract
- M6: Schema & Tenant-Scoped Read-Only Persistence
- M7: Rate Limiting & Infrastructure Guardrails
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.config import get_settings
from backend.app.core.dependencies import (
    RateLimitResult,
    RateLimiterProtocol,
    TenantContextDep,
    get_default_rate_limiter,
)
from backend.app.core.exceptions import (
    NotFoundError,
    RateLimitExceededError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.database.models.agents import Agent
from backend.app.database.models.gateway import Approval, PolicyDecision, ToolExecution, ToolProposal
from backend.app.database.models.memory import MemoryRecord, MemoryVersion, RetrievalEvent, Source
from backend.app.database.models.observability import Trace, TraceSpan

logger = logging.getLogger("amsc.traces")

# Safe trace ID pattern: W3C trace context, UUIDs, or standard trace strings.
SAFE_TRACE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

# Maximum limits to protect against resource exhaustion
MAX_SPANS_LIMIT = 500
MAX_MEMORY_EVENTS_LIMIT = 200
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
MAX_OFFSET = 10000

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|auth|bearer|credential|priv[_-]?key|prompt|cookie|ssn)"
)
SENSITIVE_VALUE_PATTERNS = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9\-_\.~+/]+=*|ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----|://[^:]+:[^@]+@|(?:^|[?&;\s,])(?:token|secret|secret[_-]?key|api[_-]?key|password)=[^&\s;,]+|sk-[a-zA-Z0-9_\-]{15,}|ghp_[a-zA-Z0-9]{15,})"
)


# ============================================================================
# Security & Redaction Helpers
# ============================================================================

def validate_trace_id(trace_id: str) -> str:
    """Validate trace ID against safe identifier rules."""
    if not trace_id or not isinstance(trace_id, str):
        raise ValidationError("Trace identifier must be a non-empty string.")
    cleaned = trace_id.strip()
    if cleaned in (".", "..") or not SAFE_TRACE_ID_REGEX.match(cleaned):
        raise ValidationError(
            "Invalid trace identifier format. Must be 1-128 alphanumeric, dash, underscore, or period characters."
        )
    return cleaned


def redact_sensitive_value(
    value: Any,
    parent_key: str = "",
    max_depth: int = 5,
    current_depth: int = 0,
) -> Any:
    """Recursively scrub values, detecting secret keys, token strings, and bounding depth."""
    if current_depth > max_depth:
        return "[DEPTH_EXCEEDED]"
    if isinstance(value, dict):
        return redact_sensitive_dict(value, max_depth, current_depth + 1)
    if isinstance(value, list):
        return [
            redact_sensitive_value(item, parent_key, max_depth, current_depth + 1)
            for item in value[:50]
        ]
    if isinstance(value, str):
        if SENSITIVE_KEY_PATTERNS.search(parent_key):
            return REDACTED_VALUE
        if SENSITIVE_VALUE_PATTERNS.search(value):
            return REDACTED_VALUE
        if len(value) > 2048:
            return value[:2048] + "... [TRUNCATED]"
        return value
    return value


def redact_sensitive_dict(
    data: Optional[Dict[str, Any]],
    max_depth: int = 5,
    current_depth: int = 0,
) -> Dict[str, Any]:
    """Recursively scrub sensitive keys/values and protect against deep nesting attacks."""
    if not data or not isinstance(data, dict) or current_depth > max_depth:
        return {}

    scrubbed: Dict[str, Any] = {}
    for key, value in data.items():
        if SENSITIVE_KEY_PATTERNS.search(key):
            scrubbed[key] = REDACTED_VALUE
        else:
            scrubbed[key] = redact_sensitive_value(value, key, max_depth, current_depth + 1)
    return scrubbed


# ============================================================================
# Response Schemas (Preserving DOC-005 and Frontend M5 DualTraceData)
# ============================================================================

class ExecutionLaneItem(BaseModel):
    """Execution lane telemetry item representing a tool proposal or execution span."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique event or span identifier")
    trace_id: str = Field(..., description="Correlated trace identifier")
    timestamp: datetime = Field(..., description="ISO 8601 UTC timestamp of occurrence")
    time_display: str = Field(..., description="Formatted time string for frontend display")
    agent_id: str = Field(..., description="Identifier of the executing agent")
    agent_name: str = Field(..., description="Display name of the executing agent")
    action_label: str = Field(..., description="High-level action description")
    action_detail: str = Field(..., description="Detailed safe execution action")
    memory_ref: Optional[str] = Field(None, description="Primary memory record reference cited")
    status: str = Field(..., description="Execution status: OK, TAINTED, BLOCKED, INTERCEPTED")
    details: Optional[Dict[str, Any]] = Field(None, description="Safe redacted execution details")
    duration_ms: Optional[int] = Field(None, description="Execution duration in milliseconds")
    operation: Optional[str] = Field(None, description="Tool operation or span operation name")
    policy_decision: Optional[str] = Field(None, description="Associated policy decision if available")
    approval_status: Optional[str] = Field(None, description="Human approval status if required")
    execution_status: Optional[str] = Field(None, description="Resulting tool execution status")


class MemoryLaneItem(BaseModel):
    """Memory lane telemetry item representing a memory retrieval or access event."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique retrieval event identifier")
    record_id: str = Field(..., description="Referenced memory record identifier")
    timestamp: datetime = Field(..., description="ISO 8601 UTC timestamp of retrieval")
    time_display: str = Field(..., description="Formatted time string for frontend display")
    label: str = Field(..., description="Label or title of the memory record")
    trust_state: str = Field(..., description="Truthful trust state description (historical or explicitly marked current)")
    historical_trust_state: Optional[str] = Field(
        None, description="Trust state at retrieval time if recorded; UNRECORDED if missing"
    )
    current_trust_state: Optional[str] = Field(
        None, description="Current trust state of the record in the memory repository"
    )
    checksum: str = Field(..., description="Content hash of the retrieved or current version")
    version: Optional[int] = Field(None, description="Version number of the memory record")
    source_uri: Optional[str] = Field(None, description="Provenance source URI if available")
    query_text_redacted: Optional[str] = Field(None, description="Redacted query text summary")


class CompletenessReport(BaseModel):
    """Truthful evidence completeness status for Execution and Memory lanes."""

    execution: str = Field(..., description="Execution lane completeness: COMPLETE, PARTIAL, EMPTY, TRUNCATED")
    memory: str = Field(..., description="Memory lane completeness: COMPLETE, PARTIAL, EMPTY, TRUNCATED")


class DualTraceResponse(BaseModel):
    """Canonical Dual Trace forensic response envelope."""

    model_config = ConfigDict(extra="ignore")

    trace_id: str = Field(..., description="Trace identifier")
    status: str = Field(..., description="Overall trace lifecycle status")
    started_at: datetime = Field(..., description="Trace initialization timestamp")
    execution_lane: List[ExecutionLaneItem] = Field(
        default_factory=list, description="Canonical execution lane telemetry"
    )
    memory_lane: List[MemoryLaneItem] = Field(
        default_factory=list, description="Canonical memory retrieval telemetry"
    )
    # M5 Frontend backwards-compatibility aliases
    execution_spans: List[ExecutionLaneItem] = Field(
        default_factory=list, description="Frontend alias for execution lane"
    )
    memory_spans: List[MemoryLaneItem] = Field(
        default_factory=list, description="Frontend alias for memory lane"
    )
    completeness: CompletenessReport = Field(..., description="Completeness breakdown")
    warnings: List[str] = Field(default_factory=list, description="Forensic warnings and gap disclosures")
    truncated: bool = Field(False, description="True if telemetry exceeded bounds and was capped")


class TraceSummary(BaseModel):
    """Summary item for trace listing."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Trace identifier")
    agent_id: Optional[str] = Field(None, description="Primary executing agent ID")
    started_at: datetime = Field(..., description="Trace start time")
    status: str = Field(..., description="Trace status")
    span_count: int = Field(0, description="Total spans/proposals in trace")


class TraceListResponse(BaseModel):
    """Paginated trace listing response."""

    model_config = ConfigDict(extra="ignore")

    items: List[TraceSummary] = Field(default_factory=list, description="List of traces")
    total: int = Field(..., description="Total available traces matching query")
    limit: int = Field(..., description="Applied page limit")
    offset: int = Field(..., description="Applied page offset")


# ============================================================================
# Internal Aggregate Entities
# ============================================================================

class DualTraceAggregate:
    """Internal domain container for raw correlated trace evidence."""

    def __init__(
        self,
        trace_id: str,
        status: str,
        started_at: datetime,
        agent_id: Optional[str] = None,
        spans: Optional[List[TraceSpan]] = None,
        proposals: Optional[List[Tuple[ToolProposal, Optional[PolicyDecision], Optional[Approval], Optional[ToolExecution]]]] = None,
        retrievals: Optional[List[Tuple[RetrievalEvent, Optional[MemoryRecord], Optional[MemoryVersion], Optional[Source]]]] = None,
        agent_names: Optional[Dict[str, str]] = None,
        truncated: bool = False,
    ) -> None:
        self.trace_id = trace_id
        self.status = status
        self.started_at = started_at
        self.agent_id = agent_id
        self.spans = spans or []
        self.proposals = proposals or []
        self.retrievals = retrievals or []
        self.agent_names = agent_names or {}
        self.truncated = truncated


# ============================================================================
# Repository Interface Protocol & Implementations
# ============================================================================

@runtime_checkable
class TraceRepositoryProtocol(Protocol):
    """Protocol boundary for M6 read-only trace persistence."""

    is_persistent: bool
    is_in_memory: bool

    async def get_dual_trace(
        self,
        tenant_id: str,
        trace_id: str,
        max_spans: int = MAX_SPANS_LIMIT,
        max_memory_events: int = MAX_MEMORY_EVENTS_LIMIT,
    ) -> Optional[DualTraceAggregate]:
        """Fetch trace aggregate strictly scoped to tenant_id."""
        ...

    async def list_traces(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> Tuple[List[TraceSummary], int]:
        """List recent traces for tenant with optional agent filter."""
        ...

    async def check_span_reference(
        self,
        span_id: str,
        tenant_id: str,
    ) -> str:
        """Verify existence and tenant ownership of a trace span. Returns 'OK', 'CROSS_TENANT', or 'NOT_FOUND'."""
        ...


class SqlAlchemyTraceRepository:
    """PostgreSQL production repository for read-only Dual Trace queries."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def get_dual_trace(
        self,
        tenant_id: str,
        trace_id: str,
        max_spans: int = MAX_SPANS_LIMIT,
        max_memory_events: int = MAX_MEMORY_EVENTS_LIMIT,
    ) -> Optional[DualTraceAggregate]:
        async with self.session_factory() as session:
            # 1. Fetch trace strictly scoped to tenant
            trace_stmt = select(Trace).where(Trace.id == trace_id, Trace.tenant_id == tenant_id)
            trace_result = await session.execute(trace_stmt)
            trace = trace_result.scalar_one_or_none()

            # If Trace table row is absent, check if spans, proposals, or retrievals exist for this trace_id
            # to preserve observability of in-flight or client-originated traces.
            if trace is None:
                span_check = await session.execute(
                    select(func.count(TraceSpan.id)).where(
                        TraceSpan.trace_id == trace_id, TraceSpan.tenant_id == tenant_id
                    )
                )
                proposal_check = await session.execute(
                    select(func.count(ToolProposal.id)).where(
                        ToolProposal.trace_id == trace_id, ToolProposal.tenant_id == tenant_id
                    )
                )
                retrieval_check = await session.execute(
                    select(func.count(RetrievalEvent.id)).where(
                        RetrievalEvent.trace_id == trace_id, RetrievalEvent.tenant_id == tenant_id
                    )
                )
                if (
                    (span_check.scalar_one() or 0) == 0
                    and (proposal_check.scalar_one() or 0) == 0
                    and (retrieval_check.scalar_one() or 0) == 0
                ):
                    return None

                status_val = "COMPLETED"
                started_at = datetime.now(timezone.utc)
                agent_id_val = None
            else:
                status_val = trace.status
                started_at = trace.started_at
                agent_id_val = trace.agent_id

            # 2. Fetch TraceSpans (bounded, tenant-scoped)
            spans_stmt = (
                select(TraceSpan)
                .where(TraceSpan.trace_id == trace_id, TraceSpan.tenant_id == tenant_id)
                .order_by(TraceSpan.created_at.asc())
                .limit(max_spans + 1)
            )
            spans_result = await session.execute(spans_stmt)
            spans = list(spans_result.scalars().all())

            # 3. Fetch ToolProposals, Decisions, Approvals, Executions (all tenant-scoped)
            proposals_stmt = (
                select(ToolProposal, PolicyDecision, Approval, ToolExecution)
                .outerjoin(
                    PolicyDecision,
                    (PolicyDecision.proposal_id == ToolProposal.id) & (PolicyDecision.tenant_id == tenant_id),
                )
                .outerjoin(
                    Approval,
                    (Approval.decision_id == PolicyDecision.id) & (Approval.tenant_id == tenant_id),
                )
                .outerjoin(
                    ToolExecution,
                    (ToolExecution.proposal_id == ToolProposal.id) & (ToolExecution.tenant_id == tenant_id),
                )
                .where(ToolProposal.trace_id == trace_id, ToolProposal.tenant_id == tenant_id)
                .order_by(ToolProposal.created_at.asc())
                .limit(max_spans + 1)
            )
            proposals_result = await session.execute(proposals_stmt)
            raw_proposal_tuples = [
                (row[0], row[1], row[2], row[3]) for row in proposals_result.all()
            ]

            # Deduplicate proposals if multiple approvals exist, keeping most recent
            dedup_proposals: Dict[str, Tuple[ToolProposal, Optional[PolicyDecision], Optional[Approval], Optional[ToolExecution]]] = {}
            for prop, dec, appr, exe in raw_proposal_tuples:
                if prop.id not in dedup_proposals:
                    dedup_proposals[prop.id] = (prop, dec, appr, exe)
                else:
                    # Update approval if existing was None or new has responded_at
                    curr_prop, curr_dec, curr_appr, curr_exe = dedup_proposals[prop.id]
                    if appr is not None and (curr_appr is None or (appr.responded_at and not curr_appr.responded_at)):
                        dedup_proposals[prop.id] = (curr_prop, curr_dec or dec, appr, curr_exe or exe)

            proposal_tuples = list(dedup_proposals.values())

            # 4. Fetch RetrievalEvents, MemoryRecord, MemoryVersion, Source
            retrievals_stmt = (
                select(RetrievalEvent, MemoryRecord, MemoryVersion, Source)
                .outerjoin(
                    MemoryRecord,
                    (MemoryRecord.id == RetrievalEvent.record_id) & (MemoryRecord.tenant_id == tenant_id),
                )
                .outerjoin(
                    MemoryVersion,
                    (MemoryVersion.record_id == MemoryRecord.id)
                    & (MemoryVersion.version == MemoryRecord.current_version)
                    & (MemoryVersion.tenant_id == tenant_id),
                )
                .outerjoin(
                    Source,
                    (Source.id == MemoryRecord.source_id) & (Source.tenant_id == tenant_id),
                )
                .where(RetrievalEvent.trace_id == trace_id, RetrievalEvent.tenant_id == tenant_id)
                .order_by(RetrievalEvent.occurred_at.asc())
                .limit(max_memory_events + 1)
            )
            retrievals_result = await session.execute(retrievals_stmt)
            retrieval_tuples = [
                (row[0], row[1], row[2], row[3]) for row in retrievals_result.all()
            ]

            # Determine truncation
            truncated = (
                len(spans) > max_spans
                or len(proposal_tuples) > max_spans
                or len(retrieval_tuples) > max_memory_events
            )

            final_spans = spans[:max_spans]
            final_proposals = proposal_tuples[:max_spans]
            final_retrievals = retrieval_tuples[:max_memory_events]

            # Collect agent IDs to resolve names
            agent_ids = set()
            if agent_id_val:
                agent_ids.add(agent_id_val)
            for p, _, _, _ in final_proposals:
                if p.agent_id:
                    agent_ids.add(p.agent_id)
            for r, _, _, _ in final_retrievals:
                if r.agent_id:
                    agent_ids.add(r.agent_id)

            agent_names: Dict[str, str] = {}
            if agent_ids:
                agents_stmt = select(Agent.id, Agent.name).where(
                    Agent.id.in_(list(agent_ids)), Agent.tenant_id == tenant_id
                )
                agents_res = await session.execute(agents_stmt)
                for a_id, a_name in agents_res.all():
                    agent_names[a_id] = a_name

            return DualTraceAggregate(
                trace_id=trace_id,
                status=status_val,
                started_at=started_at,
                agent_id=agent_id_val,
                spans=final_spans,
                proposals=final_proposals,
                retrievals=final_retrievals,
                agent_names=agent_names,
                truncated=truncated,
            )

    async def list_traces(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> Tuple[List[TraceSummary], int]:
        async with self.session_factory() as session:
            count_stmt = select(func.count(Trace.id)).where(Trace.tenant_id == tenant_id)
            if agent_id:
                count_stmt = count_stmt.where(Trace.agent_id == agent_id)
            total = (await session.execute(count_stmt)).scalar_one() or 0

            traces_stmt = (
                select(Trace)
                .where(Trace.tenant_id == tenant_id)
                .order_by(Trace.started_at.desc())
                .limit(limit)
                .offset(offset)
            )
            if agent_id:
                traces_stmt = traces_stmt.where(Trace.agent_id == agent_id)

            traces = (await session.execute(traces_stmt)).scalars().all()
            summaries = [
                TraceSummary(
                    id=t.id,
                    agent_id=t.agent_id,
                    started_at=t.started_at,
                    status=t.status,
                    span_count=0,
                )
                for t in traces
            ]
            return summaries, total

    async def check_span_reference(self, span_id: str, tenant_id: str) -> str:
        """Verify existence and tenant ownership of a trace span."""
        async with self.session_factory() as session:
            stmt = select(TraceSpan.tenant_id).where(TraceSpan.id == span_id)
            owner_tenant = (await session.execute(stmt)).scalar_one_or_none()
            if owner_tenant is None:
                return "NOT_FOUND"
            if owner_tenant != tenant_id:
                return "CROSS_TENANT"
            return "OK"


class InMemoryTraceRepository:
    """In-memory trace repository strictly for local testing and dev."""

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        self.traces: Dict[Tuple[str, str], Trace] = {}
        self.spans: List[TraceSpan] = []
        self.proposals: List[Tuple[ToolProposal, Optional[PolicyDecision], Optional[Approval], Optional[ToolExecution]]] = []
        self.retrievals: List[Tuple[RetrievalEvent, Optional[MemoryRecord], Optional[MemoryVersion], Optional[Source]]] = []
        self.agents: Dict[Tuple[str, str], Agent] = {}

    async def check_span_reference(self, span_id: str, tenant_id: str) -> str:
        """Verify existence and tenant ownership of a trace span."""
        for s in self.spans:
            if s.id == span_id:
                if s.tenant_id != tenant_id:
                    return "CROSS_TENANT"
                return "OK"
        return "NOT_FOUND"

    def seed_trace(self, trace: Trace) -> None:
        self.traces[(trace.tenant_id, trace.id)] = trace

    def seed_span(self, span: TraceSpan) -> None:
        self.spans.append(span)

    def seed_proposal(
        self,
        proposal: ToolProposal,
        decision: Optional[PolicyDecision] = None,
        approval: Optional[Approval] = None,
        execution: Optional[ToolExecution] = None,
    ) -> None:
        self.proposals.append((proposal, decision, approval, execution))

    def seed_retrieval(
        self,
        event: RetrievalEvent,
        record: Optional[MemoryRecord] = None,
        version: Optional[MemoryVersion] = None,
        source: Optional[Source] = None,
    ) -> None:
        self.retrievals.append((event, record, version, source))

    def seed_agent(self, agent: Agent) -> None:
        self.agents[(agent.tenant_id, agent.id)] = agent

    async def get_dual_trace(
        self,
        tenant_id: str,
        trace_id: str,
        max_spans: int = MAX_SPANS_LIMIT,
        max_memory_events: int = MAX_MEMORY_EVENTS_LIMIT,
    ) -> Optional[DualTraceAggregate]:
        trace = self.traces.get((tenant_id, trace_id))

        trace_spans = [
            s for s in self.spans if s.tenant_id == tenant_id and s.trace_id == trace_id
        ]
        trace_proposals = [
            (
                p[0],
                p[1] if (p[1] and p[1].tenant_id == tenant_id) else None,
                p[2] if (p[2] and p[2].tenant_id == tenant_id) else None,
                p[3] if (p[3] and p[3].tenant_id == tenant_id) else None,
            )
            for p in self.proposals
            if p[0].tenant_id == tenant_id and p[0].trace_id == trace_id
        ]
        trace_retrievals = [
            (
                r[0],
                r[1] if (r[1] and r[1].tenant_id == tenant_id) else None,
                r[2] if (r[2] and r[2].tenant_id == tenant_id) else None,
                r[3] if (r[3] and r[3].tenant_id == tenant_id) else None,
            )
            for r in self.retrievals
            if r[0].tenant_id == tenant_id and r[0].trace_id == trace_id
        ]

        if not trace and not trace_spans and not trace_proposals and not trace_retrievals:
            return None

        status_val = trace.status if trace else "COMPLETED"
        started_at = trace.started_at if trace else datetime.now(timezone.utc)
        agent_id_val = trace.agent_id if trace else None

        truncated = (
            len(trace_spans) > max_spans
            or len(trace_proposals) > max_spans
            or len(trace_retrievals) > max_memory_events
        )

        final_spans = sorted(trace_spans, key=lambda s: s.created_at)[:max_spans]
        final_proposals = sorted(trace_proposals, key=lambda p: p[0].created_at)[:max_spans]
        final_retrievals = sorted(trace_retrievals, key=lambda r: r[0].occurred_at)[:max_memory_events]

        agent_names: Dict[str, str] = {}
        for (t_id, a_id), agent in self.agents.items():
            if t_id == tenant_id:
                agent_names[a_id] = agent.name

        return DualTraceAggregate(
            trace_id=trace_id,
            status=status_val,
            started_at=started_at,
            agent_id=agent_id_val,
            spans=final_spans,
            proposals=final_proposals,
            retrievals=final_retrievals,
            agent_names=agent_names,
            truncated=truncated,
        )

    async def list_traces(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> Tuple[List[TraceSummary], int]:
        matched = [
            t for (t_id, _), t in self.traces.items()
            if t_id == tenant_id and (agent_id is None or t.agent_id == agent_id)
        ]
        matched.sort(key=lambda t: t.started_at, reverse=True)
        total = len(matched)
        page = matched[offset : offset + limit]
        summaries = [
            TraceSummary(
                id=t.id,
                agent_id=t.agent_id,
                started_at=t.started_at,
                status=t.status,
                span_count=sum(1 for s in self.spans if s.tenant_id == tenant_id and s.trace_id == t.id),
            )
            for t in page
        ]
        return summaries, total


_default_trace_repo: Optional[InMemoryTraceRepository] = None


def get_default_trace_repository() -> InMemoryTraceRepository:
    """Factory returning thread-safe default in-memory repository for unit testing."""
    global _default_trace_repo
    if _default_trace_repo is None:
        _default_trace_repo = InMemoryTraceRepository()
        now = datetime.now(timezone.utc)
        # Pre-seed canonical test spans for tenant A
        _default_trace_repo.seed_span(
            TraceSpan(
                id="span-forensic-001",
                trace_id="tr-forensic-001",
                tenant_id="tenant-a-uuid-001",
                operation="memory_retrieval",
                duration_ms=12,
                created_at=now,
            )
        )
        _default_trace_repo.seed_span(
            TraceSpan(
                id="span-sec-01",
                trace_id="tr-sec-001",
                tenant_id="tenant-a-uuid-001",
                operation="security_check",
                duration_ms=15,
                created_at=now,
            )
        )
    return _default_trace_repo


async def get_trace_repository(request: Request) -> TraceRepositoryProtocol:
    """Dependency provider for trace repository boundary."""
    repo = getattr(request.app.state, "trace_repo", None)
    if repo is not None:
        return repo

    settings = getattr(request.app.state, "settings", None) or get_settings()
    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Database persistence is required for traces in production.")

    return get_default_trace_repository()


# ============================================================================
# Lane Assembly & Correlation Engine
# ============================================================================

def build_execution_lane(
    aggregate: DualTraceAggregate,
    warnings: List[str],
) -> List[ExecutionLaneItem]:
    """Assemble execution lane items from gateway proposals and execution spans."""
    items: List[ExecutionLaneItem] = []

    # Map proposals to execution lane items
    for proposal, decision, approval, execution in aggregate.proposals:
        agent_name = aggregate.agent_names.get(proposal.agent_id, f"Agent-{proposal.agent_id[:8]}")
        
        # Determine status according to security policies
        if decision and decision.decision == "DENY":
            item_status = "BLOCKED"
        elif approval and approval.status == "REJECTED":
            item_status = "BLOCKED"
        elif decision and decision.memory_trust in ("QUARANTINED", "SUSPICIOUS"):
            item_status = "TAINTED"
        elif execution and execution.status != "SUCCESS":
            item_status = "INTERCEPTED" if execution.status == "INTERCEPTED" else "BLOCKED"
        elif decision and decision.execution_status == "BLOCKED":
            item_status = "BLOCKED"
        else:
            item_status = "OK"

        first_mem_ref = proposal.memory_refs_json[0] if proposal.memory_refs_json else None
        time_display = proposal.created_at.strftime("%H:%M:%S")

        safe_details = redact_sensitive_dict({
            "parameters": proposal.parameters_json,
            "reasons": decision.reasons_json if decision else [],
            "idempotency_key": proposal.idempotency_key,
        })

        exec_status = execution.status if execution else (decision.execution_status if decision else "NOT_EXECUTED")

        items.append(
            ExecutionLaneItem(
                id=proposal.id,
                trace_id=proposal.trace_id,
                timestamp=proposal.created_at,
                time_display=time_display,
                agent_id=proposal.agent_id,
                agent_name=redact_sensitive_value(agent_name),
                action_label=redact_sensitive_value(f"Tool Proposal: {proposal.tool_name}"),
                action_detail=redact_sensitive_value(f"tool:{proposal.tool_name}.{proposal.operation}()"),
                memory_ref=redact_sensitive_value(first_mem_ref) if first_mem_ref else None,
                status=item_status,
                details=safe_details,
                duration_ms=execution.duration_ms if execution else None,
                operation=proposal.operation,
                policy_decision=decision.decision if decision else None,
                approval_status=approval.status if approval else None,
                execution_status=exec_status,
            )
        )

    # Process and detect orphan spans and cycles safely
    known_span_ids = {s.id for s in aggregate.spans}
    orphan_count = 0
    cycle_detected = False

    span_parent_map = {s.id: s.parent_span_id for s in aggregate.spans if s.parent_span_id}
    for s_id in span_parent_map:
        curr = s_id
        visited_in_path = set()
        while curr in span_parent_map:
            visited_in_path.add(curr)
            parent = span_parent_map[curr]
            if parent in visited_in_path:
                cycle_detected = True
                break
            curr = parent
        if cycle_detected:
            break

    for span in aggregate.spans:
        if span.parent_span_id and span.parent_span_id not in known_span_ids:
            orphan_count += 1

        metadata = span.metadata_json or {}
        agent_id = metadata.get("agent_id", aggregate.agent_id or "unknown")
        agent_name = aggregate.agent_names.get(
            agent_id, metadata.get("agent_name", "AMSC Execution Agent")
        )

        safe_details = redact_sensitive_dict(metadata)
        raw_status = str(metadata.get("status", "OK")).upper()
        item_status = raw_status if raw_status in ("OK", "TAINTED", "BLOCKED", "INTERCEPTED") else "OK"

        items.append(
            ExecutionLaneItem(
                id=span.id,
                trace_id=span.trace_id,
                timestamp=span.created_at,
                time_display=span.created_at.strftime("%H:%M:%S"),
                agent_id=agent_id,
                agent_name=redact_sensitive_value(agent_name),
                action_label=redact_sensitive_value(span.operation),
                action_detail=redact_sensitive_value(str(metadata.get("detail", span.operation))),
                memory_ref=redact_sensitive_value(metadata.get("memory_ref")) if metadata.get("memory_ref") else None,
                status=item_status,
                details=safe_details,
                duration_ms=span.duration_ms,
                operation=span.operation,
            )
        )

    if orphan_count > 0:
        warnings.append(
            f"Trace contains {orphan_count} orphan span(s) whose parent telemetry was not received."
        )
    if cycle_detected:
        warnings.append("Trace contains cyclical span parent relationships.")

    # Sort deterministically by timestamp
    items.sort(key=lambda x: x.timestamp)
    return items


def build_memory_lane(
    aggregate: DualTraceAggregate,
    warnings: List[str],
) -> List[MemoryLaneItem]:
    """Assemble memory lane items from retrieval events and memory records."""
    items: List[MemoryLaneItem] = []
    unrecorded_historical_count = 0

    for event, record, version, source in aggregate.retrievals:
        time_display = event.occurred_at.strftime("%H:%M:%S")

        # Disclosure of historical trust limitation (GAP-035)
        # RetrievalEvent schema currently does not store immutable trust_state or checksum at retrieval time.
        historical_state = "UNRECORDED"
        unrecorded_historical_count += 1

        current_trust = record.trust_state if record else "NOT_FOUND"
        checksum = version.checksum if version else "UNKNOWN"
        version_num = record.current_version if record else None
        source_uri = source.uri if source else None

        # Format truthful trust label without falsely asserting current state was retrieval state
        trust_display = f"UNKNOWN (CURRENT: {current_trust})"

        label = f"Memory Record: {event.record_id}"

        # Safe redacted query text summary (never return raw unvalidated query text)
        safe_query_summary = "[QUERY RECORDED]" if event.query_text else None

        items.append(
            MemoryLaneItem(
                id=event.id,
                record_id=event.record_id,
                timestamp=event.occurred_at,
                time_display=time_display,
                label=redact_sensitive_value(label),
                trust_state=trust_display,
                historical_trust_state=historical_state,
                current_trust_state=current_trust,
                checksum=checksum,
                version=version_num,
                source_uri=redact_sensitive_value(source_uri) if source_uri else None,
                query_text_redacted=safe_query_summary,
            )
        )

    if unrecorded_historical_count > 0:
        warnings.append(
            f"Historical trust state was not recorded at retrieval time for {unrecorded_historical_count} memory event(s). Showing verified current state."
        )

    if not items:
        warnings.append("No memory retrieval events recorded for this trace context.")

    items.sort(key=lambda x: x.timestamp)
    return items


# ============================================================================
# Router Endpoints
# ============================================================================

router = APIRouter(prefix="/traces", tags=["Observability & Dual Trace"])


@router.get(
    "/{id}/dual-trace",
    response_model=DualTraceResponse,
    summary="Get Dual Trace Correlation Telemetry",
    description=(
        "Fetch correlated execution and memory telemetry for a given trace ID. "
        "Strictly scoped to the caller's authenticated tenant. "
        "Redacts sensitive parameters and truth-labels historical memory evidence."
    ),
    responses={
        200: {"description": "Correlated Dual Trace telemetry successfully retrieved."},
        400: {"description": "Invalid trace identifier format."},
        401: {"description": "Unauthenticated access attempt."},
        403: {"description": "Unauthorized role for forensic trace access."},
        404: {"description": "Trace not found in tenant scope."},
        429: {"description": "Rate limit exceeded."},
    },
)
async def get_dual_trace_endpoint(
    id: str,
    context: TenantContextDep,
    request: Request,
    repo: TraceRepositoryProtocol = Depends(get_trace_repository),
) -> DualTraceResponse:
    """Forensic Dual Trace scrubber endpoint."""
    clean_id = validate_trace_id(id)

    # 1. M7 Rate Limiting Protection (60 requests/minute per tenant)
    rate_limiter: RateLimiterProtocol = getattr(
        request.app.state, "rate_limiter", None
    ) or get_default_rate_limiter()
    rate_key = f"rl:traces:{context.tenant_id}:{clean_id}"
    rate_result: RateLimitResult = await rate_limiter.check_rate_limit(
        key=rate_key, max_requests=60, window_seconds=60
    )
    if not rate_result.allowed:
        raise RateLimitExceededError(
            message="Rate limit exceeded for Dual Trace queries.",
            retry_after=rate_result.retry_after,
        )

    # 2. Query repository with strict tenant filtering
    aggregate = await repo.get_dual_trace(
        tenant_id=context.tenant_id,
        trace_id=clean_id,
        max_spans=MAX_SPANS_LIMIT,
        max_memory_events=MAX_MEMORY_EVENTS_LIMIT,
    )
    if not aggregate:
        raise NotFoundError(f"Trace '{clean_id}' not found.")

    # 3. Assemble lanes and warnings
    warnings: List[str] = []
    execution_lane = build_execution_lane(aggregate, warnings)
    memory_lane = build_memory_lane(aggregate, warnings)

    # Defensively bound response lane sizes
    exec_truncated = False
    if len(execution_lane) > MAX_SPANS_LIMIT:
        execution_lane = execution_lane[:MAX_SPANS_LIMIT]
        exec_truncated = True

    mem_truncated = False
    if len(memory_lane) > MAX_MEMORY_EVENTS_LIMIT:
        memory_lane = memory_lane[:MAX_MEMORY_EVENTS_LIMIT]
        mem_truncated = True

    is_truncated = aggregate.truncated or exec_truncated or mem_truncated
    if is_truncated and not any("truncated" in w.lower() for w in warnings):
        warnings.append(
            f"Telemetry payload exceeded bounds ({MAX_SPANS_LIMIT} spans / {MAX_MEMORY_EVENTS_LIMIT} memory events) and was truncated."
        )

    # 4. Assess completeness truthfully
    if is_truncated and (exec_truncated or len(execution_lane) >= MAX_SPANS_LIMIT):
        exec_comp = "TRUNCATED"
    elif not execution_lane:
        exec_comp = "EMPTY"
    else:
        exec_comp = "COMPLETE"

    if is_truncated and (mem_truncated or len(memory_lane) >= MAX_MEMORY_EVENTS_LIMIT):
        mem_comp = "TRUNCATED"
    elif not memory_lane:
        mem_comp = "EMPTY"
    elif any(m.historical_trust_state == "UNRECORDED" for m in memory_lane):
        mem_comp = "PARTIAL"
    else:
        mem_comp = "COMPLETE"

    completeness = CompletenessReport(execution=exec_comp, memory=mem_comp)

    logger.info(
        "Dual trace telemetry retrieved",
        extra={
            "tenant_id": context.tenant_id,
            "trace_id": clean_id,
            "actor_id": context.user_id,
        },
    )

    return DualTraceResponse(
        trace_id=aggregate.trace_id,
        status=aggregate.status,
        started_at=aggregate.started_at,
        execution_lane=execution_lane,
        memory_lane=memory_lane,
        execution_spans=execution_lane,  # M5 frontend compatibility
        memory_spans=memory_lane,        # M5 frontend compatibility
        completeness=completeness,
        warnings=warnings,
        truncated=is_truncated,
    )


@router.get(
    "",
    response_model=TraceListResponse,
    summary="List Recent Traces",
    description="List recent trace identifiers for the authenticated tenant with bounded pagination.",
)
async def list_traces_endpoint(
    context: TenantContextDep,
    agent_id: Optional[str] = Query(None, description="Filter traces by agent ID"),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Number of traces to return"),
    offset: int = Query(0, ge=0, le=MAX_OFFSET, description="Offset for pagination (0-10000)"),
    repo: TraceRepositoryProtocol = Depends(get_trace_repository),
) -> TraceListResponse:
    """Paginated trace listing for selection and navigation."""
    items, total = await repo.list_traces(
        tenant_id=context.tenant_id,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return TraceListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )
