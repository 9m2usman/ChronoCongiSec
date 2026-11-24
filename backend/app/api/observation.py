"""Observation and Telemetry API Endpoints (Phase 1 §3 & §4).

Provides a consistent, tenant-isolated observation foundation for AI agent activity:
- Captures all 10 Phase 1 observation event categories
- Enforces strict secret & credential scrubbing
- Guarantees idempotent event ingestion and duplicate protection
- Correlates with W3C traceparent headers across Gateway and agent adapters
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from backend.app.api.traces import redact_sensitive_dict
from backend.app.core.dependencies import SettingsDep, TenantContextDep
from backend.app.core.exceptions import NotFoundError, SecurityDependencyError, ValidationError
from backend.app.database.models.baseline import OBSERVATION_CATEGORIES
from backend.app.database.repositories.observation import (
    InMemoryObservationRepository,
    ObservationRepositoryProtocol,
    SqlAlchemyObservationRepository,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.observation")
router = APIRouter(prefix="/observation", tags=["Observation & Telemetry"])

SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

_default_observation_repo: Optional[ObservationRepositoryProtocol] = None


def get_default_observation_repository() -> ObservationRepositoryProtocol:
    global _default_observation_repo
    if _default_observation_repo is None:
        _default_observation_repo = InMemoryObservationRepository()
    return _default_observation_repo


async def get_observation_repo(
    request: Request,
    settings: SettingsDep,
) -> ObservationRepositoryProtocol:
    repo = getattr(request.app.state, "observation_repo", None)
    if repo is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            repo = SqlAlchemyObservationRepository(session_factory)
            request.app.state.observation_repo = repo

    if repo is not None:
        if settings.APP_ENV == "production":
            if getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
                raise SecurityDependencyError("Production database observation repository is not configured.")
        return repo

    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Production database observation repository is not configured.")

    return get_default_observation_repository()


ObservationRepoDep = Depends(get_observation_repo)


# ============================================================================
# DTOs
# ============================================================================

class ObservationEventCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., min_length=1, max_length=64, description="Specific event type")
    event_category: str = Field(..., description="One of the 10 canonical Phase 1 observation categories")
    agent_id: Optional[str] = Field(None, max_length=64, description="Agent identifier")
    agent_runtime: Optional[str] = Field(None, max_length=64, description="Agent execution runtime")
    execution_id: Optional[str] = Field(None, max_length=128, description="Execution run or task ID")
    trace_id: Optional[str] = Field(None, max_length=128, description="W3C trace context ID")
    parent_span_id: Optional[str] = Field(None, max_length=128, description="Parent span ID")
    source_component: str = Field(default="GATEWAY", max_length=64, description="Originating component")
    related_memory_id: Optional[str] = Field(None, max_length=64, description="Referenced memory ID")
    related_memory_version: Optional[int] = Field(None, ge=1, description="Referenced memory version")
    tool_name: Optional[str] = Field(None, max_length=128, description="Tool invoked or proposed")
    action_id: Optional[str] = Field(None, max_length=128, description="Unique tool proposal action ID")
    policy_decision_id: Optional[str] = Field(None, max_length=128, description="Gateway policy decision reference")
    execution_receipt_id: Optional[str] = Field(None, max_length=128, description="Tool execution receipt ID")
    baseline_version: Optional[str] = Field(None, max_length=32, description="Active enterprise baseline version")
    outcome: str = Field(default="SUCCESS", max_length=32, description="Event outcome (SUCCESS, FAILURE, ALLOW, BLOCK)")
    idempotency_key: Optional[str] = Field(None, max_length=128, description="Unique key for duplicate event protection")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event metadata (will be scrubbed)")

    @field_validator("event_category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        if v not in OBSERVATION_CATEGORIES:
            raise ValueError(f"Invalid event category '{v}'. Must be one of: {', '.join(OBSERVATION_CATEGORIES)}")
        return v


class ObservationEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    branch_id: Optional[str] = None
    event_type: str
    event_category: str
    agent_id: Optional[str] = None
    agent_runtime: Optional[str] = None
    execution_id: Optional[str] = None
    trace_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    source_component: str
    related_memory_id: Optional[str] = None
    related_memory_version: Optional[int] = None
    tool_name: Optional[str] = None
    action_id: Optional[str] = None
    policy_decision_id: Optional[str] = None
    execution_receipt_id: Optional[str] = None
    baseline_version: Optional[str] = None
    outcome: str
    idempotency_key: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices("payload", "payload_json"))
    occurred_at: Optional[str] = None
    created_at: Optional[str] = Field(None, validation_alias=AliasChoices("created_at", "occurred_at"))


class ObservationEventListEnvelope(BaseModel):
    items: List[ObservationEventResponse]
    limit: int
    offset: int
    has_more: bool


# ============================================================================
# Endpoints
# ============================================================================

@router.post(
    "/events",
    response_model=ObservationEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record Observation Event",
    description="Ingest a structured observation event. Automatically sanitizes sensitive payloads and enforces idempotency deduplication.",
)
async def record_observation_event(
    payload: ObservationEventCreateRequest,
    request: Request,
    tenant_context: TenantContextDep,
    repo: ObservationRepositoryProtocol = ObservationRepoDep,
) -> ObservationEventResponse:
    """Ingest observation event with tenant isolation and secret redaction."""
    # Trace correlation: inherit from request header or payload
    effective_trace_id = payload.trace_id or getattr(request.state, "trace_id", None)
    effective_branch = getattr(tenant_context, "branch_id", None)

    # Secret and credential scrubbing (Phase 1 §3)
    clean_payload = redact_sensitive_dict(payload.payload)

    event_dict = {
        "tenant_id": tenant_context.tenant_id,
        "branch_id": effective_branch,
        "event_type": payload.event_type,
        "event_category": payload.event_category,
        "agent_id": payload.agent_id,
        "agent_runtime": payload.agent_runtime,
        "execution_id": payload.execution_id,
        "trace_id": effective_trace_id,
        "parent_span_id": payload.parent_span_id,
        "source_component": payload.source_component,
        "related_memory_id": payload.related_memory_id,
        "related_memory_version": payload.related_memory_version,
        "tool_name": payload.tool_name,
        "action_id": payload.action_id,
        "policy_decision_id": payload.policy_decision_id,
        "execution_receipt_id": payload.execution_receipt_id,
        "baseline_version": payload.baseline_version,
        "outcome": payload.outcome,
        "idempotency_key": payload.idempotency_key,
        "payload_json": clean_payload,
    }

    try:
        recorded = await repo.record_event(event_dict)
    except Exception as exc:
        logger.error("Failed to persist observation event: %s", exc)
        raise SecurityDependencyError("Failed to persist observation event.") from exc

    return ObservationEventResponse(**recorded)


@router.get(
    "/events",
    response_model=ObservationEventListEnvelope,
    status_code=status.HTTP_200_OK,
    summary="Query Observation Events",
    description="Query structured observation events scoped to the authenticated tenant and optional branch.",
)
async def query_observation_events(
    tenant_context: TenantContextDep,
    event_category: Optional[str] = Query(None, description="Filter by event category"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    trace_id: Optional[str] = Query(None, description="Filter by trace identifier"),
    branch_id: Optional[str] = Query(None, description="Filter by branch identifier"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    repo: ObservationRepositoryProtocol = ObservationRepoDep,
) -> ObservationEventListEnvelope:
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    effective_branch = user_branch or branch_id

    items, has_more = await repo.list_events(
        tenant_id=tenant_context.tenant_id,
        event_category=event_category,
        event_type=event_type,
        agent_id=agent_id,
        trace_id=trace_id,
        branch_id=effective_branch,
        limit=limit,
        offset=offset,
    )

    return ObservationEventListEnvelope(
        items=[ObservationEventResponse(**e) for e in items],
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.get(
    "/events/{event_id}",
    response_model=ObservationEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Observation Event Detail",
    description="Fetch single observation event by ID under strict tenant isolation.",
)
async def get_observation_event_detail(
    event_id: str,
    tenant_context: TenantContextDep,
    repo: ObservationRepositoryProtocol = ObservationRepoDep,
) -> ObservationEventResponse:
    if not event_id or not SAFE_ID_REGEX.match(event_id.strip()):
        raise NotFoundError("Observation event not found.")
    clean_id = event_id.strip()

    event = await repo.get_event(tenant_context.tenant_id, clean_id)
    if event is None:
        raise NotFoundError("Observation event not found.")

    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    if user_branch and event.get("branch_id") and event["branch_id"] != user_branch:
        raise NotFoundError("Observation event not found.")

    return ObservationEventResponse(**event)
