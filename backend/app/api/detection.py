"""FastAPI Router for Phase 2 Detection & Action Security Endpoints.

Module: backend.app.api.detection
Owner: AMSC Enterprise Security & Architecture Council

Routes:
- GET  /api/v1/detection/results                (Query detection findings with branch/category filtering)
- GET  /api/v1/detection/results/{detection_id} (Retrieve detailed detection record with evidence)
- POST /api/v1/detection/evaluate               (Ad-hoc evaluation of memory, claims, behavior, or proposals)
- POST /api/v1/detection/results/{id}/review    (Security analyst review and triage lifecycle transition)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.config import get_settings
from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import ForbiddenError, NotFoundError, SecurityDependencyError, ValidationError
from backend.app.database.repositories.detection import (
    DetectionRepositoryProtocol,
    SqlAlchemyDetectionRepository,
    get_default_detection_repository,
)
from backend.app.security.authorization import Role
from backend.app.security.detection import (
    DetectionEngine,
    DetectionResult,
    EvaluateDetectionRequest,
    EvaluateDetectionResponse,
)
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/detection", tags=["detection"])


class DetectionReviewRequest(BaseModel):
    """Payload for analyst review of a detection finding."""
    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Target status (CONFIRMED_VIOLATION, CONFIRMED_INCIDENT, DISMISSED_FALSE_POSITIVE, RESOLVED)")
    notes: Optional[str] = Field(None, max_length=1024, description="Analyst review justification")


async def get_detection_repository(request: Request) -> DetectionRepositoryProtocol:
    """Dependency to retrieve configured detection repository."""
    repo = getattr(request.app.state, "detection_repo", None)
    if repo is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            repo = SqlAlchemyDetectionRepository(session_factory)
            request.app.state.detection_repo = repo
        else:
            repo = get_default_detection_repository()
            request.app.state.detection_repo = repo

    settings = getattr(request.app.state, "settings", None) or get_settings()
    if settings.APP_ENV == "production" and (repo is None or getattr(repo, "is_in_memory", True)):
        raise SecurityDependencyError("Production persistent detection repository is not configured.")

    return repo


async def get_detection_engine(request: Request) -> DetectionEngine:
    """Dependency to retrieve configured detection engine."""
    engine = getattr(request.app.state, "detection_engine", None)
    if engine is None:
        det_repo = await get_detection_repository(request)
        base_repo = getattr(request.app.state, "baseline_repo", None)
        agent_repo = getattr(request.app.state, "agent_repo", None)
        engine = DetectionEngine(
            detection_repo=det_repo,
            baseline_repo=base_repo,
            agent_repo=agent_repo,
        )
        request.app.state.detection_engine = engine
    return engine


@router.get(
    "/results",
    response_model=List[DetectionResult],
    summary="List Detection Findings",
    description="Retrieve detection results filtered by tenant, branch, category, severity, and status.",
)
async def list_detections(
    request: Request,
    category: Optional[str] = Query(None, description="Detection category filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    status_filter: Optional[str] = Query(None, alias="status", description="Detection lifecycle status"),
    classification_type: Optional[str] = Query(None, description="Classification type filter"),
    agent_id: Optional[str] = Query(None, description="Associated agent ID"),
    trace_id: Optional[str] = Query(None, description="W3C / correlation trace ID"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    context: TenantContext = Depends(get_tenant_context),
    repo: DetectionRepositoryProtocol = Depends(get_detection_repository),
) -> List[DetectionResult]:
    branch_id = context.branch_id if getattr(context, "role", None) != Role.TENANT_ADMIN else None

    raw_items = await repo.list_detections(
        tenant_id=context.tenant_id,
        branch_id=branch_id,
        category=category,
        severity=severity,
        status=status_filter,
        classification_type=classification_type,
        agent_id=agent_id,
        trace_id=trace_id,
        limit=limit,
        offset=offset,
    )
    return [DetectionResult(**item) for item in raw_items]


@router.get(
    "/results/{detection_id}",
    response_model=DetectionResult,
    summary="Get Detection Detail",
    description="Retrieve a single detection finding by ID with full evidence items.",
)
async def get_detection(
    detection_id: str,
    context: TenantContext = Depends(get_tenant_context),
    repo: DetectionRepositoryProtocol = Depends(get_detection_repository),
) -> DetectionResult:
    branch_id = context.branch_id if getattr(context, "role", None) != Role.TENANT_ADMIN else None
    item = await repo.get_detection(detection_id, context.tenant_id, branch_id)
    if item is None:
        raise NotFoundError(f"Detection finding '{detection_id}' not found.")
    return DetectionResult(**item)


@router.post(
    "/evaluate",
    response_model=EvaluateDetectionResponse,
    summary="Ad-Hoc Security Detection Evaluation",
    description="Run on-demand detection analysis across memory, claims, behavior, or tool proposals.",
)
async def evaluate_detection(
    body: EvaluateDetectionRequest,
    context: TenantContext = Depends(get_tenant_context),
    engine: DetectionEngine = Depends(get_detection_engine),
) -> EvaluateDetectionResponse:
    # Derive branch if not specified
    if not body.branch_id and context.branch_id:
        body.branch_id = context.branch_id

    return await engine.evaluate_all(
        tenant_id=context.tenant_id,
        request=body,
    )


@router.post(
    "/results/{detection_id}/review",
    response_model=DetectionResult,
    summary="Review and Triage Detection Finding",
    description="Transition detection status after security analyst investigation.",
)
async def review_detection(
    detection_id: str,
    body: DetectionReviewRequest,
    context: TenantContext = Depends(get_tenant_context),
    repo: DetectionRepositoryProtocol = Depends(get_detection_repository),
) -> DetectionResult:
    # Role gate: only security analyst or tenant admin can review findings
    role = getattr(context, "role", None)
    if role not in (Role.SECURITY_ANALYST, Role.TENANT_ADMIN, Role.SECURITY_ANALYST.value, Role.TENANT_ADMIN.value):
        raise ForbiddenError("Only SECURITY_ANALYST or TENANT_ADMIN can review detection findings.")

    valid_statuses = ("CONFIRMED_VIOLATION", "CONFIRMED_INCIDENT", "DISMISSED_FALSE_POSITIVE", "RESOLVED")
    if body.status not in valid_statuses:
        raise ValidationError(f"Invalid review status: '{body.status}'. Expected one of: {valid_statuses}")

    updated = await repo.update_detection_status(
        detection_id=detection_id,
        tenant_id=context.tenant_id,
        new_status=body.status,
        reviewer_user_id=context.user_id,
        notes=body.notes,
    )
    if updated is None:
        raise NotFoundError(f"Detection finding '{detection_id}' not found.")
    return DetectionResult(**updated)
