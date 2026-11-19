"""Drift Monitor API (Doc 05 §5.1 route catalog; Doc 04 Screen 08).

Module: backend.app.api.drift
Owner: M4 — Security Engine & Incident Response Lead (Doc 06 Day 6 deliverable ``api/drift.py``)

Routes (canonical; no additional public routes are introduced):

    GET  /drift/observations                 any authenticated member of the tenant
    POST /drift/observations/{id}/review     SECURITY_ANALYST or TENANT_ADMIN

Scoring is not a separate route: every observation in both responses carries its
deterministic ``assessment`` (``backend.app.security.drift.assess_observation``).

Wiring (M1, ``main.py``)::

    from backend.app.api.drift import router as drift_router
    from backend.app.security.drift import DriftReviewService, SqlDriftReviewStore
    app.state.drift_service = DriftReviewService(SqlDriftReviewStore(session_factory))
    api_router.include_router(drift_router)

If ``app.state.drift_service`` is not configured, every route returns 503 (fail closed).
"""

from datetime import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict

from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import SecurityDependencyError, get_trace_context
from backend.app.security.authorization import Role, require_role_access
from backend.app.security.drift import (
    DriftAssessment,
    DriftClassification,
    DriftObservationView,
    DriftReviewService,
    ReviewerStatus,
)
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/drift", tags=["drift"])


class DriftAssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid_evidence: bool
    score: Optional[str]
    classification: Optional[str]
    exceeds_review_threshold: Optional[bool]
    review_threshold: str
    priority: str
    reason_codes: List[str]
    scoring_policy_version: str
    is_verdict: bool


class DriftObservationResponse(BaseModel):
    """Canonical ``drift_observations`` fields plus the M4 assessment. No invented fields."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    record_id: str
    classification: str
    divergence_score: str
    evidence_summary: str
    reviewer_status: str
    created_at: Optional[datetime]
    assessment: DriftAssessmentResponse


class DriftReviewRequest(BaseModel):
    """Doc 05 §5.1: ``{status}``. Tenant, actor and role come only from the verified context."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["APPROVED", "REJECTED"]


class DriftReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: str                    # APPLIED | UNCHANGED
    previous_status: str
    observation: DriftObservationResponse
    audit_event_id: Optional[str]
    follow_up: str                  # QUARANTINE_DECISION_REQUIRED | NO_TRUST_CHANGE (advisory)
    policy_version: str


def _service(request: Request) -> DriftReviewService:
    service = getattr(request.app.state, "drift_service", None)
    if not isinstance(service, DriftReviewService):
        raise SecurityDependencyError("Drift review service is not configured.")
    return service


def _to_response(view: DriftObservationView, assessment: DriftAssessment) -> DriftObservationResponse:
    return DriftObservationResponse(
        id=view.id, tenant_id=view.tenant_id, record_id=view.record_id, classification=view.classification,
        divergence_score=view.divergence_score, evidence_summary=view.evidence_summary,
        reviewer_status=view.reviewer_status, created_at=view.created_at,
        assessment=DriftAssessmentResponse(**assessment.to_dict()),
    )


@router.get(
    "/observations",
    response_model=List[DriftObservationResponse],
    status_code=status.HTTP_200_OK,
    summary="List drift observations with deterministic triage assessment",
)
async def list_drift_observations(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    classification: Optional[DriftClassification] = Query(None),
    reviewer_status: Optional[ReviewerStatus] = Query(None),
    context: TenantContext = Depends(get_tenant_context),
) -> List[DriftObservationResponse]:
    service = _service(request)
    rows = await service.list_observations(
        context, limit=limit, offset=offset,
        classification=classification.value if classification else None,
        reviewer_status=reviewer_status.value if reviewer_status else None,
    )
    return [_to_response(view, assessment) for view, assessment in rows]


@router.post(
    "/observations/{observation_id}/review",
    response_model=DriftReviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Record an analyst review decision for a drift observation (audited)",
)
async def review_drift_observation(
    request: Request,
    payload: DriftReviewRequest,
    observation_id: str = Path(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:\-]{1,128}$"),
    context: TenantContext = Depends(require_role_access(Role.SECURITY_ANALYST, Role.TENANT_ADMIN)),
) -> DriftReviewResponse:
    service = _service(request)
    _, trace_id = get_trace_context(request)
    outcome = await service.review(context, observation_id, payload.status, trace_id=trace_id)
    return DriftReviewResponse(
        outcome=outcome.kind.value,
        previous_status=outcome.previous_status,
        observation=_to_response(outcome.observation, outcome.assessment),
        audit_event_id=outcome.audit_event_id,
        follow_up=outcome.follow_up,
        policy_version=outcome.policy_version,
    )
