"""Containment API endpoints.

Module: backend.app.api.containment
Owner: M4 — Security Engine & Incident Response Lead

Implements containment API endpoints for incidents.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.app.core.dependencies import get_tenant_context
from fastapi import Request
from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.security.containment import (
    ContainmentAction,
    ContainmentOutcome,
    ContainmentReasonCode,
    ContainmentRequest,
    ContainmentService,
    ContainmentStatus,
    ContainmentType,
    raise_for_containment_outcome,
)
from backend.app.security.investigation import InvestigationService
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.containment")

router = APIRouter(prefix="/security/containment", tags=["security"])


@router.post("/apply", status_code=status.HTTP_200_OK, response_model=None)
async def apply_containment(
    request: ContainmentRequest,
    http_request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> ContainmentOutcome:
    from backend.app.security.runtime import get_quarantine_workflow, get_audit_sink
    from backend.app.api.memory import get_repository as get_memory_repository
    from backend.app.api.agents import get_agent_repository
    mem_repo = get_memory_repository(http_request) if http_request is not None else None
    from backend.app.api.incident_management import get_incident_repository
    inc_repo = await get_incident_repository(http_request) if http_request is not None else None
    agent_repo = get_agent_repository(http_request) if http_request is not None else None
    inv_svc = InvestigationService(mem_repo, inc_repo)
    quarantine_wf = get_quarantine_workflow(http_request.app.state, mem_repo) if http_request is not None else None
    audit_sink = get_audit_sink(http_request.app.state) if http_request is not None else None
    containment_service = ContainmentService(inv_svc, quarantine_wf, mem_repo, agent_repository=agent_repo, audit_sink=audit_sink)

    """Apply containment actions for an incident.

    This endpoint applies containment actions (quarantine, suspension, blocking, etc.)
    for an incident based on the provided request.

    ``response_model=None``: ``ContainmentOutcome`` is an M4 internal dataclass, not a
    public response contract. The serialized body is produced by ``to_audit_details`` at
    the audit sink; the route returns the outcome object and lets FastAPI's default
    serialization handle it.
    """
    try:
        outcome = await containment_service.apply_containment(
            context,
            request,
            persist_evidence=lambda o: _persist_containment_evidence(o),
        )
        raise_for_containment_outcome(outcome)
        return outcome
    except (ForbiddenError, ValidationError, AMSCException, SecurityDependencyError) as exc:
        logger.warning("Containment failed: %s", str(exc))
        raise


@router.post("/recommendations", status_code=status.HTTP_200_OK, response_model=None)
async def get_containment_recommendations(
    incident_id: str,
    http_request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Tuple[ContainmentAction, ...]:
    from backend.app.api.memory import get_repository as get_memory_repository
    from backend.app.api.incident_management import get_incident_repository
    mem_repo = get_memory_repository(http_request) if http_request is not None else None
    inc_repo = await get_incident_repository(http_request) if http_request is not None else None
    investigation_service = InvestigationService(mem_repo, inc_repo)
    """Get containment recommendations for an incident.

    This endpoint generates containment recommendations based on investigation findings.

    ``response_model=None``: ``ContainmentAction`` is an M4 internal dataclass, not a
    public response contract.
    """
    try:
        recommendations = await investigation_service.generate_containment_recommendations(context, incident_id)
        return recommendations
    except (ForbiddenError, ValidationError, AMSCException, SecurityDependencyError) as exc:
        logger.warning("Failed to generate containment recommendations: %s", str(exc))
        raise


async def _persist_containment_evidence(outcome: ContainmentOutcome) -> None:
    """Persist containment evidence to audit logs."""
    logger.info("Containment evidence persisted: %s", outcome.outcome_id)


__all__ = ["router"]