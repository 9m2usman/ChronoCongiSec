"""Recovery API (Doc 05 §6.3, Doc 03 §10).

Module: backend.app.api.recovery
Owner: M4 — Security Engine & Incident Response Lead (``backend/owner.md``: ``api/recovery.py``)

Routes:

    POST /recovery/plans/preview      SECURITY_ANALYST or TENANT_ADMIN   (records a PREVIEWED plan)
    POST /recovery/plans/execute      SECURITY_ANALYST or TENANT_ADMIN   body: {"plan_id": ...}
    GET  /recovery/plans/{plan_id}    any canonical role (incl. read-only AUDITOR)

Status codes never report success unless every post-condition held:

    200  EXECUTED                     rollback committed, restored records UNVERIFIED, audited
    409  plan stale / already executed / not executable (nothing changed; preview again)
    500  RECONCILIATION_REQUIRED      rollback committed but a later step failed (records restricted)
    503  FAILED                       nothing rolled back (snapshot, containment, rollback or store failure)

Wiring (M1, ``main.py``) once the ports exist (see docs/security-design/m4-integration-contracts.md)::

    from backend.app.api.recovery import router as recovery_router
    app.state.recovery_service = RecoveryService(trust=..., memory=..., checkpoints=..., plans=...,
                                                 rewind=RewindCoordinator(session_factory), ...)
    api_router.include_router(recovery_router)

Without ``app.state.recovery_service`` every route returns 503 (fail closed).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Path, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.recovery.orchestrator import RecoveryPreviewRequest, RecoveryReason, RecoveryService, RecoveryStatus
from backend.app.security.authorization import READER_ROLES, SECURITY_OPERATOR_ROLES, require_role_access
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/recovery", tags=["recovery"])

_PLAN_STATE_REASONS = {RecoveryReason.PLAN_STALE.value, RecoveryReason.PLAN_ALREADY_EXECUTED.value,
                       RecoveryReason.PLAN_NOT_EXECUTABLE.value}


class RecoveryExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    plan_id: str = Field(pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")


class RecoveryPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    status: str
    checkpoint_id: str
    target_record_id: str
    incident_id: Optional[str]
    snapshot_captured: bool
    impact_preview: Dict[str, Any]


def _service(request: Request) -> RecoveryService:
    service = getattr(request.app.state, "recovery_service", None)
    if not isinstance(service, RecoveryService):
        raise SecurityDependencyError("Recovery service is not configured.")
    return service


@router.post("/plans/preview", status_code=status.HTTP_200_OK,
             summary="Preview a checkpoint rollback (blast radius, irreversible actions); records a PREVIEWED plan")
async def preview_recovery(
    request: Request,
    payload: RecoveryPreviewRequest,
    context: TenantContext = Depends(require_role_access(*SECURITY_OPERATOR_ROLES)),
) -> Dict[str, Any]:
    preview = await _service(request).preview(context, payload)
    return preview.to_dict()


@router.post("/plans/execute", summary="Execute a previewed recovery plan (snapshot, contain, roll back, audit)")
async def execute_recovery(
    request: Request,
    payload: RecoveryExecuteRequest,
    context: TenantContext = Depends(require_role_access(*SECURITY_OPERATOR_ROLES)),
) -> JSONResponse:
    outcome = await _service(request).execute(context, payload.plan_id)
    if outcome.status is RecoveryStatus.EXECUTED:
        code = status.HTTP_200_OK
    elif outcome.status is RecoveryStatus.RECONCILIATION_REQUIRED:
        code = status.HTTP_500_INTERNAL_SERVER_ERROR
    elif set(outcome.reason_codes) & _PLAN_STATE_REASONS:
        code = status.HTTP_409_CONFLICT
    else:
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    body: Dict[str, Any] = {
        "plan_id": outcome.plan_id, "status": outcome.status.value, "success": outcome.success,
        "reason_codes": list(outcome.reason_codes),
        "restored_records_count": len(outcome.restored_record_ids),
        "restored_record_ids": list(outcome.restored_record_ids),
        "quarantined_intermediary_ids": list(outcome.quarantined_intermediary_ids),
        "irreversible_external_actions": outcome.irreversible_external_actions,
        "restored_records_trust_state": "UNVERIFIED" if outcome.success else None,
    }
    return JSONResponse(status_code=code, content=body)


@router.get("/plans/{plan_id}", response_model=RecoveryPlanResponse, summary="Read a recovery plan")
async def get_recovery_plan(
    request: Request,
    plan_id: str = Path(..., pattern=r"^[A-Za-z0-9_.:\-]{1,128}$"),
    context: TenantContext = Depends(require_role_access(*READER_ROLES)),
) -> RecoveryPlanResponse:
    plan = await _service(request).get_plan(context, plan_id)
    return RecoveryPlanResponse(plan_id=plan.id, status=plan.status, checkpoint_id=plan.checkpoint_id,
                                target_record_id=plan.target_record_id, incident_id=plan.incident_id,
                                snapshot_captured=plan.snapshot_sha256 is not None,
                                impact_preview=dict(plan.impact_preview))


__all__: List[str] = ["router"]
