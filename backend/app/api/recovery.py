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

from fastapi import APIRouter, Body, Depends, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import SecurityDependencyError, ValidationError
from backend.app.recovery.orchestrator import RecoveryPreviewRequest, RecoveryReason, RecoveryService, RecoveryStatus
from backend.app.security.authorization import READER_ROLES, SECURITY_OPERATOR_ROLES, require_role_access
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/recovery", tags=["recovery"])

_MESSAGES = {
    RecoveryStatus.EXECUTED: "Rollback committed. Restored records are UNVERIFIED and must be re-validated before use.",
    RecoveryStatus.RECONCILIATION_REQUIRED: "Rollback committed but a follow-up step failed; records remain restricted. "
                                            "Reconciliation is required.",
    RecoveryStatus.FAILED: "Recovery was not executed. No memory content was changed.",
}

_PLAN_STATE_REASONS = {RecoveryReason.PLAN_STALE.value, RecoveryReason.PLAN_ALREADY_EXECUTED.value,
                       RecoveryReason.PLAN_NOT_EXECUTABLE.value}


class RecoveryExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    plan_id: str = Field(pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")
    # Doc 05 client flag. The pre-recovery snapshot is always captured; an explicit false is refused
    # rather than silently ignored.
    pre_recovery_snapshot_confirmed: bool = True


class RecoveryApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    approval_id: Optional[str] = Field(default=None, max_length=128)
    runtime_cancellation_verified: bool = False


class RecoveryPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    status: str
    checkpoint_id: str
    target_record_id: str
    incident_id: Optional[str]
    snapshot_captured: bool
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    runtime_cancellation_verified: bool = False
    impact_preview: Dict[str, Any]


def _service(request: Request) -> RecoveryService:
    service = getattr(request.app.state, "recovery_service", None)
    if service is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.recovery.store import create_recovery_service
            service = create_recovery_service(session_factory)
            request.app.state.recovery_service = service
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
    if payload.pre_recovery_snapshot_confirmed is not True:
        raise ValidationError("The pre-recovery snapshot is mandatory and cannot be declined.")
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
        "executed_at": outcome.executed_at,
        "restored_records": list(outcome.restored_record_ids),
        "restored_records_count": len(outcome.restored_record_ids),
        "quarantined_intermediary_ids": list(outcome.quarantined_intermediary_ids),
        "irreversible_external_actions": outcome.irreversible_external_actions,
        "audit_event_id": outcome.audit_event_id,
        "postconditions": dict(outcome.postconditions),
        "restored_records_trust_state": "UNVERIFIED" if outcome.success else None,
        "message": _MESSAGES.get(outcome.status, "Recovery did not complete."),
    }
    return JSONResponse(status_code=code, content=body)


@router.post("/plans/{plan_id}/approve", summary="Approve a previewed recovery plan and verify runtime cancellation")
async def approve_recovery_plan(
    request: Request,
    plan_id: str = Path(..., pattern=r"^[A-Za-z0-9_.:\-]{1,128}$"),
    payload: Optional[RecoveryApproveRequest] = Body(default=None),
    context: TenantContext = Depends(require_role_access(*SECURITY_OPERATOR_ROLES)),
) -> Dict[str, Any]:
    req = payload or RecoveryApproveRequest()
    cancel_adapter = getattr(request.app.state, "agent_runtime_cancellation", None)
    plan = await _service(request).approve_plan(
        context,
        plan_id,
        approval_id=req.approval_id,
        runtime_cancellation_verified=req.runtime_cancellation_verified,
        runtime_cancellation_adapter=cancel_adapter,
    )
    return {
        "plan_id": plan.id,
        "status": plan.status,
        "approved_by": plan.approved_by,
        "approved_at": plan.approved_at,
        "approval_id": plan.approval_id,
        "runtime_cancellation_verified": plan.runtime_cancellation_verified,
    }


@router.get("/plans/{plan_id}", response_model=RecoveryPlanResponse, summary="Read a recovery plan")
async def get_recovery_plan(
    request: Request,
    plan_id: str = Path(..., pattern=r"^[A-Za-z0-9_.:\-]{1,128}$"),
    context: TenantContext = Depends(require_role_access(*READER_ROLES)),
) -> RecoveryPlanResponse:
    plan = await _service(request).get_plan(context, plan_id)
    return RecoveryPlanResponse(
        plan_id=plan.id,
        status=plan.status,
        checkpoint_id=plan.checkpoint_id,
        target_record_id=plan.target_record_id,
        incident_id=plan.incident_id,
        snapshot_captured=plan.snapshot_sha256 is not None,
        approved_by=plan.approved_by,
        approved_at=plan.approved_at,
        runtime_cancellation_verified=plan.runtime_cancellation_verified,
        impact_preview=dict(plan.impact_preview),
    )


@router.get("/forensics/timeline", summary="Unified forensic timeline across identity, agent, policy, containment, and recovery")
async def get_forensic_timeline(
    request: Request,
    incident_id: Optional[str] = Query(default=None),
    trace_id: Optional[str] = Query(default=None),
    agent_id: Optional[str] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    context: TenantContext = Depends(require_role_access(*READER_ROLES)),
) -> Dict[str, Any]:
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise SecurityDependencyError("Forensic persistence is unavailable.")

    from sqlalchemy import select
    from backend.app.database.models.baseline import ObservationEvent
    from backend.app.database.models.gateway import PolicyDecision
    from backend.app.database.models.observability import AuditEvent
    from backend.app.database.models.recovery import Quarantine, RecoveryAction, RecoveryPlan

    tenant_id = context.tenant_id
    entries: List[Dict[str, Any]] = []

    async with session_factory() as session:
        obs_stmt = select(ObservationEvent).where(ObservationEvent.tenant_id == tenant_id)
        if trace_id:
            obs_stmt = obs_stmt.where(ObservationEvent.trace_id == trace_id)
        if agent_id:
            obs_stmt = obs_stmt.where(ObservationEvent.agent_id == agent_id)
        obs_rows = (await session.execute(obs_stmt.order_by(ObservationEvent.occurred_at.desc()).limit(limit))).scalars().all()
        for o in obs_rows:
            p = o.payload_json or {}
            res_id = p.get("resource_id") or o.action_id
            if resource_id and res_id != resource_id:
                continue
            if incident_id and p.get("incident_id") != incident_id:
                continue
            entries.append({
                "timestamp": o.occurred_at.isoformat(),
                "stage": "CONTAINMENT" if o.event_type in ("COMPANY_RESOURCE_ISOLATED", "AGENT_RUNTIME_CANCELLED") else "OBSERVATION",
                "event_type": o.event_type,
                "who": p.get("actor_id"),
                "agent": o.agent_id,
                "workflow": {"trace_id": o.trace_id, "branch_id": o.branch_id, "source": o.source_component},
                "resource": {"type": p.get("resource_type"), "id": res_id},
                "policy": None,
                "containment": o.outcome if o.event_type in ("COMPANY_RESOURCE_ISOLATED", "AGENT_RUNTIME_CANCELLED") else None,
                "restoration": None,
                "verified_outcome": o.outcome,
            })

        pol_rows = (
            await session.execute(
                select(PolicyDecision).where(PolicyDecision.tenant_id == tenant_id).order_by(PolicyDecision.created_at.desc()).limit(limit)
            )
        ).scalars().all()
        for pd in pol_rows:
            if incident_id and pd.incident_id != incident_id:
                continue
            entries.append({
                "timestamp": pd.created_at.isoformat(),
                "stage": "POLICY",
                "event_type": f"POLICY_{pd.decision}",
                "who": None,
                "agent": None,
                "workflow": {"proposal_id": pd.proposal_id, "decision_id": pd.id, "incident_id": pd.incident_id},
                "resource": None,
                "policy": {"decision": pd.decision, "policy_result": pd.policy_result, "memory_trust": pd.memory_trust, "reasons": pd.reasons_json},
                "containment": None,
                "restoration": None,
                "verified_outcome": pd.execution_status,
            })

        quar_stmt = select(Quarantine).where(Quarantine.tenant_id == tenant_id)
        if incident_id:
            quar_stmt = quar_stmt.where(Quarantine.incident_id == incident_id)
        quar_rows = (await session.execute(quar_stmt.order_by(Quarantine.created_at.desc()).limit(limit))).scalars().all()
        for q in quar_rows:
            if resource_id and q.record_id != resource_id:
                continue
            entries.append({
                "timestamp": q.created_at.isoformat(),
                "stage": "CONTAINMENT",
                "event_type": "QUARANTINE_RECORD",
                "who": q.quarantined_by,
                "agent": None,
                "workflow": {"incident_id": q.incident_id, "quarantine_id": q.id},
                "resource": {"type": "MEMORY_RECORD", "id": q.record_id},
                "policy": None,
                "containment": "QUARANTINED",
                "restoration": None,
                "verified_outcome": "QUARANTINED",
            })

        plan_stmt = select(RecoveryPlan).where(RecoveryPlan.tenant_id == tenant_id)
        if incident_id:
            plan_stmt = plan_stmt.where(RecoveryPlan.incident_id == incident_id)
        plan_rows = (await session.execute(plan_stmt.order_by(RecoveryPlan.executed_at.desc().nullslast()).limit(limit))).scalars().all()
        for pl in plan_rows:
            approval = (pl.impact_preview_json or {}).get("_approval") or {}
            actions = (
                await session.execute(
                    select(RecoveryAction).where(
                        RecoveryAction.tenant_id == tenant_id,
                        RecoveryAction.plan_id == pl.id,
                    )
                )
            ).scalars().all()
            if resource_id and pl.target_record_id != resource_id and not any(a.resource_id == resource_id for a in actions):
                continue
            ts = pl.executed_at.isoformat() if pl.executed_at else (approval.get("approved_at") or "")
            entries.append({
                "timestamp": ts,
                "stage": "RESTORATION",
                "event_type": f"RECOVERY_{pl.status}",
                "who": approval.get("approved_by"),
                "agent": ((pl.impact_preview_json or {}).get("preview") or {}).get("agent_id"),
                "workflow": {
                    "plan_id": pl.id,
                    "checkpoint_id": pl.checkpoint_id,
                    "incident_id": pl.incident_id,
                    "trace_id": ((pl.impact_preview_json or {}).get("preview") or {}).get("trace_id"),
                },
                "resource": {"id": pl.target_record_id, "actions": [{"resource_id": a.resource_id, "action": a.action_taken, "outcome": a.outcome} for a in actions]},
                "policy": {"approval_id": approval.get("approval_id"), "runtime_cancellation_verified": approval.get("runtime_cancellation_verified")},
                "containment": None,
                "restoration": pl.status,
                "verified_outcome": "VERIFIED" if pl.status == "EXECUTED" else pl.status,
            })

        audit_stmt = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        if trace_id:
            audit_stmt = audit_stmt.where(AuditEvent.trace_id == trace_id)
        if resource_id:
            audit_stmt = audit_stmt.where(AuditEvent.resource_id == resource_id)
        audit_rows = (await session.execute(audit_stmt.order_by(AuditEvent.occurred_at.desc()).limit(limit))).scalars().all()
        for a in audit_rows:
            entries.append({
                "timestamp": a.occurred_at.isoformat(),
                "stage": "AUDIT",
                "event_type": a.event_type,
                "who": a.actor_id,
                "agent": (a.details_json or {}).get("agent_id"),
                "workflow": {"trace_id": a.trace_id, "audit_id": a.id},
                "resource": {"id": a.resource_id},
                "policy": None,
                "containment": None,
                "restoration": a.action if "RECOVERY" in a.event_type else None,
                "verified_outcome": a.outcome,
            })

    entries.sort(key=lambda e: e["timestamp"])
    return {"items": entries[:limit], "total": len(entries)}


__all__: List[str] = ["router"]
