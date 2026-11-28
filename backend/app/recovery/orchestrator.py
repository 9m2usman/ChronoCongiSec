"""Recovery orchestration: preview and execute a checkpoint rollback without bypassing trust,
authorization or audit (TRD §18, OD-17, OD-21, OD-23).

Module: backend.app.recovery.orchestrator
Owner: M4 — Security Engine & Incident Response Lead

M4 owns the security semantics of recovery: who may run it, what the plan covers, the order
of operations, the trust outcome and the honest classification of the result. Persistence and
data primitives belong to other members and are reached only through the ports below:

- ``CheckpointReader``     checkpoint + items with content (provider pending: M3 over M6 tables)
- ``RecoveryPlanStore``    recovery_plans rows with compare-and-set status (provider pending: M6)
- ``RewindPort``           M6's ``RewindCoordinator`` (capture_snapshot / execute_rollback) — the
                           real coordinator satisfies this protocol structurally
- ``ExternalActionReader`` tool executions that referenced affected records (pending: M6/M2)
- ``persist_audit``        append to M6's hash-chained audit (caller supplies the transaction)

Order of operations in ``execute`` (each step fails closed):

1. Authorize (SECURITY_ANALYST / TENANT_ADMIN), verified tenant context, per-plan lock.
2. Load the plan; recompute the preview from current state. Any difference (record version,
   state, checksum, checkpoint, scope, external actions) means the plan is stale: refuse.
3. Capture and commit the pre-recovery snapshot (once per plan; reused on retry).
4. Contain: every affected record that is not already QUARANTINED/REJECTED is quarantined
   through M4's trust evaluator. If containment fails, nothing is rolled back.
5. Roll back in one transaction (M6): append the checkpoint content as a NEW version
   (OD-17: never move ``current_version`` backwards), compare-and-set the pointer, record
   RESTORED_TO_CHECKPOINT / QUARANTINED_INTERMEDIARY / EXTERNAL_ACTION_IRREVERSIBLE actions.
6. Restored records: QUARANTINED -> UNVERIFIED via RECOVERY_RESTORE (T-17). Never TRUSTED;
   re-validation is a separate analyst action (VALIDATE with evidence bound to the new version).
7. Verify post-conditions, mark the plan, audit. A post-commit failure is reported as
   RECONCILIATION_REQUIRED, never as success; affected records stay restricted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from backend.app.core.exceptions import ForbiddenError, NotFoundError, SecurityDependencyError, ValidationError
from backend.app.memory import MemoryRepository, get_descendants, sha256_hex
from backend.app.security.audit_identity import user_actor
from backend.app.security.authorization import SECURITY_OPERATOR_ROLES, evaluate_role_access
from backend.app.security.trust import TrustEvaluator, TrustOperation, UserActor
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.recovery.orchestrator")

RECOVERY_POLICY_VERSION = "amsc-recovery/1.0.0"
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,128}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SEP_FIELD, _SEP_ITEM = "\x1e", "\x1f"
MAX_SCOPE_RECORDS = 200          # a larger blast radius is refused, not truncated


# =============================================================================
# 1. Vocabulary (OD-21)
# =============================================================================

class PlanStatus(str, Enum):
    PREVIEWED = "PREVIEWED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"           # rolled back or not started; retryable under the same snapshot


class ActionTaken(str, Enum):
    RESTORED_TO_CHECKPOINT = "RESTORED_TO_CHECKPOINT"
    QUARANTINED_INTERMEDIARY = "QUARANTINED_INTERMEDIARY"
    RESTORED_RECORD_UNVERIFIED = "RESTORED_RECORD_UNVERIFIED"
    EXTERNAL_ACTION_IRREVERSIBLE = "EXTERNAL_ACTION_IRREVERSIBLE"


class RecoveryStatus(str, Enum):
    EXECUTED = "EXECUTED"                                  # every post-condition verified
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"    # rollback committed; a later step failed
    FAILED = "FAILED"                                      # nothing rolled back (records may be contained)


class RecoveryReason(str, Enum):
    PLAN_STALE = "PLAN_STALE"
    PLAN_ALREADY_EXECUTED = "PLAN_ALREADY_EXECUTED"
    PLAN_NOT_EXECUTABLE = "PLAN_NOT_EXECUTABLE"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    RUNTIME_CANCELLATION_REQUIRED = "RUNTIME_CANCELLATION_REQUIRED"
    SNAPSHOT_FAILED = "SNAPSHOT_FAILED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    TRUST_RESTORE_FAILED = "TRUST_RESTORE_FAILED"
    POSTCONDITION_FAILED = "POSTCONDITION_FAILED"
    PLAN_STATUS_NOT_RECORDED = "PLAN_STATUS_NOT_RECORDED"
    AUDIT_FAILED = "AUDIT_FAILED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"


# =============================================================================
# 2. Ports (other members' implementations)
# =============================================================================

@dataclass(frozen=True)
class CheckpointItemView:
    record_id: str
    version: int
    checksum: str
    content: str


@dataclass(frozen=True)
class CheckpointView:
    id: str
    tenant_id: str
    integrity_hash: str
    created_at: datetime
    items: Tuple[CheckpointItemView, ...]
    name: str = ""
    resources: Tuple[Mapping[str, Any], ...] = ()
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None


@dataclass(frozen=True)
class ExternalActionView:
    execution_id: str
    status: str


@dataclass(frozen=True)
class RecoveryPlanRecord:
    id: str
    tenant_id: str
    checkpoint_id: str
    target_record_id: str
    incident_id: Optional[str]
    status: str
    preview_fingerprint: str
    impact_preview: Mapping[str, Any]
    created_by: str
    snapshot_sha256: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    approval_id: Optional[str] = None
    runtime_cancellation_verified: bool = False


class CheckpointReader(Protocol):
    async def get_checkpoint(self, tenant_id: str, checkpoint_id: str) -> Optional[CheckpointView]: ...


class RecoveryPlanStore(Protocol):
    async def create(self, plan: RecoveryPlanRecord) -> None: ...

    async def get(self, tenant_id: str, plan_id: str) -> Optional[RecoveryPlanRecord]: ...

    async def transition(self, tenant_id: str, plan_id: str, *, expected_status: str, new_status: str,
                         snapshot_sha256: Optional[str] = None) -> bool:
        """Compare-and-set the status; True only if the row was in ``expected_status``."""


class RewindPort(Protocol):
    async def capture_snapshot(self, tenant_id: str, plan_id: str, snapshot: Mapping[str, Any]) -> Any: ...

    async def execute_rollback(self, tenant_id: str, plan_id: str, *, expected_snapshot_sha256: str,
                               restore: Callable[[Any], Awaitable[None]]) -> Any: ...


class ExternalActionReader(Protocol):
    async def executions_referencing(self, tenant_id: str, record_ids: Sequence[str],
                                     since: datetime) -> Sequence[ExternalActionView]: ...


PersistAudit = Callable[[Dict[str, Any]], Awaitable[Any]]


# =============================================================================
# 3. Requests and results
# =============================================================================

class RecoveryPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    checkpoint_id: str = Field(pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")
    target_record_id: str = Field(pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")
    incident_id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")
    # Doc 05 §6.3 has no reason field; when supplied it is kept in the audit evidence.
    reason: Optional[str] = Field(default=None, min_length=10, max_length=2000)


@dataclass(frozen=True)
class PlannedRecord:
    record_id: str
    action: str                      # RESTORED_TO_CHECKPOINT | QUARANTINED_INTERMEDIARY | UNCHANGED_REJECTED
    current_version: int
    current_checksum: str
    effective_state: str
    checkpoint_version: Optional[int] = None
    checkpoint_checksum: Optional[str] = None


@dataclass(frozen=True)
class RecoveryPreview:
    plan_id: str
    tenant_id: str
    checkpoint_id: str
    checkpoint_integrity_hash: str
    target_record_id: str
    checkpoint_name: str
    records: Tuple[PlannedRecord, ...]
    irreversible_external_actions: Tuple[ExternalActionView, ...]
    fingerprint: str
    status: str = PlanStatus.PREVIEWED.value
    company_resources: Tuple[Mapping[str, Any], ...] = ()
    agent_id: Optional[str] = None
    trace_id: Optional[str] = None

    @property
    def risk_level(self) -> str:
        """HIGH: irreversible external actions; MEDIUM: intermediaries or several restored; else LOW."""
        if self.irreversible_external_actions:
            return "HIGH"
        restored = sum(1 for r in self.records if r.action == ActionTaken.RESTORED_TO_CHECKPOINT.value)
        if any(r.action == ActionTaken.QUARANTINED_INTERMEDIARY.value for r in self.records) or restored > 1 or len(self.company_resources) > 1:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        """Doc 05 §6.3 response shape; extra fields are additive."""
        data: Dict[str, Any] = {
            "plan_id": self.plan_id,
            "status": self.status,
            "preview": {
                "checkpoint_id": self.checkpoint_id,
                "checkpoint_name": self.checkpoint_name,
                "target_record_id": self.target_record_id,
                "affected_records_count": len(self.records),
                "affected_records": [{
                    "record_id": r.record_id, "action": r.action,
                    "checkpoint_version": r.checkpoint_version, "target_checksum": r.checkpoint_checksum,
                    "current_version": r.current_version, "current_trust_state": r.effective_state,
                } for r in self.records],
                "company_resources": [dict(r) for r in self.company_resources],
                "company_resources_count": len(self.company_resources),
                "agent_id": self.agent_id,
                "trace_id": self.trace_id,
                "requires_human_approval": bool(self.company_resources),
                "requires_runtime_cancellation": bool(self.company_resources and self.agent_id),
                "irreversible_external_actions": len(self.irreversible_external_actions),
                "irreversible_execution_ids": [a.execution_id for a in self.irreversible_external_actions],
                "risk_level": self.risk_level,
                "restored_records_become": "UNVERIFIED",   # never TRUSTED (TRD §18, T-17)
                "policy_version": RECOVERY_POLICY_VERSION,
            },
        }
        return data


@dataclass(frozen=True)
class RecoveryOutcome:
    plan_id: str
    status: RecoveryStatus
    reason_codes: Tuple[str, ...]
    restored_record_ids: Tuple[str, ...] = ()
    quarantined_intermediary_ids: Tuple[str, ...] = ()
    irreversible_external_actions: int = 0
    snapshot_sha256: Optional[str] = None
    postconditions: Mapping[str, Any] = field(default_factory=dict)
    executed_at: Optional[str] = None
    audit_event_id: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.status is RecoveryStatus.EXECUTED


# =============================================================================
# 4. Integrity helpers
# =============================================================================

def checkpoint_integrity_hash(items: Sequence[CheckpointItemView]) -> str:
    """OD-17 combined SHA-256: items ordered by record_id, fields joined with U+001E, items with U+001F."""
    parts = [f"{i.record_id}{_SEP_FIELD}{i.version}{_SEP_FIELD}{i.checksum}"
             for i in sorted(items, key=lambda i: i.record_id)]
    return hashlib.sha256(_SEP_ITEM.join(parts).encode("utf-8")).hexdigest()


def _checkpoint_problem(cp: Any, tenant_id: str) -> Optional[str]:
    if not isinstance(cp, CheckpointView) or cp.tenant_id != tenant_id:
        return "CHECKPOINT_NOT_FOUND"
    has_resources = isinstance(cp.resources, tuple) and len(cp.resources) > 0
    if not isinstance(cp.items, tuple) or (not cp.items and not has_resources):
        return "CHECKPOINT_INTEGRITY_FAILED"
    seen = set()
    for item in cp.items:
        if not isinstance(item, CheckpointItemView) or item.record_id in seen \
                or type(item.version) is not int or item.version < 1 \
                or not isinstance(item.checksum, str) or not _HEX64.fullmatch(item.checksum) \
                or not isinstance(item.content, str) or sha256_hex(item.content) != item.checksum:
            return "CHECKPOINT_INTEGRITY_FAILED"
        seen.add(item.record_id)
    if cp.items and (not isinstance(cp.integrity_hash, str) or checkpoint_integrity_hash(cp.items) != cp.integrity_hash):
        return "CHECKPOINT_INTEGRITY_FAILED"
    if not cp.items and (not isinstance(cp.integrity_hash, str) or not cp.integrity_hash):
        return "CHECKPOINT_INTEGRITY_FAILED"
    return None


def _state(value: Any) -> str:
    return str(getattr(value, "value", value))


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                                 default=str).encode("utf-8")).hexdigest()


# =============================================================================
# 5. Service
# =============================================================================

class RecoveryService:
    def __init__(self, *, trust: TrustEvaluator, memory: MemoryRepository, checkpoints: CheckpointReader,
                 plans: RecoveryPlanStore, rewind: RewindPort, external_actions: ExternalActionReader,
                 persist_audit: PersistAudit,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        if not isinstance(trust, TrustEvaluator):
            raise TypeError("RecoveryService requires M4's TrustEvaluator.")
        for name, port in (("memory", memory), ("checkpoints", checkpoints), ("plans", plans),
                           ("rewind", rewind), ("external_actions", external_actions)):
            if port is None:
                raise TypeError(f"RecoveryService requires the {name} port.")
        if not callable(persist_audit):
            raise TypeError("RecoveryService requires an audit sink.")
        self._trust, self._memory, self._checkpoints = trust, memory, checkpoints
        self._plans, self._rewind, self._external = plans, rewind, external_actions
        self._persist_audit, self._clock = persist_audit, clock
        self._plan_locks: Dict[Tuple[str, str], asyncio.Lock] = {}

    # -- authorization ----------------------------------------------------------

    @staticmethod
    def _authorize(context: Any) -> Tuple[str, str]:
        if not isinstance(context, TenantContext) or context.is_active is not True \
                or type(context.tenant_id) is not str or not context.tenant_id.strip():
            raise ForbiddenError("Recovery requires a verified tenant context.")
        if not evaluate_role_access(context, SECURITY_OPERATOR_ROLES).allowed:
            raise ForbiddenError("Recovery requires SECURITY_ANALYST or TENANT_ADMIN.")
        try:
            actor = user_actor(context.user_id)
        except ValueError as exc:
            raise ForbiddenError("Recovery requires a verified tenant context.") from exc
        return context.tenant_id, actor

    # -- preview ----------------------------------------------------------------

    async def preview(self, context: Optional[TenantContext], request: Any) -> RecoveryPreview:
        tenant_id, actor = self._authorize(context)
        try:
            req = request if isinstance(request, RecoveryPreviewRequest) else \
                RecoveryPreviewRequest.model_validate(dict(request) if isinstance(request, Mapping) else request)
        except (PydanticValidationError, TypeError, ValueError) as exc:
            raise ValidationError("Invalid recovery preview request.") from exc
        plan_id = f"plan-{uuid.uuid4().hex[:24]}"
        preview = await self._build_preview(tenant_id, plan_id, req.checkpoint_id, req.target_record_id)
        record = RecoveryPlanRecord(
            id=plan_id, tenant_id=tenant_id, checkpoint_id=req.checkpoint_id, target_record_id=req.target_record_id,
            incident_id=req.incident_id, status=PlanStatus.PREVIEWED.value, preview_fingerprint=preview.fingerprint,
            impact_preview=preview.to_dict(), created_by=actor,
        )
        try:
            await self._plans.create(record)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Recovery plan create failed")
            raise SecurityDependencyError("Recovery plan could not be recorded.") from exc
        try:
            await self._audit(tenant_id, actor, "RECOVERY_PREVIEWED", plan_id, "PREVIEW", "SUCCESS",
                              {"reason": req.reason, "incident_id": req.incident_id, **preview.to_dict()})
        except SecurityDependencyError:
            await self._safe_transition(tenant_id, plan_id, PlanStatus.PREVIEWED, PlanStatus.FAILED)
            raise
        return preview

    async def _build_preview(self, tenant_id: str, plan_id: str, checkpoint_id: str,
                             target_record_id: str) -> RecoveryPreview:
        try:
            checkpoint = await self._checkpoints.get_checkpoint(tenant_id, checkpoint_id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Checkpoint get_checkpoint failed")
            raise SecurityDependencyError("Checkpoint source unavailable.") from exc
        problem = _checkpoint_problem(checkpoint, tenant_id)
        if problem == "CHECKPOINT_NOT_FOUND" or (problem is None and checkpoint.id != checkpoint_id):
            raise NotFoundError("Recovery target or checkpoint not found.")   # same message as a missing target
        if problem:
            raise ValidationError("Checkpoint integrity verification failed; recovery refused.")

        items = {i.record_id: i for i in checkpoint.items}
        company_resources = tuple(dict(r) for r in (checkpoint.resources or ()))
        company_resource_ids = {str(r.get("resource_id", "")) for r in company_resources if r.get("resource_id")}

        is_company_only = (
            target_record_id not in items
            and (target_record_id in company_resource_ids or target_record_id == checkpoint_id or target_record_id.startswith("company:"))
            and bool(company_resources)
        )

        planned: List[PlannedRecord] = []
        scope: List[str] = []

        if not is_company_only:
            target = self._memory.get_record(target_record_id, tenant_id)
            if target is None or getattr(target, "tenant_id", None) != tenant_id:
                raise NotFoundError("Recovery target or checkpoint not found.")
            if target_record_id not in items:
                raise ValidationError("The recovery target is not part of the selected checkpoint.")

            descendants = get_descendants(tenant_id, target_record_id, repository=self._memory)
            if not getattr(descendants, "complete", False):
                raise ValidationError("Blast radius could not be fully determined; recovery refused.")
            scope = [target_record_id] + [rid for rid, _depth in descendants if rid != target_record_id]
            scope = list(dict.fromkeys(scope))
            if len(scope) > MAX_SCOPE_RECORDS:
                raise ValidationError("Blast radius exceeds the recovery scope limit; recovery refused.")

            for rid in scope:
                rec = self._memory.get_record(rid, tenant_id)
                if rec is None:
                    raise ValidationError("A record in the blast radius is missing; recovery refused.")
                latest = self._memory.get_version(rid, rec.current_version, tenant_id)
                if latest is None or sha256_hex(latest.content) != latest.checksum:
                    raise ValidationError("A record in the blast radius failed integrity verification.")
                use_async = (
                    getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
                    or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
                )
                if use_async and hasattr(self._trust, "aeffective_state"):
                    effective = await self._trust.aeffective_state(tenant_id, rid)
                else:
                    effective = self._trust.effective_state(tenant_id, rid)
                if effective is None:
                    raise ValidationError("Trust state of a record in the blast radius is unknown.")
                if rid == target_record_id and effective == "REJECTED":
                    raise ValidationError("A REJECTED record cannot be recovered.")
                item = items.get(rid)
                if effective == "REJECTED":
                    action = "UNCHANGED_REJECTED"
                elif item is not None:
                    action = ActionTaken.RESTORED_TO_CHECKPOINT.value
                else:
                    action = ActionTaken.QUARANTINED_INTERMEDIARY.value
                planned.append(PlannedRecord(
                    record_id=rid, action=action, current_version=rec.current_version, current_checksum=latest.checksum,
                    effective_state=effective, checkpoint_version=item.version if item else None,
                    checkpoint_checksum=item.checksum if item else None,
                ))

        try:
            external = tuple(await self._external.executions_referencing(tenant_id, scope or list(company_resource_ids), checkpoint.created_at))
        except Exception as exc:  # noqa: BLE001 — honest outcome classification is mandatory
            logger.exception("External action history query failed")
            raise SecurityDependencyError("External action history unavailable; recovery refused.") from exc
        if not all(isinstance(a, ExternalActionView) for a in external):
            raise SecurityDependencyError("External action history returned invalid data.")
        external = tuple(sorted(external, key=lambda a: a.execution_id))

        # The fingerprint binds what the analyst approved: checkpoint, scope, planned actions,
        # current content (version + checksum), company resources, and external actions.
        fingerprint = _fingerprint({
            "tenant_id": tenant_id, "checkpoint_id": checkpoint.id, "checkpoint_hash": checkpoint.integrity_hash,
            "target": target_record_id,
            "records": [{k: v for k, v in p.__dict__.items() if k != "effective_state"} for p in planned],
            "company_resources": list(company_resources),
            "external": [a.__dict__ for a in external], "policy": RECOVERY_POLICY_VERSION,
        })
        return RecoveryPreview(
            plan_id=plan_id,
            tenant_id=tenant_id,
            checkpoint_id=checkpoint.id,
            checkpoint_integrity_hash=checkpoint.integrity_hash,
            target_record_id=target_record_id,
            checkpoint_name=checkpoint.name if isinstance(checkpoint.name, str) else "",
            records=tuple(planned),
            irreversible_external_actions=external,
            fingerprint=fingerprint,
            company_resources=company_resources,
            agent_id=checkpoint.agent_id,
            trace_id=checkpoint.trace_id,
        )

    # -- approve ----------------------------------------------------------------

    async def approve_plan(
        self,
        context: Optional[TenantContext],
        plan_id: Any,
        *,
        approval_id: Optional[str] = None,
        runtime_cancellation_verified: bool = False,
        runtime_cancellation_adapter: Any = None,
    ) -> RecoveryPlanRecord:
        tenant_id, actor = self._authorize(context)
        if type(plan_id) is not str or not _SAFE_ID.fullmatch(plan_id):
            raise ValidationError("Invalid recovery plan identifier.")
        plan = await self._plans.get(tenant_id, plan_id)
        if not isinstance(plan, RecoveryPlanRecord) or plan.tenant_id != tenant_id or plan.id != plan_id:
            raise NotFoundError("Recovery plan not found.")
        if plan.status == PlanStatus.EXECUTED.value:
            raise ValidationError("Executed recovery plan cannot be approved again.")
        if plan.status not in (PlanStatus.PREVIEWED.value, PlanStatus.APPROVED.value, PlanStatus.FAILED.value):
            raise ValidationError(f"Recovery plan in status '{plan.status}' cannot be approved.")

        checkpoint = await self._checkpoints.get_checkpoint(tenant_id, plan.checkpoint_id)
        agent_id = getattr(checkpoint, "agent_id", None) if checkpoint is not None else None
        trace_id = getattr(checkpoint, "trace_id", None) if checkpoint is not None else None

        cancel_ok = bool(runtime_cancellation_verified)
        if agent_id and not cancel_ok:
            if runtime_cancellation_adapter is not None and hasattr(runtime_cancellation_adapter, "cancel_agent_work"):
                res = await runtime_cancellation_adapter.cancel_agent_work(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    incident_id=plan.incident_id,
                    trace_id=trace_id,
                )
                cancel_ok = bool(isinstance(res, Mapping) and (res.get("cancelled") or res.get("acknowledged")))
            if not cancel_ok:
                cancel_ok = await self._is_runtime_cancelled(tenant_id, agent_id)
            if not cancel_ok:
                raise ValidationError("Agent runtime cancellation must be verified before approving recovery.")
        elif not agent_id:
            cancel_ok = True

        resolved_approval_id = approval_id or f"appr-{uuid.uuid4().hex[:16]}"
        approved_at = self._clock().isoformat()
        if hasattr(self._plans, "approve"):
            await self._plans.approve(
                tenant_id,
                plan_id,
                approved_by=actor,
                approved_at=approved_at,
                approval_id=resolved_approval_id,
                runtime_cancellation_verified=cancel_ok,
            )
        else:
            await self._safe_transition(tenant_id, plan_id, PlanStatus(plan.status), PlanStatus.APPROVED)

        await self._audit(
            tenant_id,
            actor,
            "RECOVERY_PLAN_APPROVED",
            plan_id,
            "APPROVE",
            "SUCCESS",
            {
                "approval_id": resolved_approval_id,
                "runtime_cancellation_verified": cancel_ok,
                "agent_id": agent_id,
                "incident_id": plan.incident_id,
            },
        )
        updated = await self._plans.get(tenant_id, plan_id)
        return updated if updated is not None else plan

    async def _is_runtime_cancelled(self, tenant_id: str, agent_id: str) -> bool:
        session_factory = getattr(self._plans, "session_factory", None)
        if session_factory is None:
            return False
        from sqlalchemy import select
        from backend.app.database.models.baseline import ObservationEvent

        async with session_factory() as session:
            obs = (
                await session.execute(
                    select(ObservationEvent.id).where(
                        ObservationEvent.tenant_id == tenant_id,
                        ObservationEvent.agent_id == agent_id,
                        ObservationEvent.event_type == "AGENT_RUNTIME_CANCELLED",
                    ).limit(1)
                )
            ).scalar_one_or_none()
            return obs is not None

    # -- execute ----------------------------------------------------------------

    async def execute(self, context: Optional[TenantContext], plan_id: Any) -> RecoveryOutcome:
        tenant_id, actor = self._authorize(context)
        if type(plan_id) is not str or not _SAFE_ID.fullmatch(plan_id):
            raise ValidationError("Invalid recovery plan identifier.")
        lock = self._plan_locks.setdefault((tenant_id, plan_id), asyncio.Lock())
        if lock.locked():
            return RecoveryOutcome(plan_id, RecoveryStatus.FAILED, (RecoveryReason.PLAN_NOT_EXECUTABLE.value,))
        async with lock:
            return await self._execute(context, tenant_id, actor, plan_id)

    async def _execute(self, context: TenantContext, tenant_id: str, actor: str, plan_id: str) -> RecoveryOutcome:
        try:
            plan = await self._plans.get(tenant_id, plan_id)
        except Exception as exc:  # noqa: BLE001
            raise SecurityDependencyError("Recovery plan store unavailable.") from exc
        if not isinstance(plan, RecoveryPlanRecord) or plan.tenant_id != tenant_id or plan.id != plan_id:
            raise NotFoundError("Recovery plan not found.")
        if plan.status == PlanStatus.EXECUTED.value:
            return RecoveryOutcome(plan_id, RecoveryStatus.FAILED, (RecoveryReason.PLAN_ALREADY_EXECUTED.value,))
        if plan.status not in (PlanStatus.PREVIEWED.value, PlanStatus.APPROVED.value, PlanStatus.FAILED.value):
            return RecoveryOutcome(plan_id, RecoveryStatus.FAILED, (RecoveryReason.PLAN_NOT_EXECUTABLE.value,))

        # 2. Re-verify everything the analyst approved in the preview (TOCTOU).
        try:
            current = await self._build_preview(tenant_id, plan_id, plan.checkpoint_id, plan.target_record_id)
        except (NotFoundError, ValidationError, SecurityDependencyError):
            return await self._fail(tenant_id, actor, plan, RecoveryReason.PLAN_STALE, change_status=False)
        if current.fingerprint != plan.preview_fingerprint:
            return await self._fail(tenant_id, actor, plan, RecoveryReason.PLAN_STALE, change_status=False)

        if current.company_resources:
            if plan.status != PlanStatus.APPROVED.value and not plan.approved_by:
                return await self._fail(tenant_id, actor, plan, RecoveryReason.HUMAN_APPROVAL_REQUIRED, change_status=False)
            if current.agent_id and not plan.runtime_cancellation_verified:
                if not await self._is_runtime_cancelled(tenant_id, current.agent_id):
                    return await self._fail(tenant_id, actor, plan, RecoveryReason.RUNTIME_CANCELLATION_REQUIRED, change_status=False)

        checkpoint = await self._checkpoints.get_checkpoint(tenant_id, plan.checkpoint_id)
        if _checkpoint_problem(checkpoint, tenant_id):
            return await self._fail(tenant_id, actor, plan, RecoveryReason.PLAN_STALE, change_status=False)
        content = {i.record_id: i for i in checkpoint.items}
        restore = [p for p in current.records if p.action == ActionTaken.RESTORED_TO_CHECKPOINT.value]
        intermediaries = [p for p in current.records if p.action == ActionTaken.QUARANTINED_INTERMEDIARY.value]
        company_restored_ids: List[str] = []

        # 3. Pre-recovery snapshot, committed before any change (M6 transaction 1).
        snapshot_sha = plan.snapshot_sha256
        if snapshot_sha is None:
            try:
                receipt = await self._rewind.capture_snapshot(tenant_id, plan_id, {
                    "plan_id": plan_id, "captured_by": actor, "policy_version": RECOVERY_POLICY_VERSION,
                    "records": [p.__dict__ for p in current.records],
                })
                snapshot_sha = getattr(receipt, "sha256", None)
                if not isinstance(snapshot_sha, str) or not _HEX64.fullmatch(snapshot_sha):
                    raise ValueError("invalid snapshot receipt")
            except Exception as exc:  # noqa: BLE001
                logger.error("Pre-recovery snapshot failed (%s); nothing changed.", type(exc).__name__)
                return await self._fail(tenant_id, actor, plan, RecoveryReason.SNAPSHOT_FAILED)
            if not await self._safe_transition(tenant_id, plan_id, PlanStatus(plan.status), PlanStatus(plan.status),
                                               snapshot_sha256=snapshot_sha):
                return await self._fail(tenant_id, actor, plan, RecoveryReason.PLAN_STATUS_NOT_RECORDED)

        # 4. Contain every affected, not-yet-restricted record before touching content.
        user = UserActor(context)
        for p in restore + intermediaries:
            if p.effective_state in ("QUARANTINED", "REJECTED"):
                continue
            use_async = (
                getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
                or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
            )
            req_payload = await self._atrust_request(
                p.record_id, TrustOperation.QUARANTINE, "QUARANTINED", plan, p.current_version
            )
            if use_async and hasattr(self._trust, "aapply"):
                decision = await self._trust.aapply(req_payload, user)
            else:
                decision = self._trust.apply(req_payload, user)
            if use_async and hasattr(self._trust, "aeffective_state"):
                cur_state = await self._trust.aeffective_state(tenant_id, p.record_id)
            else:
                cur_state = self._trust.effective_state(tenant_id, p.record_id)
            if not decision.applied and cur_state != "QUARANTINED":
                return await self._fail(tenant_id, actor, plan, RecoveryReason.CONTAINMENT_FAILED,
                                        snapshot_sha=snapshot_sha)

        # 5. Atomic rollback (M6 transaction 2). Any exception rolls the whole transaction back.
        new_versions: Dict[str, int] = {}

        async def restore_cb(rtx: Any) -> None:
            for p in restore:
                item = await rtx.checkpoint_item_for(p.record_id)
                cp = content[p.record_id]
                if item is None or getattr(item, "checksum", None) != cp.checksum or cp.checksum != p.checkpoint_checksum:
                    raise RuntimeError("checkpoint item mismatch")
                version = await rtx.append_version(p.record_id, content=cp.content, checksum=sha256_hex(cp.content))
                await rtx.compare_and_set_current_version(p.record_id, expected=p.current_version, new=version.version)
                await rtx.record_action(p.record_id, ActionTaken.RESTORED_TO_CHECKPOINT.value, "SUCCESS")
                new_versions[p.record_id] = version.version
            for res in current.company_resources:
                rtype = str(res.get("resource_type", "")).upper()
                rid = str(res.get("resource_id", ""))
                if not rid:
                    continue
                if rtype == "FILE" and hasattr(rtx, "restore_company_file"):
                    await rtx.restore_company_file(
                        rid,
                        target_version=int(res["current_version"]),
                        expected_checksum=res.get("version_checksum"),
                        target_status=str(res.get("status", "ACTIVE")),
                    )
                    await rtx.record_action(rid, ActionTaken.RESTORED_TO_CHECKPOINT.value, "SUCCESS")
                    company_restored_ids.append(rid)
                elif rtype == "FILE_TRANSFER" and hasattr(rtx, "restore_company_file_transfer"):
                    await rtx.restore_company_file_transfer(
                        rid,
                        target_status=str(res.get("status", "PENDING")),
                    )
                    await rtx.record_action(rid, ActionTaken.RESTORED_TO_CHECKPOINT.value, "SUCCESS")
                    company_restored_ids.append(rid)
                elif rtype == "TASK" and hasattr(rtx, "restore_company_task"):
                    await rtx.restore_company_task(
                        rid,
                        target_status=str(res.get("status", "OPEN")),
                        target_assigned_to_user_id=res.get("assigned_to_user_id"),
                        target_priority=res.get("priority"),
                    )
                    await rtx.record_action(rid, ActionTaken.RESTORED_TO_CHECKPOINT.value, "SUCCESS")
                    company_restored_ids.append(rid)
                elif rtype == "MESSAGE" and hasattr(rtx, "restore_company_message"):
                    await rtx.restore_company_message(
                        rid,
                        target_status=str(res.get("status", "SENT")),
                    )
                    await rtx.record_action(rid, ActionTaken.RESTORED_TO_CHECKPOINT.value, "SUCCESS")
                    company_restored_ids.append(rid)
            for p in intermediaries:
                await rtx.record_action(p.record_id, ActionTaken.QUARANTINED_INTERMEDIARY.value, "SUCCESS")
            for a in current.irreversible_external_actions:
                await rtx.record_action(a.execution_id, ActionTaken.EXTERNAL_ACTION_IRREVERSIBLE.value,
                                        "REQUIRES_COMPENSATION")

        try:
            await self._rewind.execute_rollback(tenant_id, plan_id, expected_snapshot_sha256=snapshot_sha,
                                                restore=restore_cb)
        except Exception as exc:  # noqa: BLE001 — transaction rolled back by M6; records stay contained
            logger.error("Recovery rollback failed (%s); transaction rolled back.", type(exc).__name__)
            return await self._fail(tenant_id, actor, plan, RecoveryReason.ROLLBACK_FAILED, snapshot_sha=snapshot_sha)

        # 6. Restored records: QUARANTINED -> UNVERIFIED (T-17). Never TRUSTED.
        codes: List[str] = []
        for p in restore:
            rec = self._memory.get_record(p.record_id, tenant_id)
            version = getattr(rec, "current_version", None)
            if version is None:
                codes.append(RecoveryReason.TRUST_RESTORE_FAILED.value)
                continue
            req_payload = await self._atrust_request(
                p.record_id, TrustOperation.RECOVERY_RESTORE, "QUARANTINED",
                plan, version, checkpoint_id=plan.checkpoint_id,
            )
            use_async = (
                getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
                or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
            )
            if use_async and hasattr(self._trust, "aapply"):
                d = await self._trust.aapply(req_payload, user)
            else:
                d = self._trust.apply(req_payload, user)
            if not d.applied:
                codes.append(RecoveryReason.TRUST_RESTORE_FAILED.value)

        # 7. Post-conditions: content equals the checkpoint, no restored record is TRUSTED,
        #    intermediaries are QUARANTINED, and company resources match checkpoint integrity.
        post = await self._apostconditions(
            tenant_id, restore, intermediaries, content, new_versions, company_resources=current.company_resources
        )
        if not post["ok"]:
            codes.append(RecoveryReason.POSTCONDITION_FAILED.value)
        if not await self._safe_transition(tenant_id, plan_id, PlanStatus(plan.status), PlanStatus.EXECUTED):
            codes.append(RecoveryReason.PLAN_STATUS_NOT_RECORDED.value)
        status = RecoveryStatus.EXECUTED if not codes else RecoveryStatus.RECONCILIATION_REQUIRED
        all_restored = tuple(dict.fromkeys([p.record_id for p in restore] + company_restored_ids))
        outcome = RecoveryOutcome(
            plan_id=plan_id, status=status, reason_codes=tuple(codes) or (RecoveryReason.RECOVERY_COMPLETED.value,),
            restored_record_ids=all_restored,
            quarantined_intermediary_ids=tuple(p.record_id for p in intermediaries),
            irreversible_external_actions=len(current.irreversible_external_actions),
            snapshot_sha256=snapshot_sha, postconditions=post, executed_at=self._clock().isoformat(),
        )
        try:
            audit_id = await self._audit(tenant_id, actor, "RECOVERY_EXECUTED", plan_id, "ROLLBACK",
                                         "SUCCESS" if outcome.success else "FAILED", self._outcome_details(outcome))
            outcome = RecoveryOutcome(**{**outcome.__dict__, "audit_event_id": audit_id})
        except SecurityDependencyError:
            return RecoveryOutcome(**{**outcome.__dict__, "status": RecoveryStatus.RECONCILIATION_REQUIRED,
                                      "reason_codes": outcome.reason_codes + (RecoveryReason.AUDIT_FAILED.value,)})
        return outcome

    # -- helpers ----------------------------------------------------------------

    async def _atrust_request(self, record_id: str, op: TrustOperation, expected_state: str, plan: RecoveryPlanRecord,
                              version: int, *, checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {"evidence_refs": [f"recovery-plan:{plan.id}"], "recovery_plan_id": plan.id}
        if plan.incident_id:
            evidence["incident_id"] = plan.incident_id
        if checkpoint_id:
            evidence["checkpoint_id"] = checkpoint_id
        target = "UNVERIFIED" if op is TrustOperation.RECOVERY_RESTORE else "QUARANTINED"
        use_async = (
            getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
            or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
        )
        if use_async and hasattr(self._trust, "aeffective_state"):
            eff = await self._trust.aeffective_state(plan.tenant_id, record_id)
        else:
            eff = self._trust.effective_state(plan.tenant_id, record_id)
        return {"record_id": record_id, "operation": op.value, "target_state": target,
                "expected_state": eff or expected_state,
                "expected_version": version, "reason": f"Recovery plan {plan.id} ({op.value.lower()})",
                "evidence": evidence}

    def _trust_request(self, record_id: str, op: TrustOperation, expected_state: str, plan: RecoveryPlanRecord,
                       version: int, *, checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {"recovery_plan_id": plan.id, "evidence_refs": [plan.id]}
        if plan.incident_id:
            evidence["incident_id"] = plan.incident_id
        if checkpoint_id:
            evidence["checkpoint_id"] = checkpoint_id
        target = "UNVERIFIED" if op is TrustOperation.RECOVERY_RESTORE else "QUARANTINED"
        return {"record_id": record_id, "operation": op.value, "target_state": target,
                "expected_state": self._trust.effective_state(plan.tenant_id, record_id) or expected_state,
                "expected_version": version, "reason": f"Recovery plan {plan.id} ({op.value.lower()})",
                "evidence": evidence}

    async def _apostconditions(
        self,
        tenant_id,
        restore,
        intermediaries,
        content,
        new_versions,
        *,
        company_resources: Tuple[Mapping[str, Any], ...] = (),
    ) -> Dict[str, Any]:
        import inspect
        failures: List[str] = []
        for p in restore:
            rec_res = self._memory.get_record(p.record_id, tenant_id)
            rec = await rec_res if inspect.isawaitable(rec_res) else rec_res
            ver_res = self._memory.get_version(p.record_id, getattr(rec, "current_version", 0) or 0, tenant_id)
            latest = await ver_res if inspect.isawaitable(ver_res) else ver_res
            stored = _state(getattr(rec, "trust_state", None))
            use_async = (
                getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
                or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
            )
            if use_async and hasattr(self._trust, "aeffective_state"):
                effective = await self._trust.aeffective_state(tenant_id, p.record_id)
            else:
                effective = self._trust.effective_state(tenant_id, p.record_id)
            if latest is None or latest.checksum != content[p.record_id].checksum \
                    or rec.current_version != new_versions.get(p.record_id):
                failures.append(f"{p.record_id}:CONTENT_NOT_RESTORED")
            if "TRUSTED" in (stored, effective):
                failures.append(f"{p.record_id}:TRUSTED_AFTER_RECOVERY")
            if effective not in ("UNVERIFIED", "QUARANTINED"):
                failures.append(f"{p.record_id}:UNEXPECTED_STATE")
        for p in intermediaries:
            use_async = (
                getattr(getattr(self._trust, "_store", None), "session_factory", None) is not None
                or getattr(getattr(self._trust, "_repo", None), "session_factory", None) is not None
            )
            if use_async and hasattr(self._trust, "aeffective_state"):
                inter_state = await self._trust.aeffective_state(tenant_id, p.record_id)
            else:
                inter_state = self._trust.effective_state(tenant_id, p.record_id)
            if inter_state not in ("QUARANTINED", "REJECTED"):
                failures.append(f"{p.record_id}:INTERMEDIARY_NOT_QUARANTINED")

        company_verified: List[Dict[str, Any]] = []
        session_factory = getattr(self._plans, "session_factory", None)
        if company_resources and session_factory is not None:
            from sqlalchemy import select
            from backend.app.database.models.company import (
                CompanyFile,
                CompanyFileTransfer,
                CompanyFileVersion,
                CompanyMessage,
                CompanyTask,
            )
            async with session_factory() as session:
                for res in company_resources:
                    rtype = str(res.get("resource_type", "")).upper()
                    rid = str(res.get("resource_id", ""))
                    if not rid:
                        continue
                    if rtype == "FILE":
                        f = (await session.execute(select(CompanyFile).where(CompanyFile.tenant_id == tenant_id, CompanyFile.id == rid))).scalar_one_or_none()
                        ver = (await session.execute(select(CompanyFileVersion).where(CompanyFileVersion.tenant_id == tenant_id, CompanyFileVersion.file_id == rid, CompanyFileVersion.version_number == int(res["current_version"])))).scalar_one_or_none()
                        if f is None or f.current_version != int(res["current_version"]) or f.status != res.get("status", "ACTIVE") or ver is None or (res.get("version_checksum") and ver.checksum != res["version_checksum"]):
                            failures.append(f"{rid}:COMPANY_FILE_INTEGRITY_FAILED")
                        else:
                            company_verified.append({"resource_type": "FILE", "resource_id": rid, "version": f.current_version, "checksum": ver.checksum, "verified": True})
                    elif rtype == "FILE_TRANSFER":
                        tr = (await session.execute(select(CompanyFileTransfer).where(CompanyFileTransfer.tenant_id == tenant_id, CompanyFileTransfer.id == rid))).scalar_one_or_none()
                        if tr is None or tr.status != res.get("status", "PENDING"):
                            failures.append(f"{rid}:COMPANY_TRANSFER_INTEGRITY_FAILED")
                        else:
                            company_verified.append({"resource_type": "FILE_TRANSFER", "resource_id": rid, "status": tr.status, "verified": True})
                    elif rtype == "TASK":
                        t = (await session.execute(select(CompanyTask).where(CompanyTask.tenant_id == tenant_id, CompanyTask.id == rid))).scalar_one_or_none()
                        if t is None or t.status != res.get("status", "OPEN"):
                            failures.append(f"{rid}:COMPANY_TASK_INTEGRITY_FAILED")
                        else:
                            company_verified.append({"resource_type": "TASK", "resource_id": rid, "status": t.status, "verified": True})
                    elif rtype == "MESSAGE":
                        m = (await session.execute(select(CompanyMessage).where(CompanyMessage.tenant_id == tenant_id, CompanyMessage.id == rid))).scalar_one_or_none()
                        if m is None or m.status != res.get("status", "SENT"):
                            failures.append(f"{rid}:COMPANY_MESSAGE_INTEGRITY_FAILED")
                        else:
                            company_verified.append({"resource_type": "MESSAGE", "resource_id": rid, "status": m.status, "verified": True})
        return {"ok": not failures, "failures": failures, "company_resources": company_verified}

    def _postconditions(self, tenant_id, restore, intermediaries, content, new_versions) -> Dict[str, Any]:
        failures: List[str] = []
        for p in restore:
            rec = self._memory.get_record(p.record_id, tenant_id)
            latest = self._memory.get_version(p.record_id, getattr(rec, "current_version", 0) or 0, tenant_id)
            stored, effective = _state(getattr(rec, "trust_state", None)), self._trust.effective_state(tenant_id, p.record_id)
            if latest is None or latest.checksum != content[p.record_id].checksum \
                    or rec.current_version != new_versions.get(p.record_id):
                failures.append(f"{p.record_id}:CONTENT_NOT_RESTORED")
            if "TRUSTED" in (stored, effective):
                failures.append(f"{p.record_id}:TRUSTED_AFTER_RECOVERY")
            if effective not in ("UNVERIFIED", "QUARANTINED"):
                failures.append(f"{p.record_id}:UNEXPECTED_STATE")
        for p in intermediaries:
            if self._trust.effective_state(tenant_id, p.record_id) not in ("QUARANTINED", "REJECTED"):
                failures.append(f"{p.record_id}:INTERMEDIARY_NOT_QUARANTINED")
        return {"ok": not failures, "failures": failures}

    async def _fail(self, tenant_id: str, actor: str, plan: RecoveryPlanRecord, reason: RecoveryReason, *,
                    change_status: bool = True, snapshot_sha: Optional[str] = None) -> RecoveryOutcome:
        codes = [reason.value]
        if change_status and plan.status != PlanStatus.FAILED.value:
            if not await self._safe_transition(tenant_id, plan.id, PlanStatus(plan.status), PlanStatus.FAILED):
                codes.append(RecoveryReason.PLAN_STATUS_NOT_RECORDED.value)
        try:
            await self._audit(tenant_id, actor, "RECOVERY_FAILED", plan.id, "ROLLBACK", "FAILED",
                              {"reason_codes": codes, "snapshot_sha256": snapshot_sha})
        except SecurityDependencyError:
            codes.append(RecoveryReason.AUDIT_FAILED.value)
        return RecoveryOutcome(plan.id, RecoveryStatus.FAILED, tuple(codes), snapshot_sha256=snapshot_sha)

    async def _safe_transition(self, tenant_id: str, plan_id: str, expected: PlanStatus, new: PlanStatus,
                               snapshot_sha256: Optional[str] = None) -> bool:
        try:
            return await self._plans.transition(tenant_id, plan_id, expected_status=expected.value,
                                                new_status=new.value, snapshot_sha256=snapshot_sha256) is True
        except Exception as exc:  # noqa: BLE001
            logger.error("Recovery plan status update failed (%s).", type(exc).__name__)
            return False

    async def _audit(self, tenant_id: str, actor: str, event_type: str, resource_id: str, action: str,
                     outcome: str, details: Mapping[str, Any]) -> str:
        event = {"id": str(uuid.uuid4()), "tenant_id": tenant_id, "actor_id": actor, "event_type": event_type,
                 "resource_id": resource_id, "action": action, "outcome": outcome,
                 "details_json": {**details, "policy_version": RECOVERY_POLICY_VERSION},
                 "occurred_at": self._clock().isoformat()}
        try:
            result = await self._persist_audit(event)
        except Exception as exc:  # noqa: BLE001
            raise SecurityDependencyError("Recovery audit could not be recorded.") from exc
        if result is False:
            raise SecurityDependencyError("Recovery audit could not be recorded.")
        return event["id"]

    @staticmethod
    def _outcome_details(o: RecoveryOutcome) -> Dict[str, Any]:
        return {"status": o.status.value, "reason_codes": list(o.reason_codes),
                "restored_record_ids": list(o.restored_record_ids),
                "quarantined_intermediary_ids": list(o.quarantined_intermediary_ids),
                "irreversible_external_actions": o.irreversible_external_actions,
                "snapshot_sha256": o.snapshot_sha256, "postconditions": dict(o.postconditions)}

    async def get_plan(self, context: Optional[TenantContext], plan_id: Any) -> RecoveryPlanRecord:
        """Read view of a plan (any canonical role incl. AUDITOR is checked by the route)."""
        if not isinstance(context, TenantContext) or context.is_active is not True:
            raise ForbiddenError("A verified tenant context is required.")
        if type(plan_id) is not str or not _SAFE_ID.fullmatch(plan_id):
            raise ValidationError("Invalid recovery plan identifier.")
        try:
            plan = await self._plans.get(context.tenant_id, plan_id)
        except Exception as exc:  # noqa: BLE001
            raise SecurityDependencyError("Recovery plan store unavailable.") from exc
        if not isinstance(plan, RecoveryPlanRecord) or plan.tenant_id != context.tenant_id:
            raise NotFoundError("Recovery plan not found.")
        return plan


__all__ = [
    "ActionTaken", "CheckpointItemView", "CheckpointReader", "CheckpointView", "ExternalActionReader",
    "ExternalActionView", "PlanStatus", "PlannedRecord", "RECOVERY_POLICY_VERSION", "RecoveryOutcome",
    "RecoveryPlanRecord", "RecoveryPlanStore", "RecoveryPreview", "RecoveryPreviewRequest", "RecoveryReason",
    "RecoveryService", "RecoveryStatus", "RewindPort", "checkpoint_integrity_hash",
]
