"""SQLAlchemy persistent stores and ports for Recovery Service.

Module: backend.app.recovery.store
Owner: M6 (Database Architect & Governance) + M4 (Security Engine)
Spec: AMSC-DOC-005 Section 3.5, AMSC-DOC-002 TRD Section 18
"""

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import inspect
import json
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.baseline import TrustDecisionModel
from backend.app.database.models.gateway import ToolExecution, ToolProposal
from backend.app.database.models.memory import MemoryVersion
from backend.app.database.models.observability import AuditEvent
from backend.app.database.models.recovery import Checkpoint, CheckpointItem, RecoveryPlan
from backend.app.database.rewind import RewindCoordinator
from backend.app.memory.adapters import DatabaseMemoryRepository
from backend.app.memory.integrity import sha256_hex
from backend.app.memory.models import MemoryVersion as PydanticMemoryVersion
from backend.app.memory.repository import get_default_repository
from backend.app.recovery.orchestrator import (
    CheckpointItemView,
    CheckpointView,
    ExternalActionView,
    RecoveryPlanRecord,
    RecoveryService,
    checkpoint_integrity_hash,
    _fingerprint,
)
from backend.app.security.trust import TrustDecision, TrustEvaluator


class SqlCheckpointReader:
    """PostgreSQL implementation of CheckpointReader port."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def get_checkpoint(self, tenant_id: str, checkpoint_id: str) -> Optional[CheckpointView]:
        async with self.session_factory() as session:
            stmt_cp = select(Checkpoint).where(
                Checkpoint.id == checkpoint_id,
                Checkpoint.tenant_id == tenant_id,
            )
            cp = (await session.execute(stmt_cp)).scalar_one_or_none()
            if cp is None:
                return None

            stmt_items = (
                select(CheckpointItem, MemoryVersion)
                .join(
                    MemoryVersion,
                    (MemoryVersion.id == CheckpointItem.version_id)
                    & (MemoryVersion.tenant_id == CheckpointItem.tenant_id)
                    & (MemoryVersion.record_id == CheckpointItem.record_id),
                )
                .where(
                    CheckpointItem.checkpoint_id == checkpoint_id,
                    CheckpointItem.tenant_id == tenant_id,
                )
            )
            rows = (await session.execute(stmt_items)).all()
            item_views = []
            for item, ver in rows:
                item_views.append(
                    CheckpointItemView(
                        record_id=item.record_id,
                        version=ver.version,
                        checksum=item.checksum,
                        content=ver.content,
                    )
                )

            snap_data = cp.snapshot_data_json if isinstance(cp.snapshot_data_json, dict) else {}
            return CheckpointView(
                id=cp.id,
                tenant_id=cp.tenant_id,
                name=cp.name,
                integrity_hash=cp.integrity_hash,
                created_at=cp.created_at,
                items=tuple(item_views),
                resources=tuple(snap_data.get("resources") or ()),
                agent_id=snap_data.get("agent_id"),
                trace_id=snap_data.get("trace_id"),
            )


class SqlRecoveryPlanStore:
    """PostgreSQL implementation of RecoveryPlanStore port with compare-and-set transitions."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create(self, plan: RecoveryPlanRecord) -> None:
        from backend.app.workers.outbox import publish_outbox_event

        preview_payload = dict(plan.impact_preview)
        preview_payload["_preview_fingerprint"] = plan.preview_fingerprint
        preview_section = preview_payload.get("preview") or {}
        is_company_only = bool(preview_section.get("company_resources")) and not bool(preview_section.get("affected_records"))
        db_target_record_id = None if is_company_only else (plan.target_record_id or None)
        async with self.session_factory() as session:
            async with session.begin():
                db_plan = RecoveryPlan(
                    id=plan.id,
                    tenant_id=plan.tenant_id,
                    incident_id=plan.incident_id,
                    checkpoint_id=plan.checkpoint_id,
                    target_record_id=db_target_record_id,
                    status=plan.status,
                    pre_recovery_snapshot_json={},
                    pre_recovery_snapshot_sha256=None,
                    impact_preview_json=preview_payload,
                )
                session.add(db_plan)
                await publish_outbox_event(
                    session,
                    tenant_id=plan.tenant_id,
                    event_type="RECOVERY_PLAN_CREATED",
                    payload={
                        "plan_id": plan.id,
                        "checkpoint_id": plan.checkpoint_id,
                        "target_record_id": plan.target_record_id,
                        "incident_id": plan.incident_id,
                        "status": plan.status,
                    },
                    idempotency_key=f"recovery-plan-create-{plan.tenant_id}-{plan.id}",
                )

    async def get(self, tenant_id: str, plan_id: str) -> Optional[RecoveryPlanRecord]:
        async with self.session_factory() as session:
            stmt = select(RecoveryPlan).where(
                RecoveryPlan.id == plan_id,
                RecoveryPlan.tenant_id == tenant_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None

            raw_preview = dict(row.impact_preview_json or {})
            stored_fp = raw_preview.get("_preview_fingerprint")
            approval = raw_preview.get("_approval") or {}
            clean_preview = {k: v for k, v in raw_preview.items() if k not in ("_preview_fingerprint", "_approval")}
            return RecoveryPlanRecord(
                id=row.id,
                tenant_id=row.tenant_id,
                checkpoint_id=row.checkpoint_id,
                target_record_id=row.target_record_id or (clean_preview.get("preview") or {}).get("target_record_id") or "",
                incident_id=row.incident_id,
                status=row.status,
                preview_fingerprint=stored_fp or _fingerprint(clean_preview),
                impact_preview=clean_preview,
                created_by="system",
                snapshot_sha256=row.pre_recovery_snapshot_sha256,
                approved_by=approval.get("approved_by"),
                approved_at=approval.get("approved_at"),
                approval_id=approval.get("approval_id"),
                runtime_cancellation_verified=bool(approval.get("runtime_cancellation_verified", False)),
            )

    async def approve(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        approved_by: str,
        approved_at: str,
        approval_id: str,
        runtime_cancellation_verified: bool,
    ) -> bool:
        from backend.app.workers.outbox import publish_outbox_event

        async with self.session_factory() as session:
            async with session.begin():
                row = (
                    await session.execute(
                        select(RecoveryPlan).where(
                            RecoveryPlan.id == plan_id,
                            RecoveryPlan.tenant_id == tenant_id,
                        ).with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None or row.status not in ("PREVIEWED", "APPROVED", "FAILED"):
                    return False
                preview = dict(row.impact_preview_json or {})
                preview["_approval"] = {
                    "approved_by": approved_by,
                    "approved_at": approved_at,
                    "approval_id": approval_id,
                    "runtime_cancellation_verified": runtime_cancellation_verified,
                }
                row.impact_preview_json = preview
                row.status = "APPROVED"
                await publish_outbox_event(
                    session,
                    tenant_id=tenant_id,
                    event_type="RECOVERY_PLAN_APPROVED",
                    payload={
                        "plan_id": plan_id,
                        "approved_by": approved_by,
                        "approval_id": approval_id,
                        "runtime_cancellation_verified": runtime_cancellation_verified,
                    },
                    idempotency_key=f"recovery-plan-approve-{tenant_id}-{plan_id}-{approval_id}",
                )
                return True

    async def transition(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_status: str,
        new_status: str,
        snapshot_sha256: Optional[str] = None,
    ) -> bool:
        """Compare-and-set status transition."""
        from backend.app.workers.outbox import publish_outbox_event

        async with self.session_factory() as session:
            async with session.begin():
                values: Dict[str, Any] = {"status": new_status}
                if snapshot_sha256 is not None:
                    values["pre_recovery_snapshot_sha256"] = snapshot_sha256

                stmt = (
                    update(RecoveryPlan)
                    .where(
                        RecoveryPlan.id == plan_id,
                        RecoveryPlan.tenant_id == tenant_id,
                        RecoveryPlan.status == expected_status,
                    )
                    .values(**values)
                )
                result = await session.execute(stmt)
                if result.rowcount > 0 and new_status in ("EXECUTED", "FAILED"):
                    await publish_outbox_event(
                        session,
                        tenant_id=tenant_id,
                        event_type="RECOVERY_EXECUTED" if new_status == "EXECUTED" else "RECOVERY_FAILED",
                        payload={"plan_id": plan_id, "status": new_status},
                    )
                return result.rowcount > 0


class SqlExternalActionReader:
    """PostgreSQL implementation of ExternalActionReader port."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def executions_referencing(
        self,
        tenant_id: str,
        record_ids: Sequence[str],
        since: datetime,
    ) -> Sequence[ExternalActionView]:
        async with self.session_factory() as session:
            stmt = (
                select(ToolExecution, ToolProposal)
                .join(
                    ToolProposal,
                    (ToolProposal.id == ToolExecution.proposal_id)
                    & (ToolProposal.tenant_id == ToolExecution.tenant_id),
                )
                .where(
                    ToolExecution.tenant_id == tenant_id,
                    ToolExecution.executed_at >= since,
                )
            )
            rows = (await session.execute(stmt)).all()
            rec_set = set(record_ids)
            views: List[ExternalActionView] = []
            for exec_row, prop_row in rows:
                mem_refs = prop_row.memory_refs_json or []
                if any(ref in rec_set for ref in mem_refs):
                    views.append(
                        ExternalActionView(
                            execution_id=exec_row.id,
                            status=exec_row.status,
                        )
                    )
            return views


class SqlTrustDecisionStore:
    """Persistent TrustDecisionStore implementation for production recovery and gateway services.

    Persists decisions durably to PostgreSQL `trust_decisions` table. All database
    writes and reads are awaited and fail closed on persistence errors (never swallowed).
    """

    def __init__(self, session_factory: Optional[async_sessionmaker[AsyncSession]] = None) -> None:
        self.session_factory = session_factory
        self._by_record: Dict[Tuple[str, str], List[TrustDecision]] = {}

    @property
    def is_persistent(self) -> bool:
        return self.session_factory is not None

    @staticmethod
    def _serialize_decision(decision: TrustDecision) -> Dict[str, Any]:
        return {
            "decision_id": decision.decision_id,
            "allowed": bool(decision.allowed),
            "applied": bool(decision.applied),
            "decision": decision.decision,
            "reason_codes": list(decision.reason_codes),
            "reason": decision.reason,
            "transition_id": decision.transition_id,
            "current_state": decision.current_state,
            "stored_state": decision.stored_state,
            "target_state": decision.target_state,
            "resulting_state": decision.resulting_state,
            "record_version": decision.record_version,
            "version_checksum": decision.version_checksum,
            "actor_type": decision.actor_type,
            "actor_id": decision.actor_id,
            "actor_role": decision.actor_role,
            "incident_id": decision.incident_id,
            "evidence_summary": dict(decision.evidence_summary or {}),
            "policy_version": decision.policy_version,
            "timestamp": decision.timestamp.isoformat(),
            "history_available": bool(decision.history_available),
        }

    @staticmethod
    def _deserialize_decision(row: TrustDecisionModel) -> TrustDecision:
        payload = dict(row.evidence_json or {})
        raw_ts = payload.get("timestamp")
        if isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts)
        else:
            ts = row.created_at
        raw_codes = payload.get("reason_codes")
        reason_codes = tuple(str(c) for c in raw_codes) if isinstance(raw_codes, (list, tuple)) else (row.reason_code,)
        return TrustDecision(
            decision_id=str(payload.get("decision_id") or row.id),
            allowed=bool(payload.get("allowed", False)),
            applied=bool(payload.get("applied", False)),
            decision=str(payload.get("decision") or "DENIED"),
            reason_codes=reason_codes,
            reason=str(payload.get("reason") or ""),
            record_id=row.record_id,
            tenant_id=row.tenant_id,
            operation=payload.get("operation", row.operation),
            transition_id=payload.get("transition_id"),
            current_state=payload.get("current_state", row.from_state),
            stored_state=payload.get("stored_state", row.from_state),
            target_state=payload.get("target_state", row.to_state),
            resulting_state=payload.get("resulting_state", row.to_state),
            record_version=payload.get("record_version"),
            version_checksum=payload.get("version_checksum"),
            actor_type=payload.get("actor_type"),
            actor_id=payload.get("actor_id", row.actor_id),
            actor_role=payload.get("actor_role"),
            incident_id=payload.get("incident_id"),
            evidence_summary=dict(payload.get("evidence_summary") or {}),
            policy_version=str(payload.get("policy_version") or "amsc-trust-policy/1.0.0"),
            timestamp=ts,
            history_available=bool(payload.get("history_available", True)),
        )

    async def _persist_decision(self, decision: TrustDecision) -> None:
        if self.session_factory is None:
            raise RuntimeError("Trust decision store session factory is not configured.")
        now = decision.timestamp if isinstance(decision.timestamp, datetime) else datetime.now(timezone.utc)
        from_state = (decision.current_state or decision.stored_state or "UNKNOWN")[:32]
        to_state = (decision.resulting_state or decision.target_state or decision.current_state or "UNKNOWN")[:32]
        operation = (decision.operation or "UNKNOWN")[:64]
        actor_id = (decision.actor_id or decision.actor_type or "SYSTEM")[:128]
        reason_code = (decision.reason_codes[0] if decision.reason_codes else "UNKNOWN")[:64]
        row_id = decision.decision_id[:36] if decision.decision_id and len(decision.decision_id) <= 36 else f"td-{uuid.uuid4().hex[:12]}"

        async with self.session_factory() as session:
            async with session.begin():
                db_row = TrustDecisionModel(
                    id=row_id,
                    tenant_id=decision.tenant_id,
                    record_id=decision.record_id,
                    from_state=from_state,
                    to_state=to_state,
                    operation=operation,
                    actor_id=actor_id,
                    reason_code=reason_code,
                    evidence_json=self._serialize_decision(decision),
                    created_at=now,
                )
                session.add(db_row)

    def _append_in_memory(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            raise ValueError("Trust decisions must be tenant-scoped.")
        self._by_record.setdefault((decision.tenant_id, decision.record_id), []).append(decision)

    def append(self, decision: TrustDecision) -> None:
        if self.session_factory is not None:
            raise RuntimeError(
                "SqlTrustDecisionStore requires await aappend() when backed by a database session factory."
            )
        self._append_in_memory(decision)

    async def aappend(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            raise ValueError("Trust decisions must be tenant-scoped.")
        await self._persist_decision(decision)
        self._append_in_memory(decision)

    def list_for_record(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        if self.session_factory is not None:
            raise RuntimeError(
                "SqlTrustDecisionStore requires await alist_for_record() when backed by a database session factory."
            )
        return tuple(self._by_record.get((tenant_id, record_id), ()))

    async def alist_for_record(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        if self.session_factory is None:
            raise RuntimeError("Trust decision store session factory is not configured.")
        async with self.session_factory() as session:
            stmt = (
                select(TrustDecisionModel)
                .where(
                    TrustDecisionModel.tenant_id == tenant_id,
                    TrustDecisionModel.record_id == record_id,
                )
                .order_by(TrustDecisionModel.created_at.asc(), TrustDecisionModel.id.asc())
            )
            rows = (await session.execute(stmt)).scalars().all()
            decisions = [self._deserialize_decision(r) for r in rows]
            self._by_record[(tenant_id, record_id)] = decisions
            return tuple(decisions)


def create_recovery_service(
    session_factory: async_sessionmaker[AsyncSession],
    memory_repo: Optional[Any] = None,
    trust_evaluator: Optional[TrustEvaluator] = None,
) -> RecoveryService:
    """Factory creating fully wired, durable RecoveryService with PostgreSQL persistence."""
    memory = memory_repo if memory_repo is not None else DatabaseMemoryRepository(session_factory)
    if trust_evaluator is None:
        store = SqlTrustDecisionStore(session_factory)
        trust = TrustEvaluator(memory, store)
    else:
        trust = trust_evaluator
    checkpoints = SqlCheckpointReader(session_factory)
    plans = SqlRecoveryPlanStore(session_factory)
    rewind = RewindCoordinator(session_factory)
    external_actions = SqlExternalActionReader(session_factory)

    async def persist_audit(audit_dict: Dict[str, Any]) -> None:
        async with session_factory() as session:
            async with session.begin():
                event = AuditEvent(
                    id=audit_dict.get("id") or f"aud-{uuid.uuid4().hex[:12]}",
                    tenant_id=audit_dict["tenant_id"],
                    actor_id=audit_dict.get("actor_id", "system"),
                    event_type=audit_dict.get("event_type", "RECOVERY_ACTION"),
                    resource_id=audit_dict.get("resource_id", "recovery"),
                    action=audit_dict.get("action", "EXECUTE"),
                    outcome=audit_dict.get("outcome", "SUCCESS"),
                    trace_id=audit_dict.get("trace_id"),
                    details_json=audit_dict.get("details", {}),
                    occurred_at=datetime.now(timezone.utc),
                )
                session.add(event)

    return RecoveryService(
        trust=trust,
        memory=memory,
        checkpoints=checkpoints,
        plans=plans,
        rewind=rewind,
        external_actions=external_actions,
        persist_audit=persist_audit,
    )


class MemoryCheckpoints:
    def __init__(self) -> None:
        self.rows: Dict[Tuple[str, str], CheckpointView] = {}

    def add(self, cp: CheckpointView) -> None:
        self.rows[(cp.tenant_id, cp.id)] = cp

    async def get_checkpoint(self, tenant_id: str, checkpoint_id: str) -> Optional[CheckpointView]:
        return self.rows.get((tenant_id, checkpoint_id))


class MemoryPlanStore:
    def __init__(self) -> None:
        self.rows: Dict[Tuple[str, str], RecoveryPlanRecord] = {}

    async def create(self, plan: RecoveryPlanRecord) -> None:
        self.rows[(plan.tenant_id, plan.id)] = plan

    async def get(self, tenant_id: str, plan_id: str) -> Optional[RecoveryPlanRecord]:
        return self.rows.get((tenant_id, plan_id))

    async def transition(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_status: str,
        new_status: str,
        snapshot_sha256: Optional[str] = None,
    ) -> bool:
        plan = self.rows.get((tenant_id, plan_id))
        if plan is None or plan.status != expected_status:
            return False
        self.rows[(tenant_id, plan_id)] = replace(
            plan,
            status=new_status,
            snapshot_sha256=snapshot_sha256 or plan.snapshot_sha256,
        )
        return True


@dataclass
class _MemoryReceipt:
    plan_id: str
    sha256: str


class _MemoryRtx:
    def __init__(self, rewind: "MemoryRewindCoordinator", tenant_id: str, plan: Any) -> None:
        self.r = rewind
        self.tenant_id = tenant_id
        self.plan = plan
        self.pending: List[Tuple[str, str, Optional[str]]] = []

    async def checkpoint_item_for(self, record_id: str) -> Optional[CheckpointItemView]:
        cp = self.r.checkpoints.rows.get((self.tenant_id, self.plan.checkpoint_id))
        if cp:
            for item in cp.items:
                if item.record_id == record_id:
                    return item
        return None

    async def append_version(self, record_id: str, *, content: str, checksum: str) -> Any:
        repo = self.r.repo
        rec = repo.get_record(record_id, self.tenant_id)
        if inspect.isawaitable(rec):
            rec = await rec
        versions = repo.get_versions(record_id, self.tenant_id)
        if inspect.isawaitable(versions):
            versions = await versions
        highest = max((v.version for v in versions), default=0)
        v = PydanticMemoryVersion(
            id=f"v-{record_id}-{highest + 1}",
            tenant_id=self.tenant_id,
            record_id=record_id,
            version=highest + 1,
            content=content,
            checksum=checksum,
            created_at=datetime.now(timezone.utc),
        )
        res = repo.create_version(v)
        if inspect.isawaitable(res):
            await res
        return v

    async def compare_and_set_current_version(self, record_id: str, *, expected: int, new: int) -> None:
        rec = self.r.repo.get_record(record_id, self.tenant_id)
        if inspect.isawaitable(rec):
            rec = await rec
        if rec.current_version != expected:
            raise RuntimeError("ConcurrencyConflict")
        updated = rec.model_copy(update={"current_version": new})
        res = self.r.repo.update_record(updated)
        if inspect.isawaitable(res):
            await res

    async def record_action(self, resource_id: str, action_taken: str, outcome: Optional[str] = None) -> None:
        self.pending.append((resource_id, action_taken, outcome))


class MemoryRewindCoordinator:
    def __init__(self, repo: Any, plans: MemoryPlanStore, checkpoints: MemoryCheckpoints) -> None:
        self.repo = repo
        self.plans = plans
        self.checkpoints = checkpoints
        self.snapshots: Dict[Tuple[str, str], str] = {}
        self.executed: Set[Tuple[str, str]] = set()
        self.actions: List[Tuple[str, str, Optional[str]]] = []

    async def capture_snapshot(self, tenant_id: str, plan_id: str, snapshot: Mapping[str, Any]) -> Any:
        if (tenant_id, plan_id) in self.snapshots:
            raise RuntimeError("SnapshotAlreadyCaptured")
        if await self.plans.get(tenant_id, plan_id) is None:
            raise RuntimeError("PlanNotFound")
        sha = hashlib.sha256(json.dumps(dict(snapshot), sort_keys=True, default=str).encode()).hexdigest()
        self.snapshots[(tenant_id, plan_id)] = sha
        return _MemoryReceipt(plan_id, sha)

    async def execute_rollback(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_snapshot_sha256: str,
        restore: Callable[[Any], Awaitable[None]],
    ) -> Any:
        if self.snapshots.get((tenant_id, plan_id)) != expected_snapshot_sha256:
            raise RuntimeError("SnapshotMismatch")
        if (tenant_id, plan_id) in self.executed:
            raise RuntimeError("PlanAlreadyExecuted")
        plan = await self.plans.get(tenant_id, plan_id)
        saved_records = copy.deepcopy(getattr(self.repo, "_records", {}))
        saved_versions = copy.deepcopy(getattr(self.repo, "_versions", {}))
        rtx = _MemoryRtx(self, tenant_id, plan)
        try:
            await restore(rtx)
        except BaseException:
            if hasattr(self.repo, "_records"):
                self.repo._records = saved_records
                self.repo._versions = saved_versions
            raise
        self.actions.extend(rtx.pending)
        self.executed.add((tenant_id, plan_id))


class MemoryExternalActionReader:
    def __init__(self, actions: Sequence[ExternalActionView] = ()) -> None:
        self.actions = list(actions)

    async def executions_referencing(
        self, tenant_id: str, record_ids: Sequence[str], since: datetime
    ) -> Sequence[ExternalActionView]:
        return list(self.actions)


def create_in_memory_recovery_service(
    memory_repo: Optional[Any] = None,
    trust_evaluator: Optional[TrustEvaluator] = None,
) -> RecoveryService:
    """Factory creating fully wired in-memory RecoveryService for non-production environments."""
    try:
        from backend.app.core.config import get_settings
        settings = get_settings()
        if settings.APP_ENV == "production":
            raise RuntimeError(
                "Production startup failure: Real database recovery service is required. "
                "In-memory recovery service fallback is prohibited in production."
            )
    except ImportError:
        pass

    memory = memory_repo if memory_repo is not None else get_default_repository()
    if trust_evaluator is None:
        from backend.app.security.trust import InMemoryTrustDecisionStore
        store = InMemoryTrustDecisionStore()
        trust = TrustEvaluator(memory, store, app_env="development")
    else:
        trust = trust_evaluator

    checkpoints = MemoryCheckpoints()
    plans = MemoryPlanStore()
    rewind = MemoryRewindCoordinator(memory, plans, checkpoints)
    external_actions = MemoryExternalActionReader([ExternalActionView("exec-demo-001", "SUCCESS")])

    # Ensure canonical demo memories are present in memory repository
    t_a = "tenant-a-uuid-001"
    existing_target = memory.get_record("rec-8812-441a", t_a)
    if inspect.isawaitable(existing_target):
        pass  # will be handled if needed
    elif existing_target is None:
        from backend.app.memory.repository import seed_enterprise_demo_memories
        seed_enterprise_demo_memories(memory)
    v1_content = "Standard invoice for ACME supplies: $450 due in net 30 days."
    item_poison = CheckpointItemView(
        record_id="rec-8812-441a",
        version=1,
        checksum=sha256_hex(v1_content),
        content=v1_content,
    )
    items_poison = (item_poison,)
    checkpoints.add(
        CheckpointView(
            id="cp-baseline-alpha-001",
            tenant_id=t_a,
            integrity_hash=checkpoint_integrity_hash(items_poison),
            created_at=datetime.now(timezone.utc),
            items=items_poison,
            name="CHK-2026-T15M (v2 Verified Baseline)",
        )
    )

    crm_content = "Tier-1 Support can issue service credit vouchers up to $150."
    item_crm = CheckpointItemView(
        record_id="rec-crm-2041",
        version=1,
        checksum=sha256_hex(crm_content),
        content=crm_content,
    )
    items_crm = (item_crm,)
    checkpoints.add(
        CheckpointView(
            id="cp-crm-v1",
            tenant_id=t_a,
            integrity_hash=checkpoint_integrity_hash(items_crm),
            created_at=datetime.now(timezone.utc),
            items=items_crm,
            name="CHK-2026-CRM-V1 (Baseline)",
        )
    )

    async def persist_audit(audit_dict: Dict[str, Any]) -> None:
        pass

    return RecoveryService(
        trust=trust,
        memory=memory,
        checkpoints=checkpoints,
        plans=plans,
        rewind=rewind,
        external_actions=external_actions,
        persist_audit=persist_audit,
    )
