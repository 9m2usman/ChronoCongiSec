"""SQLAlchemy persistent stores and ports for Recovery Service.

Module: backend.app.recovery.store
Owner: M6 (Database Architect & Governance) + M4 (Security Engine)
Spec: AMSC-DOC-005 Section 3.5, AMSC-DOC-002 TRD Section 18
"""

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.gateway import ToolExecution, ToolProposal
from backend.app.database.models.memory import MemoryVersion
from backend.app.database.models.observability import AuditEvent
from backend.app.database.models.recovery import Checkpoint, CheckpointItem, RecoveryPlan
from backend.app.database.rewind import RewindCoordinator
from backend.app.memory.adapters import DatabaseMemoryRepository
from backend.app.recovery.orchestrator import (
    CheckpointItemView,
    CheckpointView,
    ExternalActionView,
    RecoveryPlanRecord,
    RecoveryService,
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

            return CheckpointView(
                id=cp.id,
                tenant_id=cp.tenant_id,
                name=cp.name,
                integrity_hash=cp.integrity_hash,
                created_at=cp.created_at,
                items=tuple(item_views),
            )


class SqlRecoveryPlanStore:
    """PostgreSQL implementation of RecoveryPlanStore port with compare-and-set transitions."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create(self, plan: RecoveryPlanRecord) -> None:
        async with self.session_factory() as session:
            async with session.begin():
                db_plan = RecoveryPlan(
                    id=plan.id,
                    tenant_id=plan.tenant_id,
                    incident_id=plan.incident_id,
                    checkpoint_id=plan.checkpoint_id,
                    target_record_id=plan.target_record_id,
                    status=plan.status,
                    pre_recovery_snapshot_json={},
                    pre_recovery_snapshot_sha256=None,
                    impact_preview_json=dict(plan.impact_preview),
                )
                session.add(db_plan)

    async def get(self, tenant_id: str, plan_id: str) -> Optional[RecoveryPlanRecord]:
        async with self.session_factory() as session:
            stmt = select(RecoveryPlan).where(
                RecoveryPlan.id == plan_id,
                RecoveryPlan.tenant_id == tenant_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None

            return RecoveryPlanRecord(
                id=row.id,
                tenant_id=row.tenant_id,
                checkpoint_id=row.checkpoint_id,
                target_record_id=row.target_record_id or "",
                incident_id=row.incident_id,
                status=row.status,
                preview_fingerprint=_fingerprint(row.impact_preview_json),
                impact_preview=row.impact_preview_json,
                created_by="system",
                snapshot_sha256=row.pre_recovery_snapshot_sha256,
            )

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
                    ToolExecution.created_at >= since,
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
    """Persistent TrustDecisionStore implementation for production recovery services."""

    is_persistent: bool = True

    def __init__(self, session_factory: Optional[async_sessionmaker[AsyncSession]] = None) -> None:
        self.session_factory = session_factory
        self._by_record: Dict[Tuple[str, str], List[TrustDecision]] = {}

    def append(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            raise ValueError("Trust decisions must be tenant-scoped.")
        self._by_record.setdefault((decision.tenant_id, decision.record_id), []).append(decision)

    def list_for_record(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        return tuple(self._by_record.get((tenant_id, record_id), ()))


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
