"""Atomic agent rewind with pre-recovery state preservation (Day 5).

Module: backend.app.database.rewind
Owner: M6
Spec: AMSC-DOC-006 Day 5 M6 row (exit: "Pre-recovery snapshot committed before rollback"),
TRD section 18 and SEC-007, AMSC-DOC-008 GAP-008 (atomic recovery, optimistic concurrency).

Two transactions, in this order:

1. ``capture_snapshot(tenant_id, plan_id, snapshot)``: locks the plan, stores the
   contaminated state in ``pre_recovery_snapshot_json``, lets PostgreSQL compute
   ``pre_recovery_snapshot_sha256``, and COMMITS. From then on the database refuses to
   change the snapshot or delete the plan (migration 0008).
2. ``execute_rollback(tenant_id, plan_id, expected_snapshot_sha256=..., restore=...)``:
   locks the plan again, verifies that the snapshot exists, is unchanged and matches the
   hash the caller received, runs the caller's ``restore`` callback with generic restore
   operations, sets ``executed_at`` and COMMITS. Any exception rolls back this transaction
   only; the committed snapshot stays as evidence and the rewind can be retried.

This module decides nothing about the business meaning of a rewind. What to put in the
snapshot, which version a record returns to, whether that is a new version or a moved
``current_version`` pointer, the trust state afterwards and the plan/action status values
belong to M3 and M4 (OPEN-DEPENDENCIES OD-17, OD-21). The ``restore`` callback receives
building blocks:

- ``checkpoint_item_for(record_id)``: the record's item in the plan's checkpoint;
- ``append_version(record_id, content=..., checksum=...)``: a new immutable version
  (number = highest + 1, under a row lock on the record);
- ``compare_and_set_current_version(record_id, expected=..., new=...)``: moves the
  pointer only if nobody changed it meanwhile (optimistic concurrency);
- ``record_action(resource_id, action_taken, outcome=None)``: a ``recovery_actions`` row.
"""

import json
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models import (
    CheckpointItem,
    MemoryRecord,
    MemoryVersion,
    RecoveryAction,
    RecoveryPlan,
)
from backend.app.database.unit_of_work import UnitOfWork

SNAPSHOT_SHA256_OF_PARAM = "encode(sha256(convert_to(CAST(:snapshot AS jsonb)::text, 'UTF8')), 'hex')"
SNAPSHOT_SHA256_OF_COLUMN = "encode(sha256(convert_to(pre_recovery_snapshot_json::text, 'UTF8')), 'hex')"


class RewindError(RuntimeError):
    """Base class for rewind refusals. The transaction that raised it was rolled back."""


class PlanNotFound(RewindError):
    pass


class RecordNotFound(RewindError):
    pass


class SnapshotAlreadyCaptured(RewindError):
    pass


class SnapshotMissing(RewindError):
    pass


class SnapshotMismatch(RewindError):
    pass


class PlanAlreadyExecuted(RewindError):
    pass


class ConcurrencyConflict(RewindError):
    pass


@dataclass(frozen=True)
class SnapshotReceipt:
    plan_id: str
    sha256: str


@dataclass(frozen=True)
class RewindResult:
    plan_id: str
    snapshot_sha256: str
    executed_at: datetime
    actions_recorded: int


def _check_id(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _snapshot_json(snapshot: Any) -> str:
    if not isinstance(snapshot, Mapping) or not snapshot:
        raise ValueError("snapshot must be a non-empty mapping")
    try:
        return json.dumps(snapshot, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"snapshot must be JSON-serialisable: {exc}") from exc


class RecoveryTransaction:
    """Generic restore operations available inside ``execute_rollback`` (one transaction, one tenant)."""

    def __init__(self, session: AsyncSession, tenant_id: str, plan: RecoveryPlan) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.plan_id = plan.id
        self.checkpoint_id = plan.checkpoint_id
        self.target_record_id = plan.target_record_id
        self.actions_recorded = 0

    async def checkpoint_item_for(self, record_id: str) -> Optional[CheckpointItem]:
        _check_id("record_id", record_id)
        stmt = select(CheckpointItem).where(
            CheckpointItem.tenant_id == self.tenant_id,
            CheckpointItem.checkpoint_id == self.checkpoint_id,
            CheckpointItem.record_id == record_id,
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def _lock_record(self, record_id: str) -> MemoryRecord:
        stmt = (
            select(MemoryRecord)
            .where(MemoryRecord.tenant_id == self.tenant_id, MemoryRecord.id == record_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        record = (await self.session.execute(stmt)).scalar_one_or_none()
        if record is None:
            raise RecordNotFound(f"memory record {record_id!r} not found in this tenant")
        return record

    async def append_version(
        self, record_id: str, *, content: str, checksum: str, version_id: Optional[str] = None
    ) -> MemoryVersion:
        """Append an immutable version numbered highest + 1. Does NOT move current_version."""
        _check_id("record_id", record_id)
        if not isinstance(content, str):
            raise ValueError("content must be a string")
        _check_id("checksum", checksum)
        await self._lock_record(record_id)
        highest = (await self.session.execute(
            select(func.max(MemoryVersion.version)).where(
                MemoryVersion.tenant_id == self.tenant_id, MemoryVersion.record_id == record_id
            )
        )).scalar()
        version = MemoryVersion(
            id=version_id or _new_id(),
            tenant_id=self.tenant_id,
            record_id=record_id,
            version=(highest or 0) + 1,
            content=content,
            checksum=checksum,
        )
        self.session.add(version)
        await self.session.flush()
        return version

    async def compare_and_set_current_version(self, record_id: str, *, expected: int, new: int) -> None:
        """Set current_version to ``new`` only if it is still ``expected``; ``new`` must exist."""
        _check_id("record_id", record_id)
        for name, value in (("expected", expected), ("new", new)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        exists = (await self.session.execute(
            select(MemoryVersion.id).where(
                MemoryVersion.tenant_id == self.tenant_id,
                MemoryVersion.record_id == record_id,
                MemoryVersion.version == new,
            )
        )).scalar_one_or_none()
        if exists is None:
            await self._lock_record(record_id)  # RecordNotFound if the record itself is missing
            raise ValueError(f"version {new} does not exist for record {record_id!r}")
        result = await self.session.execute(
            update(MemoryRecord)
            .where(
                MemoryRecord.tenant_id == self.tenant_id,
                MemoryRecord.id == record_id,
                MemoryRecord.current_version == expected,
            )
            .values(current_version=new, updated_at=func.now())
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            await self._lock_record(record_id)
            raise ConcurrencyConflict(
                f"record {record_id!r}: current_version is no longer {expected}; refusing to overwrite"
            )

    async def record_action(self, resource_id: str, action_taken: str, outcome: Optional[str] = None) -> RecoveryAction:
        """Record a recovery action for this plan. Values are stored as given (OD-21)."""
        _check_id("resource_id", resource_id)
        _check_id("action_taken", action_taken)
        values: dict[str, Any] = {}
        if outcome is not None:
            _check_id("outcome", outcome)
            values["outcome"] = outcome
        action = RecoveryAction(
            id=_new_id(), tenant_id=self.tenant_id, plan_id=self.plan_id,
            resource_id=resource_id, action_taken=action_taken, **values,
        )
        self.session.add(action)
        await self.session.flush()
        self.actions_recorded += 1
        return action


def _new_id() -> str:
    return str(uuid.uuid4())


RestoreCallback = Callable[[RecoveryTransaction], Awaitable[None]]


class RewindCoordinator:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        statement_timeout_ms: Optional[int] = None,
        lock_timeout_ms: Optional[int] = None,
    ) -> None:
        self._uow = UnitOfWork(
            session_factory, statement_timeout_ms=statement_timeout_ms, lock_timeout_ms=lock_timeout_ms
        )

    @staticmethod
    async def _lock_plan(session: AsyncSession, tenant_id: str, plan_id: str) -> RecoveryPlan:
        stmt = (
            select(RecoveryPlan)
            .where(RecoveryPlan.tenant_id == tenant_id, RecoveryPlan.id == plan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        plan = (await session.execute(stmt)).scalar_one_or_none()
        if plan is None:
            raise PlanNotFound(f"recovery plan {plan_id!r} not found in this tenant")
        return plan

    async def capture_snapshot(self, tenant_id: str, plan_id: str, snapshot: Mapping[str, Any]) -> SnapshotReceipt:
        """Transaction 1: store and COMMIT the pre-recovery snapshot. It can be captured once."""
        _check_id("plan_id", plan_id)
        snapshot_text = _snapshot_json(snapshot)
        async with self._uow(tenant_id) as tx:
            plan = await self._lock_plan(tx.session, tenant_id, plan_id)
            if plan.pre_recovery_snapshot_sha256 is not None:
                raise SnapshotAlreadyCaptured(f"recovery plan {plan_id!r} already has a pre-recovery snapshot")
            sha256 = (await tx.session.execute(
                text(
                    "UPDATE recovery_plans SET pre_recovery_snapshot_json = CAST(:snapshot AS jsonb), "
                    f"pre_recovery_snapshot_sha256 = {SNAPSHOT_SHA256_OF_PARAM} "
                    "WHERE tenant_id = :tenant_id AND id = :plan_id RETURNING pre_recovery_snapshot_sha256"
                ),
                {"snapshot": snapshot_text, "tenant_id": tenant_id, "plan_id": plan_id},
            )).scalar_one()
        return SnapshotReceipt(plan_id=plan_id, sha256=sha256)

    async def execute_rollback(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_snapshot_sha256: str,
        restore: RestoreCallback,
    ) -> RewindResult:
        """Transaction 2: verify the committed snapshot, run ``restore``, mark the plan executed."""
        _check_id("plan_id", plan_id)
        _check_id("expected_snapshot_sha256", expected_snapshot_sha256)
        if not callable(restore):
            raise ValueError("restore must be an async callable")
        async with self._uow(tenant_id) as tx:
            plan = await self._lock_plan(tx.session, tenant_id, plan_id)
            stored = plan.pre_recovery_snapshot_sha256
            if stored is None:
                raise SnapshotMissing(f"recovery plan {plan_id!r} has no committed pre-recovery snapshot")
            if plan.executed_at is not None:
                raise PlanAlreadyExecuted(f"recovery plan {plan_id!r} was already executed")
            recomputed = (await tx.session.execute(
                text(f"SELECT {SNAPSHOT_SHA256_OF_COLUMN} FROM recovery_plans WHERE tenant_id = :t AND id = :p"),
                {"t": tenant_id, "p": plan_id},
            )).scalar_one()
            if stored != expected_snapshot_sha256 or recomputed != stored:
                raise SnapshotMismatch(f"recovery plan {plan_id!r}: snapshot hash does not match")

            rtx = RecoveryTransaction(tx.session, tenant_id, plan)
            await restore(rtx)

            executed_at = (await tx.session.execute(
                update(RecoveryPlan)
                .where(RecoveryPlan.tenant_id == tenant_id, RecoveryPlan.id == plan_id)
                .values(executed_at=func.now())
                .returning(RecoveryPlan.executed_at)
                .execution_options(synchronize_session=False)
            )).scalar_one()
        return RewindResult(
            plan_id=plan_id, snapshot_sha256=stored, executed_at=executed_at, actions_recorded=rtx.actions_recorded
        )
