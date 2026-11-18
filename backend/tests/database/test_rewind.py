"""Two-transaction agent rewind (DOC-006 Day 5: "Pre-recovery snapshot committed before rollback").

Owner: M6
These tests really COMMIT, so each test works in its own fresh tenant inside the module's
temporary database. Action/status values are neutral placeholders on purpose (OD-21).
"""

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.database.models import (
    Checkpoint,
    CheckpointItem,
    MemoryRecord,
    MemoryVersion,
    RecoveryAction,
    RecoveryPlan,
    Tenant,
)
from backend.app.database.rewind import (
    ConcurrencyConflict,
    PlanAlreadyExecuted,
    PlanNotFound,
    RecordNotFound,
    RewindCoordinator,
    SnapshotAlreadyCaptured,
    SnapshotMismatch,
    SnapshotMissing,
)
from backend.tests.database import helpers

pytestmark = pytest.mark.asyncio

ACTION = "TEST_ACTION"  # deliberately not a real action_taken value (OD-21)


def _id() -> str:
    return str(uuid.uuid4())


@pytest_asyncio.fixture
async def session_factory(module_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), poolclass=NullPool)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def world(session_factory) -> dict[str, str]:
    """A tenant, a record with versions 1..3 (current = 3, contaminated), a checkpoint holding
    version 1, and an uncaptured recovery plan targeting the record."""
    ids = {k: _id() for k in ("tenant", "record", "v1", "v2", "v3", "checkpoint", "item", "plan")}
    t = ids["tenant"]
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=t, name="Company", slug=f"co-{t[:8]}"))
        await session.flush()
        session.add(MemoryRecord(id=ids["record"], tenant_id=t, current_version=3))
        await session.flush()
        for n in (1, 2, 3):
            session.add(MemoryVersion(id=ids[f"v{n}"], tenant_id=t, record_id=ids["record"], version=n,
                                      content=f"content v{n}", checksum=f"sum{n}"))
        session.add(Checkpoint(id=ids["checkpoint"], tenant_id=t, name="CP-001", integrity_hash="h"))
        await session.flush()
        session.add(CheckpointItem(id=ids["item"], tenant_id=t, checkpoint_id=ids["checkpoint"],
                                   record_id=ids["record"], version_id=ids["v1"], checksum="sum1"))
        session.add(RecoveryPlan(id=ids["plan"], tenant_id=t, checkpoint_id=ids["checkpoint"],
                                 target_record_id=ids["record"]))
    return ids


async def _plan(session_factory, plan_id: str) -> RecoveryPlan:
    async with session_factory() as session:
        return await session.get(RecoveryPlan, plan_id)


async def _current_version(session_factory, record_id: str) -> int:
    async with session_factory() as session:
        return (await session.get(MemoryRecord, record_id)).current_version


async def _action_count(session_factory, plan_id: str) -> int:
    async with session_factory() as session:
        return (await session.execute(
            select(func.count()).select_from(RecoveryAction).where(RecoveryAction.plan_id == plan_id)
        )).scalar_one()


def _restore_to_checkpoint(expected: int = 3):
    async def restore(rtx) -> None:
        item = await rtx.checkpoint_item_for(rtx.target_record_id)
        async with rtx.session.begin_nested():
            pass  # nested savepoints are allowed inside the callback
        version = await rtx.session.get(MemoryVersion, item.version_id)
        await rtx.compare_and_set_current_version(rtx.target_record_id, expected=expected, new=version.version)
        await rtx.record_action(rtx.target_record_id, ACTION)
    return restore


SNAPSHOT = {"records": [{"id": "r", "current_version": 3, "checksum": "sum3"}]}


# -- transaction 1: snapshot ------------------------------------------------------------------


async def test_capture_commits_snapshot_and_database_hash(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)

    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    plan = await _plan(session_factory, world["plan"])
    assert plan.pre_recovery_snapshot_json == SNAPSHOT
    assert plan.pre_recovery_snapshot_sha256 == receipt.sha256 and len(receipt.sha256) == 64
    async with session_factory() as session:
        recomputed = (await session.execute(text(
            "SELECT encode(sha256(convert_to(pre_recovery_snapshot_json::text, 'UTF8')), 'hex') "
            "FROM recovery_plans WHERE id = :p"), {"p": world["plan"]})).scalar_one()
    assert recomputed == receipt.sha256
    assert plan.executed_at is None


async def test_snapshot_can_be_captured_only_once(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    first = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    with pytest.raises(SnapshotAlreadyCaptured):
        await coordinator.capture_snapshot(world["tenant"], world["plan"], {"other": True})

    assert (await _plan(session_factory, world["plan"])).pre_recovery_snapshot_sha256 == first.sha256


@pytest.mark.parametrize("bad", [{}, [], "text", None, {"x": float("nan")}, {"x": object()}])
async def test_invalid_snapshot_is_refused(session_factory, world, bad) -> None:
    with pytest.raises(ValueError):
        await RewindCoordinator(session_factory).capture_snapshot(world["tenant"], world["plan"], bad)

    assert (await _plan(session_factory, world["plan"])).pre_recovery_snapshot_sha256 is None


async def test_plan_of_another_tenant_is_not_found(session_factory, world) -> None:
    other_tenant = _id()
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=other_tenant, name="Other", slug=f"co-{other_tenant[:8]}"))
    coordinator = RewindCoordinator(session_factory)

    with pytest.raises(PlanNotFound):
        await coordinator.capture_snapshot(other_tenant, world["plan"], SNAPSHOT)
    with pytest.raises(PlanNotFound):
        await coordinator.execute_rollback(other_tenant, world["plan"], expected_snapshot_sha256="x" * 64,
                                           restore=_restore_to_checkpoint())
    with pytest.raises(PlanNotFound):
        await coordinator.capture_snapshot(world["tenant"], _id(), SNAPSHOT)


# -- transaction 2: rollback ------------------------------------------------------------------


async def test_rollback_without_snapshot_is_refused(session_factory, world) -> None:
    with pytest.raises(SnapshotMissing):
        await RewindCoordinator(session_factory).execute_rollback(
            world["tenant"], world["plan"], expected_snapshot_sha256="x" * 64, restore=_restore_to_checkpoint()
        )

    assert await _current_version(session_factory, world["record"]) == 3
    assert (await _plan(session_factory, world["plan"])).executed_at is None


async def test_rollback_with_wrong_expected_hash_is_refused(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    with pytest.raises(SnapshotMismatch):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256="0" * 64,
                                           restore=_restore_to_checkpoint())

    assert await _current_version(session_factory, world["record"]) == 3
    assert await _action_count(session_factory, world["plan"]) == 0


async def test_rollback_restores_records_and_marks_plan_executed_atomically(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    result = await coordinator.execute_rollback(
        world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256, restore=_restore_to_checkpoint()
    )

    assert await _current_version(session_factory, world["record"]) == 1
    assert await _action_count(session_factory, world["plan"]) == 1
    plan = await _plan(session_factory, world["plan"])
    assert plan.executed_at == result.executed_at and result.actions_recorded == 1
    assert plan.pre_recovery_snapshot_json == SNAPSHOT, "the snapshot survives the rollback"


async def test_snapshot_is_already_committed_while_rollback_runs(session_factory, world) -> None:
    """Proof of ordering: inside transaction 2, an independent session already sees the snapshot."""
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)
    seen = {}

    async def restore(rtx) -> None:
        async with session_factory() as other:
            seen["sha"] = (await other.get(RecoveryPlan, world["plan"])).pre_recovery_snapshot_sha256
        await rtx.record_action(world["record"], ACTION)

    await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                       restore=restore)

    assert seen["sha"] == receipt.sha256


async def test_failure_during_rollback_keeps_snapshot_and_changes_nothing_else(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    class Injected(Exception):
        pass

    async def failing_restore(rtx) -> None:
        await _restore_to_checkpoint()(rtx)  # pointer moved + action recorded, then:
        raise Injected

    with pytest.raises(Injected):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                           restore=failing_restore)

    plan = await _plan(session_factory, world["plan"])
    assert plan.pre_recovery_snapshot_sha256 == receipt.sha256, "the committed snapshot must survive"
    assert plan.executed_at is None
    assert await _current_version(session_factory, world["record"]) == 3
    assert await _action_count(session_factory, world["plan"]) == 0

    # The rewind can be retried with the same snapshot.
    await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                       restore=_restore_to_checkpoint())
    assert await _current_version(session_factory, world["record"]) == 1


async def test_plan_cannot_be_executed_twice(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)
    await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                       restore=_restore_to_checkpoint())

    with pytest.raises(PlanAlreadyExecuted):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                           restore=_restore_to_checkpoint(expected=1))

    assert await _action_count(session_factory, world["plan"]) == 1


async def test_concurrent_executions_of_one_plan_let_exactly_one_win(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)
    first_inside = asyncio.Event()

    async def slow_restore(rtx) -> None:
        first_inside.set()
        await asyncio.sleep(0.5)  # hold the plan lock
        await _restore_to_checkpoint()(rtx)

    async def first():
        return await coordinator.execute_rollback(world["tenant"], world["plan"],
                                                  expected_snapshot_sha256=receipt.sha256, restore=slow_restore)

    async def second():
        await first_inside.wait()
        return await coordinator.execute_rollback(world["tenant"], world["plan"],
                                                  expected_snapshot_sha256=receipt.sha256,
                                                  restore=_restore_to_checkpoint())

    results = await asyncio.gather(first(), second(), return_exceptions=True)

    assert results[0].actions_recorded == 1
    assert isinstance(results[1], PlanAlreadyExecuted)
    assert await _action_count(session_factory, world["plan"]) == 1


# -- generic restore operations ----------------------------------------------------------------


async def test_compare_and_set_detects_concurrent_change(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    with pytest.raises(ConcurrencyConflict):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                           restore=_restore_to_checkpoint(expected=2))  # it is really 3

    assert await _current_version(session_factory, world["record"]) == 3
    assert (await _plan(session_factory, world["plan"])).executed_at is None


async def test_compare_and_set_to_missing_version_is_refused(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)

    async def restore(rtx) -> None:
        await rtx.compare_and_set_current_version(world["record"], expected=3, new=9)

    with pytest.raises(ValueError, match="does not exist"):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                           restore=restore)
    assert await _current_version(session_factory, world["record"]) == 3


async def test_append_version_numbers_after_the_highest(session_factory, world) -> None:
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)
    created = []

    async def restore(rtx) -> None:
        for _ in range(2):
            created.append(await rtx.append_version(world["record"], content="content v1", checksum="sum1"))
        await rtx.compare_and_set_current_version(world["record"], expected=3, new=created[-1].version)
        await rtx.record_action(world["record"], ACTION)

    await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                       restore=restore)

    assert [v.version for v in created] == [4, 5]
    assert await _current_version(session_factory, world["record"]) == 5


async def test_restore_operations_are_tenant_scoped(session_factory, world) -> None:
    """A rewind in tenant A cannot touch or even see tenant B's record."""
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(world["tenant"], world["plan"], SNAPSHOT)
    other = {k: _id() for k in ("tenant", "record")}
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=other["tenant"], name="Other", slug=f"co-{other['tenant'][:8]}"))
        await session.flush()
        session.add(MemoryRecord(id=other["record"], tenant_id=other["tenant"]))
    seen = {}

    async def restore(rtx) -> None:
        seen["item"] = await rtx.checkpoint_item_for(other["record"])
        await rtx.append_version(other["record"], content="x", checksum="y")

    with pytest.raises(RecordNotFound):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=receipt.sha256,
                                           restore=restore)
    assert seen["item"] is None
    async with session_factory() as session:
        count = (await session.execute(
            select(func.count()).select_from(MemoryVersion).where(MemoryVersion.record_id == other["record"])
        )).scalar_one()
    assert count == 0


@pytest.mark.parametrize("bad", ["", "  ", None])
async def test_arguments_are_validated(session_factory, world, bad) -> None:
    coordinator = RewindCoordinator(session_factory)
    with pytest.raises((ValueError, PlanNotFound)):
        await coordinator.capture_snapshot(world["tenant"], bad, SNAPSHOT)
    with pytest.raises(ValueError):
        await coordinator.execute_rollback(world["tenant"], world["plan"], expected_snapshot_sha256=bad,
                                           restore=_restore_to_checkpoint())
