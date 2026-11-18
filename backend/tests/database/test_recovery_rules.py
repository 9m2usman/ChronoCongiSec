"""Database rules added by migration 0008 (pre-recovery snapshot, recovery chain), raw SQL.

Owner: M6
These hold even if the RewindCoordinator is bypassed.
"""

import asyncpg
import pytest

from backend.tests.database.factory import DEFAULT_RECOVERY_SNAPSHOT, RowFactory

pytestmark = pytest.mark.asyncio

SHA_SQL = "encode(sha256(convert_to($1::jsonb::text, 'UTF8')), 'hex')"


async def _uncaptured_plan(factory: RowFactory) -> tuple[str, str]:
    tenant = await factory.tenant()
    plan = await factory.create("recovery_plans", tenant, pre_recovery_snapshot_json="{}")
    return tenant, plan


async def _captured_plan(factory: RowFactory) -> tuple[str, str]:
    tenant = await factory.tenant()
    return tenant, await factory.create("recovery_plans", tenant)  # factory default: captured


# -- snapshot rules ----------------------------------------------------------------------------


async def test_action_for_uncaptured_plan_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, plan = await _uncaptured_plan(factory)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="requires a captured pre-recovery snapshot"):
        async with tx_conn.transaction():
            await factory.create("recovery_actions", tenant, plan_id=plan)


async def test_moving_an_action_to_an_uncaptured_plan_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, captured = await _captured_plan(factory)
    uncaptured = await factory.create("recovery_plans", tenant, pre_recovery_snapshot_json="{}")
    action = await factory.create("recovery_actions", tenant, plan_id=captured)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE recovery_actions SET plan_id = $1 WHERE id = $2", uncaptured, action)


async def test_executed_at_requires_a_snapshot(factory: RowFactory, tx_conn) -> None:
    _, plan = await _uncaptured_plan(factory)

    with pytest.raises(asyncpg.CheckViolationError, match="ck_recovery_plans_executed_requires_snapshot"):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE recovery_plans SET executed_at = now() WHERE id = $1", plan)


@pytest.mark.parametrize(
    ("snapshot", "sha"),
    [
        (DEFAULT_RECOVERY_SNAPSHOT, "0" * 64),   # wrong hash
        (DEFAULT_RECOVERY_SNAPSHOT, None),       # snapshot without hash
        ("{}", "0" * 64),                        # hash without snapshot
    ],
)
async def test_snapshot_and_hash_must_be_consistent(factory: RowFactory, tx_conn, snapshot, sha) -> None:
    tenant = await factory.tenant()

    with pytest.raises(asyncpg.CheckViolationError, match="ck_recovery_plans_snapshot_hash_consistent"):
        async with tx_conn.transaction():
            await factory.create("recovery_plans", tenant, pre_recovery_snapshot_json=snapshot,
                                 pre_recovery_snapshot_sha256=sha)


async def test_capturing_a_snapshot_later_with_the_database_hash_is_allowed(factory: RowFactory, tx_conn) -> None:
    _, plan = await _uncaptured_plan(factory)

    await tx_conn.execute(
        f"UPDATE recovery_plans SET pre_recovery_snapshot_json = $1::jsonb, pre_recovery_snapshot_sha256 = {SHA_SQL} "
        "WHERE id = $2", '{"state": "contaminated"}', plan,
    )

    assert await tx_conn.fetchval("SELECT pre_recovery_snapshot_sha256 FROM recovery_plans WHERE id = $1", plan)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE recovery_plans SET pre_recovery_snapshot_json = '{\"tampered\": true}'::jsonb, "
        "pre_recovery_snapshot_sha256 = encode(sha256(convert_to('{\"tampered\": true}', 'UTF8')), 'hex') WHERE id = $1",
        "UPDATE recovery_plans SET pre_recovery_snapshot_json = '{}'::jsonb, pre_recovery_snapshot_sha256 = NULL "
        "WHERE id = $1",
    ],
    ids=["replace", "erase"],
)
async def test_captured_snapshot_is_immutable(factory: RowFactory, tx_conn, statement: str) -> None:
    _, plan = await _captured_plan(factory)
    before = await tx_conn.fetchval("SELECT pre_recovery_snapshot_sha256 FROM recovery_plans WHERE id = $1", plan)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="is immutable"):
        async with tx_conn.transaction():
            await tx_conn.execute(statement, plan)

    assert await tx_conn.fetchval("SELECT pre_recovery_snapshot_sha256 FROM recovery_plans WHERE id = $1", plan) == before


async def test_other_plan_columns_can_still_change(factory: RowFactory, tx_conn) -> None:
    _, plan = await _captured_plan(factory)

    await tx_conn.execute(
        "UPDATE recovery_plans SET status = 'TEST_STATUS', impact_preview_json = '{\"n\": 1}', executed_at = now() "
        "WHERE id = $1", plan,
    )

    assert await tx_conn.fetchval("SELECT executed_at IS NOT NULL FROM recovery_plans WHERE id = $1", plan)


async def test_plan_with_captured_snapshot_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    _, plan = await _captured_plan(factory)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="cannot be deleted"):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM recovery_plans WHERE id = $1", plan)

    assert await tx_conn.fetchval("SELECT count(*) FROM recovery_plans WHERE id = $1", plan) == 1


async def test_uncaptured_plan_without_actions_can_be_deleted(factory: RowFactory, tx_conn) -> None:
    _, plan = await _uncaptured_plan(factory)

    await tx_conn.execute("DELETE FROM recovery_plans WHERE id = $1", plan)

    assert await tx_conn.fetchval("SELECT count(*) FROM recovery_plans WHERE id = $1", plan) == 0


# -- checkpoint items -----------------------------------------------------------------------------


async def test_checkpoint_cannot_hold_the_same_record_twice(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    checkpoint = await factory.create("checkpoints", tenant)
    record = await factory.create("memory_records", tenant)
    version = await factory.create("memory_versions", tenant, record_id=record)
    await factory.create("checkpoint_items", tenant, checkpoint_id=checkpoint, record_id=record, version_id=version)

    with pytest.raises(asyncpg.UniqueViolationError, match="uq_checkpoint_items_tenant_id_checkpoint_id_record_id"):
        async with tx_conn.transaction():
            await factory.create("checkpoint_items", tenant, checkpoint_id=checkpoint, record_id=record,
                                 version_id=version)


async def test_same_record_in_two_checkpoints_is_allowed(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    record = await factory.create("memory_records", tenant)
    version = await factory.create("memory_versions", tenant, record_id=record)

    for _ in range(2):
        checkpoint = await factory.create("checkpoints", tenant)
        await factory.create("checkpoint_items", tenant, checkpoint_id=checkpoint, record_id=record,
                             version_id=version)

    assert await tx_conn.fetchval("SELECT count(*) FROM checkpoint_items WHERE record_id = $1", record) == 2


# -- recovery chain RESTRICT ------------------------------------------------------------------------


async def test_checkpoint_used_by_items_or_plans_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    checkpoint = await factory.create("checkpoints", tenant)
    await factory.create("checkpoint_items", tenant, checkpoint_id=checkpoint)
    plan = await factory.create("recovery_plans", tenant, checkpoint_id=checkpoint, pre_recovery_snapshot_json="{}")

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM checkpoints WHERE id = $1", checkpoint)

    assert await tx_conn.fetchval("SELECT count(*) FROM checkpoint_items WHERE checkpoint_id = $1", checkpoint) == 1
    assert await tx_conn.fetchval("SELECT count(*) FROM recovery_plans WHERE id = $1", plan) == 1


async def test_incident_with_evidence_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    incident = await factory.create("incidents", tenant)
    evidence = await factory.create("incident_evidence", tenant, incident_id=incident)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM incidents WHERE id = $1", incident)

    assert await tx_conn.fetchval("SELECT count(*) FROM incident_evidence WHERE id = $1", evidence) == 1
