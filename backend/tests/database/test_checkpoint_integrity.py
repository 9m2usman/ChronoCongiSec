"""Day 3 checkpoint integrity: a checkpoint item must snapshot a version of its record.

Owner: M6. These raw-SQL-backed tests verify the PostgreSQL constraint, not
just ORM validation.
"""

import asyncpg
import pytest

pytestmark = pytest.mark.asyncio


async def _checkpoint_fixture(factory):
    tenant_id = await factory.tenant()
    checkpoint_id = await factory.create("checkpoints", tenant_id)
    record_a = await factory.create("memory_records", tenant_id)
    version_a = await factory.create("memory_versions", tenant_id, record_id=record_a)
    record_b = await factory.create("memory_records", tenant_id)
    version_b = await factory.create("memory_versions", tenant_id, record_id=record_b)
    return tenant_id, checkpoint_id, record_a, version_a, record_b, version_b


async def test_checkpoint_item_accepts_version_of_its_own_record(factory, tx_conn) -> None:
    tenant_id, checkpoint_id, record_id, version_id, _, _ = await _checkpoint_fixture(factory)

    item_id = await factory.create(
        "checkpoint_items",
        tenant_id,
        checkpoint_id=checkpoint_id,
        record_id=record_id,
        version_id=version_id,
    )

    row = await tx_conn.fetchrow(
        "SELECT record_id, version_id FROM checkpoint_items WHERE id = $1", item_id
    )
    assert row is not None
    assert row["record_id"] == record_id
    assert row["version_id"] == version_id


async def test_checkpoint_item_rejects_version_from_another_record_on_insert(factory, tx_conn) -> None:
    tenant_id, checkpoint_id, record_a, _, _, version_b = await _checkpoint_fixture(factory)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await factory.create(
                "checkpoint_items",
                tenant_id,
                checkpoint_id=checkpoint_id,
                record_id=record_a,
                version_id=version_b,
            )


async def test_checkpoint_item_rejects_version_from_another_record_on_update(factory, tx_conn) -> None:
    tenant_id, checkpoint_id, record_a, version_a, _, version_b = await _checkpoint_fixture(factory)
    item_id = await factory.create(
        "checkpoint_items",
        tenant_id,
        checkpoint_id=checkpoint_id,
        record_id=record_a,
        version_id=version_a,
    )

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute(
                "UPDATE checkpoint_items SET version_id = $1 WHERE id = $2",
                version_b,
                item_id,
            )

    assert await tx_conn.fetchval(
        "SELECT version_id FROM checkpoint_items WHERE id = $1", item_id
    ) == version_a
