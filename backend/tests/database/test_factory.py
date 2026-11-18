"""Regression tests for the shared schema-driven RowFactory.

Owner: M6
The factory must build VALID rows for multi-column ("linked") foreign keys
(migration 0005: a checkpoint item's version belongs to its record), while still
letting negative tests forge invalid combinations that PostgreSQL must reject.
"""

import uuid

import asyncpg
import pytest

from backend.tests.database.factory import LinkedReference, RowFactory

pytestmark = pytest.mark.asyncio


async def _item(tx_conn, item_id: str):
    return await tx_conn.fetchrow(
        """
        SELECT ci.tenant_id, ci.record_id, ci.version_id, mv.record_id AS version_record, mv.tenant_id AS version_tenant
        FROM checkpoint_items ci JOIN memory_versions mv ON mv.id = ci.version_id
        WHERE ci.id = $1
        """,
        item_id,
    )


async def test_schema_info_detects_linked_checkpoint_reference(factory: RowFactory) -> None:
    assert factory.schema.linked["checkpoint_items"] == [
        LinkedReference(
            child="checkpoint_items",
            parent="memory_versions",
            anchor="version_id",
            derived=(("record_id", "record_id"),),
        )
    ]
    # Single-column references are still mapped as before.
    assert factory.schema.references[("checkpoint_items", "version_id")] == "memory_versions"
    assert factory.schema.references[("checkpoint_items", "record_id")] == "memory_records"


async def test_auto_generated_version_belongs_to_auto_generated_record(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()

    item = await _item(tx_conn, await factory.create("checkpoint_items", tenant_id))

    assert item["version_record"] == item["record_id"]
    assert item["tenant_id"] == item["version_tenant"] == tenant_id


async def test_auto_generated_version_belongs_to_supplied_record(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    record_id = await factory.create("memory_records", tenant_id)

    item = await _item(tx_conn, await factory.create("checkpoint_items", tenant_id, record_id=record_id))

    assert item["record_id"] == record_id
    assert item["version_record"] == record_id


async def test_record_is_derived_from_supplied_version(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    record_id = await factory.create("memory_records", tenant_id)
    version_id = await factory.create("memory_versions", tenant_id, record_id=record_id)

    item = await _item(tx_conn, await factory.create("checkpoint_items", tenant_id, version_id=version_id))

    assert (item["record_id"], item["version_id"]) == (record_id, version_id)


async def test_explicit_mismatch_is_not_repaired_and_is_rejected(factory: RowFactory, tx_conn) -> None:
    """Supplying both columns keeps them as given, so the database must reject the mismatch."""
    tenant_id = await factory.tenant()
    record_a = await factory.create("memory_records", tenant_id)
    record_b = await factory.create("memory_records", tenant_id)
    version_b = await factory.create("memory_versions", tenant_id, record_id=record_b)

    with pytest.raises(asyncpg.ForeignKeyViolationError, match="fk_checkpoint_items_version_matches_record"):
        async with tx_conn.transaction():
            await factory.create("checkpoint_items", tenant_id, record_id=record_a, version_id=version_b)


async def test_forged_cross_tenant_version_is_still_rejected(factory: RowFactory, tx_conn) -> None:
    tenant_a, tenant_b = await factory.tenant(), await factory.tenant()
    foreign_version = await factory.create("memory_versions", tenant_b)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await factory.create("checkpoint_items", tenant_a, version_id=foreign_version)


async def test_forged_cross_tenant_record_is_still_rejected(factory: RowFactory, tx_conn) -> None:
    tenant_a, tenant_b = await factory.tenant(), await factory.tenant()
    foreign_record = await factory.create("memory_records", tenant_b)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await factory.create("checkpoint_items", tenant_a, record_id=foreign_record)


async def test_unknown_version_is_still_rejected(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await factory.create("checkpoint_items", tenant_id, version_id=str(uuid.uuid4()))
