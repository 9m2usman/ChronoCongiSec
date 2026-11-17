"""Forged cross-tenant references, run directly against PostgreSQL (DOC-006 Day 2 exit gate).

Owner: M6
For EVERY tenant relationship:
- control: a same-tenant reference is accepted;
- forged insert: a child in tenant A pointing at tenant B's parent is rejected;
- missing parent: a reference to a non-existent id is rejected;
- forged update: re-pointing an existing child at tenant B's parent is rejected;
- delete behaviour: CASCADE removes the child, SET NULL clears only the
  reference and keeps the child's tenant_id.
Plus: tenant_id can never be changed on any tenant-owned row.

Raw SQL on purpose: the database must hold the line even if the ORM, the
repositories or the API layer are bypassed.
"""

import uuid

import asyncpg
import pytest

from backend.tests.database.factory import RowFactory
from backend.tests.database.relationships import TENANT_RELATIONSHIPS, Rel

pytestmark = pytest.mark.asyncio

CASCADE_RELS = [r for r in TENANT_RELATIONSHIPS if r.on_delete == "CASCADE"]
SET_NULL_RELS = [r for r in TENANT_RELATIONSHIPS if r.on_delete == "SET NULL"]


def _ids(rels):
    return [r.id for r in rels]


@pytest.mark.parametrize("rel", TENANT_RELATIONSHIPS, ids=_ids(TENANT_RELATIONSHIPS))
async def test_same_tenant_reference_is_accepted(factory: RowFactory, tx_conn, rel: Rel) -> None:
    tenant_a = await factory.tenant()
    parent_id = await factory.create(rel.parent, tenant_a)

    child_id = await factory.create(rel.child, tenant_a, **{rel.column: parent_id})

    stored = await tx_conn.fetchval(f"SELECT {rel.column} FROM {rel.child} WHERE id = $1", child_id)
    assert stored == parent_id


@pytest.mark.parametrize("rel", TENANT_RELATIONSHIPS, ids=_ids(TENANT_RELATIONSHIPS))
async def test_forged_cross_tenant_insert_is_rejected(factory: RowFactory, rel: Rel) -> None:
    tenant_a = await factory.tenant()
    tenant_b = await factory.tenant()
    foreign_parent = await factory.create(rel.parent, tenant_b)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await factory.create(rel.child, tenant_a, **{rel.column: foreign_parent})


@pytest.mark.parametrize("rel", TENANT_RELATIONSHIPS, ids=_ids(TENANT_RELATIONSHIPS))
async def test_missing_parent_is_rejected(factory: RowFactory, rel: Rel) -> None:
    tenant_a = await factory.tenant()

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await factory.create(rel.child, tenant_a, **{rel.column: str(uuid.uuid4())})


@pytest.mark.parametrize("rel", TENANT_RELATIONSHIPS, ids=_ids(TENANT_RELATIONSHIPS))
async def test_forged_cross_tenant_update_is_rejected(factory: RowFactory, tx_conn, rel: Rel) -> None:
    tenant_a = await factory.tenant()
    tenant_b = await factory.tenant()
    own_parent = await factory.create(rel.parent, tenant_a)
    child_id = await factory.create(rel.child, tenant_a, **{rel.column: own_parent})
    foreign_parent = await factory.create(rel.parent, tenant_b)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute(
                f"UPDATE {rel.child} SET {rel.column} = $1 WHERE id = $2", foreign_parent, child_id
            )

    assert await tx_conn.fetchval(
        f"SELECT {rel.column} FROM {rel.child} WHERE id = $1", child_id
    ) == own_parent


@pytest.mark.parametrize("rel", CASCADE_RELS, ids=_ids(CASCADE_RELS))
async def test_cascade_delete_removes_child(factory: RowFactory, tx_conn, rel: Rel) -> None:
    tenant_a = await factory.tenant()
    parent_id = await factory.create(rel.parent, tenant_a)
    child_id = await factory.create(rel.child, tenant_a, **{rel.column: parent_id})

    await tx_conn.execute(f"DELETE FROM {rel.parent} WHERE id = $1", parent_id)

    assert await tx_conn.fetchval(f"SELECT count(*) FROM {rel.child} WHERE id = $1", child_id) == 0


@pytest.mark.parametrize("rel", SET_NULL_RELS, ids=_ids(SET_NULL_RELS))
async def test_set_null_delete_keeps_child_and_tenant(factory: RowFactory, tx_conn, rel: Rel) -> None:
    tenant_a = await factory.tenant()
    parent_id = await factory.create(rel.parent, tenant_a)
    child_id = await factory.create(rel.child, tenant_a, **{rel.column: parent_id})

    await tx_conn.execute(f"DELETE FROM {rel.parent} WHERE id = $1", parent_id)

    row = await tx_conn.fetchrow(f"SELECT tenant_id, {rel.column} AS ref FROM {rel.child} WHERE id = $1", child_id)
    assert row is not None, "SET NULL relationship must keep the child row (forensic history)"
    assert row["ref"] is None
    assert row["tenant_id"] == tenant_a


async def test_delete_of_other_tenant_parent_does_not_touch_my_rows(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    tenant_b = await factory.tenant()
    record_a = await factory.create("memory_records", tenant_a)
    version_a = await factory.create("memory_versions", tenant_a, record_id=record_a)
    record_b = await factory.create("memory_records", tenant_b)

    await tx_conn.execute("DELETE FROM memory_records WHERE id = $1", record_b)

    assert await tx_conn.fetchval("SELECT count(*) FROM memory_versions WHERE id = $1", version_a) == 1


TENANT_ID_TABLES = sorted({r.child for r in TENANT_RELATIONSHIPS} | {r.parent for r in TENANT_RELATIONSHIPS} | {
    "audit_events", "branches", "memberships", "outbox_events", "roles",
})


@pytest.mark.parametrize("table", TENANT_ID_TABLES)
async def test_tenant_id_cannot_be_changed(factory: RowFactory, tx_conn, table: str) -> None:
    tenant_a = await factory.tenant()
    tenant_b = await factory.tenant()
    row_id = await factory.create(table, tenant_a)

    with pytest.raises(asyncpg.IntegrityConstraintViolationError, match="tenant_id is immutable"):
        async with tx_conn.transaction():
            await tx_conn.execute(f"UPDATE {table} SET tenant_id = $1 WHERE id = $2", tenant_b, row_id)

    assert await tx_conn.fetchval(f"SELECT tenant_id FROM {table} WHERE id = $1", row_id) == tenant_a


async def test_tenant_id_table_list_covers_every_tenant_table(tx_conn) -> None:
    rows = await tx_conn.fetch(
        "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'tenant_id'"
    )
    assert {r["table_name"] for r in rows} == set(TENANT_ID_TABLES)
