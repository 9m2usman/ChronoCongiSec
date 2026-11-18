"""Database rules added by migration 0006 (requested by M3), checked with raw SQL.

Owner: M6
- sources.status: only ACTIVE / INACTIVE, NOT NULL, new rows default to ACTIVE.
- provenance_edges: known relation_type only, no duplicate directed edge per tenant,
  no self-loop. Direction is not normalised (A->B and B->A are both allowed).
"""

import asyncpg
import pytest

from backend.tests.database.factory import RowFactory

pytestmark = pytest.mark.asyncio

RELATION_TYPES = ("DERIVED_FROM", "TRANSFORMED_INTO", "SUPERSEDES")


# -- sources.status -------------------------------------------------------------------


async def test_new_source_defaults_to_active(factory: RowFactory, tx_conn) -> None:
    source = await factory.create("sources", await factory.tenant())

    assert await tx_conn.fetchval("SELECT status FROM sources WHERE id = $1", source) == "ACTIVE"


@pytest.mark.parametrize("status", ["ACTIVE", "INACTIVE"])
async def test_allowed_source_statuses(factory: RowFactory, tx_conn, status: str) -> None:
    source = await factory.create("sources", await factory.tenant(), status=status)

    assert await tx_conn.fetchval("SELECT status FROM sources WHERE id = $1", source) == status


@pytest.mark.parametrize("bad", ["active", "REVOKED", "SUSPENDED", "", "ACTIVE "])
async def test_unknown_source_status_is_rejected(factory: RowFactory, tx_conn, bad: str) -> None:
    tenant = await factory.tenant()

    with pytest.raises(asyncpg.CheckViolationError, match="ck_sources_status"):
        async with tx_conn.transaction():
            await factory.create("sources", tenant, status=bad)


async def test_null_source_status_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()

    with pytest.raises(asyncpg.NotNullViolationError):
        async with tx_conn.transaction():
            await factory.create("sources", tenant, status=None)


async def test_source_status_update_is_checked(factory: RowFactory, tx_conn) -> None:
    source = await factory.create("sources", await factory.tenant())

    await tx_conn.execute("UPDATE sources SET status = 'INACTIVE' WHERE id = $1", source)
    with pytest.raises(asyncpg.CheckViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE sources SET status = 'DELETED' WHERE id = $1", source)

    assert await tx_conn.fetchval("SELECT status FROM sources WHERE id = $1", source) == "INACTIVE"


async def test_trust_state_is_unchanged_and_separate(factory: RowFactory, tx_conn) -> None:
    source = await factory.create("sources", await factory.tenant())

    row = await tx_conn.fetchrow("SELECT status, trust_state FROM sources WHERE id = $1", source)
    assert (row["status"], row["trust_state"]) == ("ACTIVE", "UNVERIFIED")


# -- provenance_edges ------------------------------------------------------------------


async def _two_records(factory: RowFactory) -> tuple[str, str, str]:
    tenant = await factory.tenant()
    return tenant, await factory.create("memory_records", tenant), await factory.create("memory_records", tenant)


@pytest.mark.parametrize("relation", RELATION_TYPES)
async def test_known_relation_types_are_accepted(factory: RowFactory, relation: str) -> None:
    tenant, a, b = await _two_records(factory)

    await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b, relation_type=relation)


@pytest.mark.parametrize("bad", ["derived_from", "RELATED_TO", "", "SUPERSEDES "])
async def test_unknown_relation_type_is_rejected(factory: RowFactory, tx_conn, bad: str) -> None:
    tenant, a, b = await _two_records(factory)

    with pytest.raises(asyncpg.CheckViolationError, match="ck_provenance_edges_relation_type"):
        async with tx_conn.transaction():
            await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b, relation_type=bad)


async def test_duplicate_edge_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, a, b = await _two_records(factory)
    await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b)

    with pytest.raises(asyncpg.UniqueViolationError, match="uq_provenance_edges_tenant_from_to_relation"):
        async with tx_conn.transaction():
            await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b)

    assert await tx_conn.fetchval(
        "SELECT count(*) FROM provenance_edges WHERE from_record_id = $1 AND to_record_id = $2", a, b
    ) == 1


async def test_duplicate_through_update_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, a, b = await _two_records(factory)
    await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b)
    other = await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b,
                                 relation_type="SUPERSEDES")

    with pytest.raises(asyncpg.UniqueViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE provenance_edges SET relation_type = 'DERIVED_FROM' WHERE id = $1", other)


async def test_same_pair_with_another_relation_type_is_allowed(factory: RowFactory, tx_conn) -> None:
    tenant, a, b = await _two_records(factory)

    for relation in RELATION_TYPES:
        await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b, relation_type=relation)

    assert await tx_conn.fetchval("SELECT count(*) FROM provenance_edges WHERE from_record_id = $1", a) == 3


async def test_direction_is_not_normalised(factory: RowFactory, tx_conn) -> None:
    """A->B and B->A are different edges (cycle detection stays in M3's service code)."""
    tenant, a, b = await _two_records(factory)

    await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b)
    await factory.create("provenance_edges", tenant, from_record_id=b, to_record_id=a)

    rows = await tx_conn.fetch(
        "SELECT from_record_id, to_record_id FROM provenance_edges WHERE tenant_id = $1", tenant
    )
    assert {(r["from_record_id"], r["to_record_id"]) for r in rows} == {(a, b), (b, a)}


async def test_self_loop_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, a, _ = await _two_records(factory)

    with pytest.raises(asyncpg.CheckViolationError, match="ck_provenance_edges_no_self_loop"):
        async with tx_conn.transaction():
            await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=a)


async def test_self_loop_through_update_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, a, b = await _two_records(factory)
    edge = await factory.create("provenance_edges", tenant, from_record_id=a, to_record_id=b)

    with pytest.raises(asyncpg.CheckViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE provenance_edges SET to_record_id = $1 WHERE id = $2", a, edge)


async def test_identical_edge_in_two_tenants_is_independent(factory: RowFactory, tx_conn) -> None:
    """Uniqueness is per tenant; record ids differ per tenant anyway, so each tenant keeps its own edges."""
    tenant_a, a1, a2 = await _two_records(factory)
    tenant_b, b1, b2 = await _two_records(factory)

    await factory.create("provenance_edges", tenant_a, from_record_id=a1, to_record_id=a2)
    await factory.create("provenance_edges", tenant_b, from_record_id=b1, to_record_id=b2)

    assert await tx_conn.fetchval(
        "SELECT count(*) FROM provenance_edges WHERE tenant_id = ANY($1::varchar[])", [tenant_a, tenant_b]
    ) == 2
