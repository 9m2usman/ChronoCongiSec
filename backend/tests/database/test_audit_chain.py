"""Per-tenant hash chain on audit_events and the audit verification functions (migration 0009).

Owner: M6
Tamper scenarios simulate a privileged attacker: inside the test transaction (always rolled
back) the superuser test connection pauses the append-only trigger, changes rows, and the
verification function must point at the first broken link.
"""

import asyncio
import uuid

import asyncpg
import pytest

from backend.app.database.models import AuditEvent, Tenant
from backend.app.database.unit_of_work import UnitOfWork
from backend.tests.database import helpers
from backend.tests.database.factory import RowFactory

pytestmark = pytest.mark.asyncio

HASH_SQL = (
    "SELECT amsc_audit_event_hash(prev_hash, tenant_id, id, actor_id, event_type, resource_id, action, outcome, "
    "trace_id, details_json, occurred_at) FROM audit_events WHERE id = $1"
)


async def _events(factory: RowFactory, tenant: str, count: int) -> list[str]:
    return [await factory.create("audit_events", tenant) for _ in range(count)]


async def _chain(tx_conn, tenant: str) -> list[asyncpg.Record]:
    return await tx_conn.fetch(
        "SELECT id, chain_seq, prev_hash, event_hash FROM audit_events WHERE tenant_id = $1 ORDER BY chain_seq", tenant
    )


async def _break(tx_conn, tenant: str):
    return await tx_conn.fetchval("SELECT amsc_audit_chain_break($1)", tenant)


async def _pause_append_only(tx_conn) -> None:
    # Superuser-only; happens inside the test transaction and is rolled back with it.
    await tx_conn.execute("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update_delete")


# -- chain construction ------------------------------------------------------------------------


async def test_each_tenant_gets_its_own_linked_chain(factory: RowFactory, tx_conn) -> None:
    tenant_a, tenant_b = await factory.tenant(), await factory.tenant()
    ids_a = await _events(factory, tenant_a, 3)
    await _events(factory, tenant_b, 2)

    chain_a, chain_b = await _chain(tx_conn, tenant_a), await _chain(tx_conn, tenant_b)

    assert [r["chain_seq"] for r in chain_a] == [1, 2, 3]
    assert [r["chain_seq"] for r in chain_b] == [1, 2]
    assert [r["id"] for r in chain_a] == ids_a
    assert chain_a[0]["prev_hash"] is None
    assert chain_a[1]["prev_hash"] == chain_a[0]["event_hash"]
    assert chain_a[2]["prev_hash"] == chain_a[1]["event_hash"]
    for row in chain_a:
        assert row["event_hash"] == await tx_conn.fetchval(HASH_SQL, row["id"])


async def test_caller_supplied_chain_values_are_ignored(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()

    event = await factory.create("audit_events", tenant, chain_seq=99, prev_hash="f" * 64, event_hash="0" * 64)

    row = await tx_conn.fetchrow("SELECT chain_seq, prev_hash, event_hash FROM audit_events WHERE id = $1", event)
    assert (row["chain_seq"], row["prev_hash"]) == (1, None)
    assert row["event_hash"] == await tx_conn.fetchval(HASH_SQL, event)


async def test_hash_covers_every_audit_field(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    (event,) = await _events(factory, tenant, 1)
    base = await tx_conn.fetchrow("SELECT * FROM audit_events WHERE id = $1", event)
    original = await tx_conn.fetchval(HASH_SQL, event)

    variants = {
        "actor_id": "other", "event_type": "other", "resource_id": "other", "action": "other",
        "outcome": "other", "trace_id": "other",
    }
    for column, value in variants.items():
        args = [base["prev_hash"], base["tenant_id"], base["id"], base["actor_id"], base["event_type"],
                base["resource_id"], base["action"], base["outcome"], base["trace_id"], base["details_json"],
                base["occurred_at"]]
        index = ["prev_hash", "tenant_id", "id", "actor_id", "event_type", "resource_id", "action", "outcome",
                 "trace_id", "details_json", "occurred_at"].index(column)
        args[index] = value
        changed = await tx_conn.fetchval(
            "SELECT amsc_audit_event_hash($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)", *args
        )
        assert changed != original, f"{column} is not covered by the hash"


async def test_intact_chain_reports_no_break(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    await _events(factory, tenant, 4)

    assert await _break(tx_conn, tenant) is None
    assert await _break(tx_conn, str(uuid.uuid4())) is None  # unknown tenant: empty chain


# -- tamper detection ---------------------------------------------------------------------------


async def test_edited_event_is_detected(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    ids = await _events(factory, tenant, 3)
    await _pause_append_only(tx_conn)

    await tx_conn.execute("UPDATE audit_events SET action = 'TAMPERED' WHERE id = $1", ids[1])

    assert await _break(tx_conn, tenant) == 2


async def test_edit_with_recomputed_hash_is_detected_at_the_next_link(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    ids = await _events(factory, tenant, 3)
    await _pause_append_only(tx_conn)

    await tx_conn.execute("UPDATE audit_events SET action = 'TAMPERED' WHERE id = $1", ids[1])
    await tx_conn.execute(
        "UPDATE audit_events SET event_hash = amsc_audit_event_hash(prev_hash, tenant_id, id, actor_id, event_type, "
        "resource_id, action, outcome, trace_id, details_json, occurred_at) WHERE id = $1", ids[1],
    )

    assert await _break(tx_conn, tenant) == 3


async def test_deleted_event_in_the_middle_is_detected(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    ids = await _events(factory, tenant, 3)
    await _pause_append_only(tx_conn)

    await tx_conn.execute("DELETE FROM audit_events WHERE id = $1", ids[1])

    assert await _break(tx_conn, tenant) == 2


async def test_tail_truncation_is_not_detectable_without_an_external_anchor(factory: RowFactory, tx_conn) -> None:
    """Documented limit (OD-26): removing the LAST event leaves a valid shorter chain."""
    tenant = await factory.tenant()
    ids = await _events(factory, tenant, 3)
    await _pause_append_only(tx_conn)

    await tx_conn.execute("DELETE FROM audit_events WHERE id = $1", ids[2])

    assert await _break(tx_conn, tenant) is None


async def test_chain_constraints_hold_even_if_the_chain_trigger_is_bypassed(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    (first,) = await _events(factory, tenant, 1)
    await tx_conn.execute("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_chain")
    insert = (
        "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome, "
        "chain_seq, prev_hash, event_hash) VALUES ($1, $2, 'a', 'e', 'r', 'x', 'o', $3, $4, $5)"
    )

    with pytest.raises(asyncpg.UniqueViolationError, match="uq_audit_events_tenant_id_chain_seq"):
        async with tx_conn.transaction():
            await tx_conn.execute(insert, str(uuid.uuid4()), tenant, 1, None, "0" * 64)
    with pytest.raises(asyncpg.CheckViolationError, match="ck_audit_events_chain_link"):
        async with tx_conn.transaction():
            await tx_conn.execute(insert, str(uuid.uuid4()), tenant, 2, None, "0" * 64)
    with pytest.raises(asyncpg.CheckViolationError, match="ck_audit_events_chain_link"):
        async with tx_conn.transaction():
            await tx_conn.execute(insert, str(uuid.uuid4()), tenant, 1, "f" * 64, "0" * 64)
    assert first


# -- protection report ---------------------------------------------------------------------------


async def _report(tx_conn) -> dict[str, bool]:
    rows = await tx_conn.fetch("SELECT check_name, ok FROM amsc_audit_protection_report()")
    return {r["check_name"]: r["ok"] for r in rows}


async def test_protection_report_is_all_green_on_a_healthy_database(factory: RowFactory, tx_conn) -> None:
    await _events(factory, await factory.tenant(), 2)

    report = await _report(tx_conn)

    assert report == {
        "trigger trg_audit_events_no_update_delete": True,
        "trigger trg_audit_events_no_truncate": True,
        "trigger trg_audit_events_chain": True,
        "trigger trg_forbid_tenant_id_change": True,
        "hash chains intact": True,
    }


async def test_protection_report_flags_a_disabled_trigger_and_a_broken_chain(factory: RowFactory, tx_conn) -> None:
    tenant = await factory.tenant()
    ids = await _events(factory, tenant, 2)
    await _pause_append_only(tx_conn)
    await tx_conn.execute("UPDATE audit_events SET outcome = 'TAMPERED' WHERE id = $1", ids[0])

    report = await _report(tx_conn)
    detail = await tx_conn.fetchval(
        "SELECT detail FROM amsc_audit_protection_report() WHERE check_name = 'hash chains intact'"
    )

    assert report["trigger trg_audit_events_no_update_delete"] is False
    assert report["hash chains intact"] is False and tenant in detail


# -- concurrency (real commits) ----------------------------------------------------------------------


async def test_concurrent_inserts_produce_one_gapless_chain(module_db: str) -> None:
    tenant = str(uuid.uuid4())
    admin = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
    try:
        await admin.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Co', $2)", tenant, "co-" + tenant[:8])

        async def insert_one() -> None:
            conn = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
            try:
                await conn.execute(
                    "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome) "
                    "VALUES ($1, $2, 'a', 'e', 'r', 'x', 'o')", str(uuid.uuid4()), tenant,
                )
            finally:
                await conn.close()

        await asyncio.gather(*(insert_one() for _ in range(12)))

        seqs = [r["chain_seq"] for r in await admin.fetch(
            "SELECT chain_seq FROM audit_events WHERE tenant_id = $1 ORDER BY chain_seq", tenant)]
        assert seqs == list(range(1, 13))
        assert await admin.fetchval("SELECT amsc_audit_chain_break($1)", tenant) is None
    finally:
        await admin.close()


# -- repository ---------------------------------------------------------------------------------------


async def test_repository_append_returns_database_chain_values(module_db: str) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(helpers.sqlalchemy_url(module_db), poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    tenant = str(uuid.uuid4())
    try:
        async with factory() as session, session.begin():
            session.add(Tenant(id=tenant, name="Co", slug=f"co-{tenant[:8]}"))
        uow = UnitOfWork(factory)

        def event() -> AuditEvent:
            return AuditEvent(id=str(uuid.uuid4()), actor_id="a", event_type="e", resource_id="r",
                              action="x", outcome="o")

        async with uow(tenant) as tx:
            first = await tx.audit.append(event())
            second = await tx.audit.append(event())
            with pytest.raises(ValueError, match="assigned by the database"):
                forged = event()
                forged.chain_seq = 7
                await tx.audit.append(forged)

        assert (first.chain_seq, second.chain_seq) == (1, 2)
        assert first.prev_hash is None and second.prev_hash == first.event_hash
        async with uow(tenant) as tx:
            assert [e.chain_seq for e in await tx.audit.list_recent()] == [2, 1]
            assert await tx.audit.chain_break() is None
    finally:
        await engine.dispose()
