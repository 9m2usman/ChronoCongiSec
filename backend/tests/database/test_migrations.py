"""Migration lifecycle tests (Day 1 exit gate + Day 7 forward/backward).

Owner: M6
- The migration chain applies cleanly to a blank database.
- upgrade head -> downgrade base -> upgrade head works with no leftovers.
- SQLAlchemy models and the migrated schema are identical (no drift).
"""

import asyncio
import io
import uuid

import asyncpg
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import backend.app.database.models  # noqa: F401
from backend.app.database.base import Base
from backend.tests.database import helpers

EXPECTED_TABLE_COUNT = 36


async def _public_tables(database: str) -> set[str]:
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        rows = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
        return {r["tablename"] for r in rows}
    finally:
        await conn.close()


async def _schema_diff(database: str) -> list:
    engine = create_async_engine(helpers.sqlalchemy_url(database), poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            def _compare(sync_conn):
                ctx = MigrationContext.configure(
                    sync_conn, opts={"compare_server_default": True, "compare_type": True}
                )
                return compare_metadata(ctx, Base.metadata)

            return await connection.run_sync(_compare)
    finally:
        await engine.dispose()


def test_migration_chain_has_single_head() -> None:
    script = ScriptDirectory.from_config(helpers.alembic_config("unused"))
    assert len(script.get_heads()) == 1, "Migration history must not branch"


def test_upgrade_head_applies_to_blank_database(empty_db: str) -> None:
    assert asyncio.run(_public_tables(empty_db)) == set()

    helpers.upgrade(empty_db, "head")

    tables = asyncio.run(_public_tables(empty_db)) - {"alembic_version"}
    assert tables == set(Base.metadata.tables)
    assert len(tables) == EXPECTED_TABLE_COUNT


def test_upgrade_downgrade_upgrade_roundtrip(empty_db: str) -> None:
    helpers.upgrade(empty_db, "head")
    helpers.downgrade(empty_db, "base")

    # Only Alembic's own bookkeeping table may survive a full downgrade.
    assert asyncio.run(_public_tables(empty_db)) <= {"alembic_version"}

    helpers.upgrade(empty_db, "head")
    tables = asyncio.run(_public_tables(empty_db)) - {"alembic_version"}
    assert len(tables) == EXPECTED_TABLE_COUNT


def test_models_match_migrated_schema(migrated_db: str) -> None:
    diff = asyncio.run(_schema_diff(migrated_db))
    assert diff == [], f"Models and migrations have drifted: {diff}"


# ---------------------------------------------------------------------------
# Migration 0003 on a database that already contains data
# ---------------------------------------------------------------------------

_SEED_KEYS = ("tenant", "user", "outsider", "membership", "agent", "proposal", "decision", "approval", "audit")


async def _seed_at_0002(database: str, *, approver_is_member: bool = True) -> dict[str, str]:
    """Rows written with the 0002 schema (no membership status yet)."""
    ids = {k: str(uuid.uuid4()) for k in _SEED_KEYS}
    approver = ids["user"] if approver_is_member else ids["outsider"]
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, 'Co', $2)", ids["tenant"], "co-" + ids["tenant"][:8]
        )
        for key in ("user", "outsider"):
            await conn.execute(
                "INSERT INTO users (id, email, hashed_password, full_name) VALUES ($1, $2, 'x', 'U')",
                ids[key], ids[key][:8] + "@example.com",
            )
        await conn.execute(
            "INSERT INTO memberships (id, tenant_id, user_id, role) VALUES ($1, $2, $3, 'AUDITOR')",
            ids["membership"], ids["tenant"], ids["user"],
        )
        await conn.execute(
            "INSERT INTO agents (id, tenant_id, name) VALUES ($1, $2, 'bot')", ids["agent"], ids["tenant"]
        )
        await conn.execute(
            "INSERT INTO tool_proposals (id, tenant_id, agent_id, action_id, tool_name, operation, "
            "idempotency_key, trace_id) VALUES ($1, $2, $3, 'a', 't', 'o', $1, 'tr')",
            ids["proposal"], ids["tenant"], ids["agent"],
        )
        await conn.execute(
            "INSERT INTO policy_decisions (id, tenant_id, proposal_id, decision, memory_trust, policy_result) "
            "VALUES ($1, $2, $3, 'D', 'M', 'P')",
            ids["decision"], ids["tenant"], ids["proposal"],
        )
        await conn.execute(
            "INSERT INTO approvals (id, tenant_id, decision_id, approver_user_id) VALUES ($1, $2, $3, $4)",
            ids["approval"], ids["tenant"], ids["decision"], approver,
        )
        await conn.execute(
            "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome) "
            "VALUES ($1, $2, 'u', 'E', 'r', 'a', 'o')",
            ids["audit"], ids["tenant"],
        )
    finally:
        await conn.close()
    return ids


async def _fetchrow(database: str, sql: str, *args):
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        return await conn.fetchrow(sql, *args)
    finally:
        await conn.close()


async def _insert_membership(database: str, tenant_id: str, user_id: str) -> str:
    """Insert a membership without a status; return the status the database chose."""
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        membership_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO memberships (id, tenant_id, user_id) VALUES ($1, $2, $3)", membership_id, tenant_id, user_id
        )
        return await conn.fetchval("SELECT status FROM memberships WHERE id = $1", membership_id)
    finally:
        await conn.close()


def test_0003_preserves_existing_data_and_never_activates_old_memberships(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0002")
    ids = asyncio.run(_seed_at_0002(empty_db))

    helpers.upgrade(empty_db, "0003")

    m = asyncio.run(_fetchrow(empty_db, "SELECT * FROM memberships WHERE id = $1", ids["membership"]))
    assert (m["tenant_id"], m["user_id"], m["role"]) == (ids["tenant"], ids["user"], "AUDITOR")
    assert m["status"] == "INACTIVE", "pre-existing memberships must not be silently activated"
    a = asyncio.run(_fetchrow(empty_db, "SELECT * FROM approvals WHERE id = $1", ids["approval"]))
    assert (a["decision_id"], a["approver_user_id"]) == (ids["decision"], ids["user"])
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM audit_events WHERE id = $1", ids["audit"])) is not None

    # Rows written after the upgrade default to ACTIVE.
    assert asyncio.run(_insert_membership(empty_db, ids["tenant"], ids["outsider"])) == "ACTIVE"


def test_0003_stops_without_changes_when_an_approver_is_not_a_member(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0002")
    ids = asyncio.run(_seed_at_0002(empty_db, approver_is_member=False))

    with pytest.raises(RuntimeError, match="Migration 0003 stopped"):
        helpers.upgrade(empty_db, "0003")

    assert asyncio.run(_fetchrow(empty_db, "SELECT version_num FROM alembic_version"))[0] == "0002"
    status_col = asyncio.run(_fetchrow(
        empty_db,
        "SELECT 1 FROM information_schema.columns WHERE table_name = 'memberships' AND column_name = 'status'",
    ))
    assert status_col is None, "a failed 0003 must leave the 0002 schema untouched"
    a = asyncio.run(_fetchrow(empty_db, "SELECT approver_user_id FROM approvals WHERE id = $1", ids["approval"]))
    assert a["approver_user_id"] == ids["outsider"]


def test_0003_downgrade_keeps_data(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0002")
    ids = asyncio.run(_seed_at_0002(empty_db))
    helpers.upgrade(empty_db, "0003")

    helpers.downgrade(empty_db, "0002")

    m = asyncio.run(_fetchrow(empty_db, "SELECT * FROM memberships WHERE id = $1", ids["membership"]))
    assert m is not None and "status" not in m.keys()
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM approvals WHERE id = $1", ids["approval"])) is not None


# ---------------------------------------------------------------------------
# Migrations 0004 / 0005 on a database that already contains data
# ---------------------------------------------------------------------------


async def _seed_checkpoint_at(database: str, *, mismatched: bool = False) -> dict[str, str]:
    """A tenant with an audit event and one checkpoint item (valid unless ``mismatched``)."""
    ids = {k: str(uuid.uuid4()) for k in ("tenant", "audit", "rec_a", "rec_b", "ver_a", "ver_b", "cp", "item")}
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Co', $2)",
                           ids["tenant"], "co-" + ids["tenant"][:8])
        await conn.execute(
            "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome) "
            "VALUES ($1, $2, 'u', 'E', 'r', 'a', 'o')", ids["audit"], ids["tenant"])
        for rec, ver in (("rec_a", "ver_a"), ("rec_b", "ver_b")):
            await conn.execute("INSERT INTO memory_records (id, tenant_id) VALUES ($1, $2)", ids[rec], ids["tenant"])
            await conn.execute(
                "INSERT INTO memory_versions (id, tenant_id, record_id, version, content, checksum) "
                "VALUES ($1, $2, $3, 1, 'c', 'h')", ids[ver], ids["tenant"], ids[rec])
        await conn.execute("INSERT INTO checkpoints (id, tenant_id, name, integrity_hash) VALUES ($1, $2, 'cp', 'h')",
                           ids["cp"], ids["tenant"])
        version = ids["ver_b"] if mismatched else ids["ver_a"]
        await conn.execute(
            "INSERT INTO checkpoint_items (id, tenant_id, checkpoint_id, record_id, version_id, checksum) "
            "VALUES ($1, $2, $3, $4, $5, 'h')", ids["item"], ids["tenant"], ids["cp"], ids["rec_a"], version)
    finally:
        await conn.close()
    return ids


def test_0004_0005_preserve_existing_data_up_and_down(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0003")
    ids = asyncio.run(_seed_checkpoint_at(empty_db))

    helpers.upgrade(empty_db, "head")

    item = asyncio.run(_fetchrow(empty_db, "SELECT record_id, version_id FROM checkpoint_items WHERE id = $1",
                                 ids["item"]))
    assert (item["record_id"], item["version_id"]) == (ids["rec_a"], ids["ver_a"])
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM audit_events WHERE id = $1", ids["audit"])) is not None

    helpers.downgrade(empty_db, "0003")

    assert asyncio.run(_fetchrow(empty_db, "SELECT version_num FROM alembic_version"))[0] == "0003"
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM checkpoint_items WHERE id = $1", ids["item"])) is not None
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM audit_events WHERE id = $1", ids["audit"])) is not None


def test_0005_refuses_existing_mismatched_checkpoint_item_without_partial_changes(empty_db: str) -> None:
    """0005 has no explicit pre-check: PostgreSQL rejects the FK and the 0005 transaction rolls back."""
    helpers.upgrade(empty_db, "0004")
    ids = asyncio.run(_seed_checkpoint_at(empty_db, mismatched=True))

    with pytest.raises(Exception, match="fk_checkpoint_items_version_matches_record"):
        helpers.upgrade(empty_db, "0005")

    assert asyncio.run(_fetchrow(empty_db, "SELECT version_num FROM alembic_version"))[0] == "0004"
    unique_key = asyncio.run(_fetchrow(
        empty_db, "SELECT 1 FROM pg_constraint WHERE conname = 'uq_memory_versions_tenant_record_id'"))
    assert unique_key is None, "a failed 0005 must not leave its parent key behind"
    assert asyncio.run(_fetchrow(empty_db, "SELECT id FROM checkpoint_items WHERE id = $1", ids["item"])) is not None


# ---------------------------------------------------------------------------
# Migration 0006 (sources.status, provenance edge rules) on existing data
# ---------------------------------------------------------------------------


async def _execute(database: str, *statements: tuple) -> None:
    conn = await asyncpg.connect(helpers.asyncpg_dsn(database))
    try:
        for sql, *args in statements:
            await conn.execute(sql, *args)
    finally:
        await conn.close()


_EDGE_INSERT = (
    "INSERT INTO provenance_edges (id, tenant_id, from_record_id, to_record_id, relation_type) "
    "VALUES ($1, $2, $3, $4, $5)"
)


async def _seed_sources_and_edges_at_0005(database: str) -> dict[str, str]:
    """Rows written with the 0005 schema: two sources and valid edges (incl. both directions)."""
    keys = ("tenant", "src_1", "src_2", "rec_a", "rec_b", "rec_c", "e_ab", "e_ba", "e_ac_t")
    ids = {k: str(uuid.uuid4()) for k in keys}
    t = ids["tenant"]
    await _execute(
        database,
        ("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Co', $2)", t, "co-" + t[:8]),
        ("INSERT INTO sources (id, tenant_id, name) VALUES ($1, $2, 'feed-1')", ids["src_1"], t),
        ("INSERT INTO sources (id, tenant_id, name, trust_state) VALUES ($1, $2, 'feed-2', 'TRUSTED')",
         ids["src_2"], t),
        ("INSERT INTO memory_records (id, tenant_id) VALUES ($1, $2)", ids["rec_a"], t),
        ("INSERT INTO memory_records (id, tenant_id) VALUES ($1, $2)", ids["rec_b"], t),
        ("INSERT INTO memory_records (id, tenant_id) VALUES ($1, $2)", ids["rec_c"], t),
        (_EDGE_INSERT, ids["e_ab"], t, ids["rec_a"], ids["rec_b"], "DERIVED_FROM"),
        (_EDGE_INSERT, ids["e_ba"], t, ids["rec_b"], ids["rec_a"], "DERIVED_FROM"),
        (_EDGE_INSERT, ids["e_ac_t"], t, ids["rec_a"], ids["rec_c"], "TRANSFORMED_INTO"),
    )
    return ids


async def _column_exists(database: str, table: str, column: str) -> bool:
    row = await _fetchrow(
        database,
        "SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2",
        table,
        column,
    )
    return row is not None


async def _count(database: str, table: str, tenant_id: str) -> int:
    return (await _fetchrow(database, f"SELECT count(*) FROM {table} WHERE tenant_id = $1", tenant_id))[0]


def test_0006_keeps_data_and_never_activates_old_sources(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0005")
    ids = asyncio.run(_seed_sources_and_edges_at_0005(empty_db))

    helpers.upgrade(empty_db, "0006")

    for src, trust in (("src_1", "UNVERIFIED"), ("src_2", "TRUSTED")):
        row = asyncio.run(_fetchrow(empty_db, "SELECT status, trust_state FROM sources WHERE id = $1", ids[src]))
        assert row["status"] == "INACTIVE", "pre-existing sources must not be silently activated"
        assert row["trust_state"] == trust, "trust_state must be untouched"
    edges = asyncio.run(_fetchrow(
        empty_db, "SELECT array_agg(id ORDER BY id) AS ids FROM provenance_edges WHERE tenant_id = $1", ids["tenant"]
    ))
    assert edges["ids"] == sorted([ids["e_ab"], ids["e_ba"], ids["e_ac_t"]])

    new_source = str(uuid.uuid4())
    asyncio.run(_execute(
        empty_db, ("INSERT INTO sources (id, tenant_id, name) VALUES ($1, $2, 'new')", new_source, ids["tenant"])
    ))
    assert asyncio.run(_fetchrow(empty_db, "SELECT status FROM sources WHERE id = $1", new_source))[0] == "ACTIVE"


def test_0006_downgrade_drops_status_and_rules_but_keeps_rows(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0005")
    ids = asyncio.run(_seed_sources_and_edges_at_0005(empty_db))
    helpers.upgrade(empty_db, "0006")

    helpers.downgrade(empty_db, "0005")

    assert asyncio.run(_fetchrow(empty_db, "SELECT version_num FROM alembic_version"))[0] == "0005"
    assert not asyncio.run(_column_exists(empty_db, "sources", "status"))
    assert asyncio.run(_count(empty_db, "sources", ids["tenant"])) == 2
    assert asyncio.run(_count(empty_db, "provenance_edges", ids["tenant"])) == 3
    # The 0005 behaviour is back: a duplicate edge is accepted again.
    asyncio.run(_execute(
        empty_db, (_EDGE_INSERT, str(uuid.uuid4()), ids["tenant"], ids["rec_a"], ids["rec_b"], "DERIVED_FROM")
    ))
    # Upgrading again would set every existing source to INACTIVE (documented), but first
    # the pre-check refuses because of the duplicate inserted above.
    with pytest.raises(RuntimeError, match="duplicate edges"):
        helpers.upgrade(empty_db, "0006")


def test_0006_reupgrade_after_downgrade_sets_existing_sources_inactive(empty_db: str) -> None:
    helpers.upgrade(empty_db, "0005")
    ids = asyncio.run(_seed_sources_and_edges_at_0005(empty_db))
    helpers.upgrade(empty_db, "0006")
    asyncio.run(_execute(empty_db, ("UPDATE sources SET status = 'ACTIVE' WHERE id = $1", ids["src_1"])))

    helpers.downgrade(empty_db, "0005")
    helpers.upgrade(empty_db, "0006")

    row = asyncio.run(_fetchrow(empty_db, "SELECT status FROM sources WHERE id = $1", ids["src_1"]))
    assert row["status"] == "INACTIVE", "downgrade discards status; re-activation must be explicit"


@pytest.mark.parametrize("violation", ["duplicate", "self_loop", "bad_relation_type"])
def test_0006_stops_and_lists_offending_ids_without_changing_anything(empty_db: str, violation: str) -> None:
    helpers.upgrade(empty_db, "0005")
    ids = asyncio.run(_seed_sources_and_edges_at_0005(empty_db))
    bad_id = str(uuid.uuid4())
    t = ids["tenant"]
    if violation == "duplicate":
        row = (_EDGE_INSERT, bad_id, t, ids["rec_a"], ids["rec_b"], "DERIVED_FROM")  # same as e_ab
        expected = ["duplicate edges", ids["e_ab"], bad_id]
    elif violation == "self_loop":
        row = (_EDGE_INSERT, bad_id, t, ids["rec_c"], ids["rec_c"], "DERIVED_FROM")
        expected = ["self-loop", bad_id]
    else:
        row = (_EDGE_INSERT, bad_id, t, ids["rec_b"], ids["rec_c"], "RELATED_TO")
        expected = ["unknown relation_type", bad_id]
    asyncio.run(_execute(empty_db, row))

    with pytest.raises(RuntimeError, match="Migration 0006 stopped") as exc_info:
        helpers.upgrade(empty_db, "0006")

    for text in expected:
        assert text in str(exc_info.value)
    assert asyncio.run(_fetchrow(empty_db, "SELECT version_num FROM alembic_version"))[0] == "0005"
    assert not asyncio.run(_column_exists(empty_db, "sources", "status")), "nothing may change on failure"
    assert asyncio.run(_count(empty_db, "provenance_edges", t)) == 4, "no edge may be deleted"


# ---------------------------------------------------------------------------
# Offline mode (``alembic upgrade --sql``): SQL generation only, no connection
# ---------------------------------------------------------------------------

# Never connected to: offline mode only needs the dialect.
OFFLINE_URL = "postgresql+asyncpg://offline@localhost/amsc_test_offline"


def _offline_sql(direction: str, revisions: str) -> str:
    buffer = io.StringIO()
    cfg = Config(str(helpers.ALEMBIC_INI), output_buffer=buffer)
    cfg.attributes["database_url"] = OFFLINE_URL
    cfg.attributes["configure_logger"] = False
    getattr(command, direction)(cfg, revisions, sql=True)
    return buffer.getvalue()


def test_offline_upgrade_generates_sql_for_every_revision() -> None:
    sql = _offline_sql("upgrade", "base:head")

    for marker in (
        "CREATE TABLE tenants",                            # 0001
        "fk_memory_versions_record_id_tenant",             # 0002
        "trg_forbid_tenant_id_change",                     # 0002
        "ck_memberships_status",                           # 0003 (approver pre-check skipped offline)
        "fk_approvals_approver_user_id_tenant",            # 0003
        "trg_audit_events_no_truncate",                    # 0004
        "fk_checkpoint_items_version_matches_record",      # 0005
        "ck_sources_status",                               # 0006 (edge pre-check skipped offline)
        "ck_provenance_edges_no_self_loop",                # 0006
        "uq_provenance_edges_tenant_from_to_relation",     # 0006
    ):
        assert marker in sql, f"offline upgrade SQL is missing {marker}"
    assert "UPDATE alembic_version SET version_num='0006'" in sql


def test_offline_downgrade_generates_sql_back_to_base() -> None:
    sql = _offline_sql("downgrade", "head:base")

    for marker in (
        "DROP CONSTRAINT uq_provenance_edges_tenant_from_to_relation",  # 0006
        "DROP COLUMN status",                                           # 0006 (sources)
        "DROP CONSTRAINT fk_checkpoint_items_version_matches_record",  # 0005
        "DROP TRIGGER IF EXISTS trg_audit_events_no_truncate",          # 0004
        "DROP CONSTRAINT ck_memberships_status",                        # 0003
        "DROP TABLE tenants",                                           # 0001
    ):
        assert marker in sql, f"offline downgrade SQL is missing {marker}"
