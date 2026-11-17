"""Migration lifecycle tests (Day 1 exit gate + Day 7 forward/backward).

Owner: M6
- The migration chain applies cleanly to a blank database.
- upgrade head -> downgrade base -> upgrade head works with no leftovers.
- SQLAlchemy models and the migrated schema are identical (no drift).
"""

import asyncio
import uuid

import asyncpg
import pytest
from alembic.autogenerate import compare_metadata
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
