"""Migration lifecycle tests (Day 1 exit gate + Day 7 forward/backward).

Owner: M6
- The migration chain applies cleanly to a blank database.
- upgrade head -> downgrade base -> upgrade head works with no leftovers.
- SQLAlchemy models and the migrated schema are identical (no drift).
"""

import asyncio

import asyncpg
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
