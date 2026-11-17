"""Tenant-ownership rules, verified against the REAL migrated PostgreSQL schema.

Owner: M6
HARD RULE (AMSC-DOC-005 §1, DOC-006 M6 constraint): every tenant-owned table has a
non-nullable ``tenant_id`` FK to ``tenants.id``. Only ``roles.tenant_id`` may be
NULL (platform-global roles). Global tables are listed explicitly.
"""

import asyncpg
import pytest

from backend.app.database.models import GLOBAL_TABLES, NULLABLE_TENANT_TABLES

pytestmark = pytest.mark.asyncio


async def _tables(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
    )
    return {r["tablename"] for r in rows}


async def _tenant_id_columns(conn: asyncpg.Connection) -> dict[str, bool]:
    """table -> is_nullable for every public.<table>.tenant_id column."""
    rows = await conn.fetch(
        """
        SELECT table_name, is_nullable = 'YES' AS nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' AND column_name = 'tenant_id'
        """
    )
    return {r["table_name"]: r["nullable"] for r in rows}


async def _tables_with_tenant_fk(conn: asyncpg.Connection) -> set[str]:
    """Tables whose FK set includes one where tenant_id references tenants.id."""
    rows = await conn.fetch(
        """
        SELECT DISTINCT src.relname AS table_name
        FROM pg_constraint c
        JOIN pg_class src ON src.oid = c.conrelid
        JOIN pg_class ref ON ref.oid = c.confrelid
        JOIN pg_namespace n ON n.oid = src.relnamespace
        JOIN LATERAL unnest(c.conkey, c.confkey) AS k(src_attnum, ref_attnum) ON TRUE
        JOIN pg_attribute sa ON sa.attrelid = c.conrelid AND sa.attnum = k.src_attnum
        JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.ref_attnum
        WHERE c.contype = 'f' AND n.nspname = 'public'
          AND ref.relname = 'tenants'
          AND sa.attname = 'tenant_id' AND ra.attname = 'id'
          AND array_length(c.conkey, 1) = 1
        """
    )
    return {r["table_name"] for r in rows}


async def test_every_table_is_tenant_owned_or_explicitly_global(ro_conn: asyncpg.Connection) -> None:
    tables = await _tables(ro_conn)
    tenant_cols = await _tenant_id_columns(ro_conn)

    unclassified = tables - GLOBAL_TABLES - set(tenant_cols)
    assert unclassified == set(), (
        f"Tables with no tenant_id that are not in GLOBAL_TABLES: {sorted(unclassified)}"
    )


async def test_global_tables_have_no_tenant_id(ro_conn: asyncpg.Connection) -> None:
    tables = await _tables(ro_conn)
    tenant_cols = await _tenant_id_columns(ro_conn)

    assert GLOBAL_TABLES <= tables, "GLOBAL_TABLES lists a table that does not exist"
    assert GLOBAL_TABLES.isdisjoint(tenant_cols), (
        "A table declared global carries tenant_id; classify it as tenant-owned instead"
    )


async def test_tenant_id_is_not_null_except_global_roles(ro_conn: asyncpg.Connection) -> None:
    tenant_cols = await _tenant_id_columns(ro_conn)

    nullable = {table for table, is_nullable in tenant_cols.items() if is_nullable}
    assert nullable == set(NULLABLE_TENANT_TABLES), (
        f"tenant_id must be NOT NULL; unexpected nullable tables: {sorted(nullable - NULLABLE_TENANT_TABLES)}"
    )


async def test_every_tenant_id_references_tenants(ro_conn: asyncpg.Connection) -> None:
    tenant_cols = await _tenant_id_columns(ro_conn)
    with_fk = await _tables_with_tenant_fk(ro_conn)

    missing = set(tenant_cols) - with_fk
    assert missing == set(), f"tenant_id without FK to tenants.id: {sorted(missing)}"
