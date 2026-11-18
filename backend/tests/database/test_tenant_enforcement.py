"""Behavioural proof that PostgreSQL itself rejects rows without a valid tenant.

Owner: M6
Raw SQL is used on purpose: the database must enforce the rule even when the
application layer (ORM, repositories) is bypassed.
"""

import uuid

import asyncpg
import pytest

pytestmark = pytest.mark.asyncio


def _id() -> str:
    return str(uuid.uuid4())


async def _make_tenant(conn: asyncpg.Connection) -> str:
    tenant_id = _id()
    await conn.execute(
        "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
        tenant_id, "Company", f"co-{tenant_id[:8]}",
    )
    return tenant_id


async def test_insert_with_valid_tenant_succeeds_and_applies_defaults(conn: asyncpg.Connection) -> None:
    tenant_id = await _make_tenant(conn)
    agent_id = _id()

    await conn.execute(
        "INSERT INTO agents (id, tenant_id, name) VALUES ($1, $2, $3)", agent_id, tenant_id, "Treasury Bot"
    )

    row = await conn.fetchrow("SELECT status, runtime, created_at FROM agents WHERE id = $1", agent_id)
    assert row["status"] == "ACTIVE"
    assert row["runtime"] == "LANGCHAIN"
    assert row["created_at"] is not None


async def test_insert_without_tenant_id_is_rejected(conn: asyncpg.Connection) -> None:
    with pytest.raises(asyncpg.NotNullViolationError):
        await conn.execute("INSERT INTO agents (id, name) VALUES ($1, $2)", _id(), "Orphan Bot")


async def test_insert_with_unknown_tenant_is_rejected(conn: asyncpg.Connection) -> None:
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await conn.execute(
            "INSERT INTO agents (id, tenant_id, name) VALUES ($1, $2, $3)", _id(), _id(), "Ghost Bot"
        )


async def test_global_role_may_have_null_tenant(conn: asyncpg.Connection) -> None:
    await conn.execute("INSERT INTO roles (id, tenant_id, name) VALUES ($1, NULL, $2)", _id(), "AUDITOR")
    assert await conn.fetchval("SELECT count(*) FROM roles WHERE tenant_id IS NULL") == 1


async def test_tenant_slug_is_unique(conn: asyncpg.Connection) -> None:
    await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'A', 'chrono')", _id())
    with pytest.raises(asyncpg.UniqueViolationError):
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'B', 'chrono')", _id())
