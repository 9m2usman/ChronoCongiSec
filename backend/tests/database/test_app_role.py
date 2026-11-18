"""Least-privilege application role (backend.app.database.roles), proven with a temporary role.

Owner: M6
A throwaway LOGIN role ``amsc_test_role_<hex>`` is created with the real
``app_role_create_statement``, given the real ``app_role_grant_statements`` in the module's
temporary database, used for the checks, and always dropped. Nothing touches docker-compose,
.env or the dev database (OD-18: provisioning the real role belongs to M7).
"""

import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest
import pytest_asyncio

from backend.app.database import roles
from backend.tests.database import helpers

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def seeded(module_db: str) -> dict[str, str]:
    """Committed rows (as the superuser) that the app role will work with."""
    ids = {k: str(uuid.uuid4()) for k in ("tenant", "agent", "proposal", "decision", "audit")}
    conn = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
    try:
        t = ids["tenant"]
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, 'Co', $2)", t, "co-" + t[:8])
        await conn.execute("INSERT INTO agents (id, tenant_id, name) VALUES ($1, $2, 'bot')", ids["agent"], t)
        await conn.execute(
            "INSERT INTO tool_proposals (id, tenant_id, agent_id, action_id, tool_name, operation, idempotency_key, "
            "trace_id) VALUES ($1, $2, $3, 'a', 't', 'o', $1, 'tr')", ids["proposal"], t, ids["agent"])
        await conn.execute(
            "INSERT INTO policy_decisions (id, tenant_id, proposal_id, decision, memory_trust, policy_result) "
            "VALUES ($1, $2, $3, 'X', 'X', 'X')", ids["decision"], t, ids["proposal"])
        await conn.execute(
            "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome) "
            "VALUES ($1, $2, 'a', 'e', 'r', 'x', 'o')", ids["audit"], t)
    finally:
        await conn.close()
    return ids


@pytest_asyncio.fixture
async def app_conn(module_db: str) -> AsyncIterator[asyncpg.Connection]:
    """A connection logged in as a fresh, least-privilege application role."""
    name, password = await helpers.create_temp_login_role(roles.app_role_create_statement)
    try:
        admin = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
        try:
            for statement in roles.app_role_grant_statements(name):
                await admin.execute(statement)
        finally:
            await admin.close()
        conn = await asyncpg.connect(helpers.role_dsn(module_db, name, password))
        try:
            yield conn
        finally:
            await conn.close()
    finally:
        await helpers.drop_temp_login_role(name, [module_db])


# -- role definition ---------------------------------------------------------------------------


async def test_app_role_has_no_dangerous_attributes_and_owns_nothing(app_conn) -> None:
    name = await app_conn.fetchval("SELECT current_user")
    attrs = await app_conn.fetchrow(roles.APP_ROLE_ATTRIBUTES_SQL.replace("$1", f"'{name}'"))

    assert dict(attrs) == {
        "rolsuper": False, "rolcreatedb": False, "rolcreaterole": False,
        "rolreplication": False, "rolbypassrls": False,
    }
    assert await app_conn.fetchval(roles.TABLES_OWNED_BY_ROLE_SQL.replace("$1", f"'{name}'")) == 0


# -- audit_events: append-only, and the triggers cannot be switched off ---------------------------


async def test_app_role_can_append_audit_events_and_gets_a_chain(app_conn, seeded) -> None:
    event = str(uuid.uuid4())

    await app_conn.execute(
        "INSERT INTO audit_events (id, tenant_id, actor_id, event_type, resource_id, action, outcome) "
        "VALUES ($1, $2, 'a', 'e', 'r', 'x', 'o')", event, seeded["tenant"])

    row = await app_conn.fetchrow("SELECT chain_seq, prev_hash FROM audit_events WHERE id = $1", event)
    assert row["chain_seq"] == 2 and row["prev_hash"] is not None
    assert await app_conn.fetchval("SELECT amsc_audit_chain_break($1)", seeded["tenant"]) is None


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'TAMPERED' WHERE tenant_id = '{t}'",
        "DELETE FROM audit_events WHERE tenant_id = '{t}'",
        "TRUNCATE audit_events",
        "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_update_delete",
        "DROP TRIGGER trg_audit_events_no_update_delete ON audit_events",
        "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_chain",
        "SET session_replication_role = replica",
    ],
    ids=["update", "delete", "truncate", "disable-append-only", "drop-trigger", "disable-chain", "replica-mode"],
)
async def test_app_role_cannot_tamper_with_audit_events(app_conn, seeded, statement: str) -> None:
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(statement.format(t=seeded["tenant"]))

    assert await app_conn.fetchval("SELECT count(*) FROM audit_events WHERE id = $1", seeded["audit"]) == 1


# -- policy_decisions: permanent except execution_status ---------------------------------------------


async def test_app_role_can_update_execution_status(app_conn, seeded) -> None:
    await app_conn.execute(
        "UPDATE policy_decisions SET execution_status = 'TEST_STATUS' WHERE id = $1", seeded["decision"])

    assert await app_conn.fetchval(
        "SELECT execution_status FROM policy_decisions WHERE id = $1", seeded["decision"]) == "TEST_STATUS"


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE policy_decisions SET decision = 'CHANGED' WHERE id = $1",
        "DELETE FROM policy_decisions WHERE id = $1",
    ],
    ids=["update-decision", "delete"],
)
async def test_app_role_cannot_change_or_delete_decisions(app_conn, seeded, statement: str) -> None:
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(statement, seeded["decision"])


# -- ordinary work still works; everything else is refused ---------------------------------------------


async def test_app_role_can_do_ordinary_dml(app_conn, seeded) -> None:
    agent = str(uuid.uuid4())

    await app_conn.execute("INSERT INTO agents (id, tenant_id, name) VALUES ($1, $2, 'bot2')", agent, seeded["tenant"])
    await app_conn.execute("UPDATE agents SET status = 'ISOLATED' WHERE id = $1", agent)
    await app_conn.execute("DELETE FROM agents WHERE id = $1", agent)

    assert await app_conn.fetchval("SELECT count(*) FROM agents WHERE id = $1", agent) == 0


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE TABLE intruder (id int)",
        "SELECT version_num FROM alembic_version",
        "TRUNCATE agents",
        "ALTER TABLE agents DISABLE TRIGGER trg_forbid_tenant_id_change",
    ],
    ids=["create-table", "read-alembic-version", "truncate", "disable-tenant-trigger"],
)
async def test_app_role_cannot_change_schema_or_bypass_triggers(app_conn, statement: str) -> None:
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(statement)


async def test_app_role_can_read_the_protection_report(app_conn, seeded) -> None:
    rows = await app_conn.fetch("SELECT check_name, ok FROM amsc_audit_protection_report()")

    assert rows and all(r["ok"] for r in rows)


# -- SQL generation ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", ["", "App", "amsc-app", 'x"; DROP TABLE agents; --', "a" * 64, "1app", None, "app role"],
)
async def test_invalid_role_names_are_refused(bad) -> None:
    with pytest.raises(ValueError):
        roles.app_role_create_statement(bad)
    with pytest.raises(ValueError):
        roles.app_role_grant_statements("amsc_app", owner_role=bad if bad is not None else "Bad")


async def test_provisioning_script_content() -> None:
    script = roles.app_role_script("amsc_app", owner_role="amsc_owner")

    assert 'CREATE ROLE "amsc_app" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' in script
    assert 'GRANT SELECT, INSERT ON TABLE public.audit_events TO "amsc_app"' in script
    assert 'GRANT SELECT, INSERT, UPDATE (execution_status) ON TABLE public.policy_decisions TO "amsc_app"' in script
    assert 'REVOKE ALL ON TABLE public.alembic_version FROM "amsc_app"' in script
    assert 'ALTER DEFAULT PRIVILEGES FOR ROLE "amsc_owner"' in script
    assert "PASSWORD" not in script.upper(), "passwords are set by M7, never generated here"


async def test_no_temporary_roles_are_left_behind(module_db: str) -> None:
    conn = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
    try:
        leftovers = await conn.fetchval(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE $1", helpers.TEMP_ROLE_PREFIX + "%")
    finally:
        await conn.close()
    assert leftovers == 0


async def test_role_guard_refuses_non_test_roles() -> None:
    for name in ("amsc", "postgres", "amsc_app", "amsc_test_role_", "amsc_test_role_XYZ"):
        with pytest.raises(helpers.UnsafeTestDatabaseError):
            helpers.check_temp_role_name(name)
