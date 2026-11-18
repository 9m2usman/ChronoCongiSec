"""Database-level append-only guarantees for audit_events (migration 0004).

Owner: M6. Raw SQL is intentional: repository-level restrictions are insufficient.

Every rejection must come from the append-only trigger itself: SQLSTATE 55000
(object_not_in_prerequisite_state, ``asyncpg.ObjectNotInPrerequisiteStateError``)
with the trigger's message. A broad ``PostgresError`` would also accept unrelated
failures and could hide a missing trigger.
"""

import asyncpg
import pytest

pytestmark = pytest.mark.asyncio

APPEND_ONLY_SQLSTATE = "55000"


def _rejected(operation: str):
    return pytest.raises(
        asyncpg.ObjectNotInPrerequisiteStateError,
        match=f"audit_events is append-only; {operation} is forbidden",
    )


async def _snapshot(tx_conn, event_id: str):
    return await tx_conn.fetchrow(
        "SELECT tenant_id, actor_id, event_type, resource_id, action, outcome, details_json "
        "FROM audit_events WHERE id = $1",
        event_id,
    )


async def test_audit_event_insert_is_allowed(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)

    assert await _snapshot(tx_conn, event_id) is not None


async def test_audit_event_update_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)
    before = await _snapshot(tx_conn, event_id)

    with _rejected("UPDATE") as exc_info:
        async with tx_conn.transaction():
            await tx_conn.execute(
                "UPDATE audit_events SET action = 'TAMPERED' WHERE id = $1",
                event_id,
            )

    assert exc_info.value.sqlstate == APPEND_ONLY_SQLSTATE
    assert await _snapshot(tx_conn, event_id) == before


async def test_audit_event_delete_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)
    before = await _snapshot(tx_conn, event_id)

    with _rejected("DELETE") as exc_info:
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM audit_events WHERE id = $1", event_id)

    assert exc_info.value.sqlstate == APPEND_ONLY_SQLSTATE
    assert await _snapshot(tx_conn, event_id) == before


async def test_audit_event_truncate_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)
    before = await _snapshot(tx_conn, event_id)

    with _rejected("TRUNCATE") as exc_info:
        async with tx_conn.transaction():
            await tx_conn.execute("TRUNCATE TABLE audit_events")

    assert exc_info.value.sqlstate == APPEND_ONLY_SQLSTATE
    assert await _snapshot(tx_conn, event_id) == before


async def test_truncate_cascade_from_tenants_is_rejected(factory, tx_conn) -> None:
    """TRUNCATE ... CASCADE reaches audit_events through its FK and must still be refused."""
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)

    with _rejected("TRUNCATE"):
        async with tx_conn.transaction():
            await tx_conn.execute("TRUNCATE TABLE tenants CASCADE")

    assert await _snapshot(tx_conn, event_id) is not None


async def test_append_only_triggers_are_installed_and_enabled(tx_conn) -> None:
    rows = await tx_conn.fetch(
        """
        SELECT t.tgname, t.tgenabled::text AS enabled
        FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        WHERE c.relname = 'audit_events' AND NOT t.tgisinternal
          AND t.tgname IN ('trg_audit_events_no_update_delete', 'trg_audit_events_no_truncate')
        """
    )
    assert {r["tgname"]: r["enabled"] for r in rows} == {
        "trg_audit_events_no_update_delete": "O",
        "trg_audit_events_no_truncate": "O",
    }
