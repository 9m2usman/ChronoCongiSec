"""Database-level append-only guarantees for audit_events (migration 0004).

Owner: M6. Raw SQL is intentional: repository-level restrictions are insufficient.
"""

import asyncpg
import pytest

pytestmark = pytest.mark.asyncio


async def test_audit_event_update_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)

    with pytest.raises(asyncpg.PostgresError):
        async with tx_conn.transaction():
            await tx_conn.execute(
                "UPDATE audit_events SET action = 'TAMPERED' WHERE id = $1",
                event_id,
            )

    assert await tx_conn.fetchval(
        "SELECT count(*) FROM audit_events WHERE id = $1", event_id
    ) == 1


async def test_audit_event_delete_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)

    with pytest.raises(asyncpg.PostgresError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM audit_events WHERE id = $1", event_id)

    assert await tx_conn.fetchval(
        "SELECT count(*) FROM audit_events WHERE id = $1", event_id
    ) == 1


async def test_audit_event_truncate_is_rejected(factory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    event_id = await factory.create("audit_events", tenant_id)

    with pytest.raises(asyncpg.PostgresError):
        async with tx_conn.transaction():
            await tx_conn.execute("TRUNCATE TABLE audit_events")

    assert await tx_conn.fetchval(
        "SELECT count(*) FROM audit_events WHERE id = $1", event_id
    ) == 1
