"""Policy decisions are permanent forensic records (TRD section 8; migration 0009).

Owner: M6
Only execution_status may change after insert (the gateway records the execution outcome
there; OD-25). Raw SQL on purpose: this must hold even if the application is bypassed.
"""

import asyncpg
import pytest

from backend.tests.database.factory import RowFactory

pytestmark = pytest.mark.asyncio


async def _decision(factory: RowFactory) -> tuple[str, str]:
    tenant = await factory.tenant()
    return tenant, await factory.create("policy_decisions", tenant)


@pytest.mark.parametrize(
    ("column", "value_sql"),
    [
        ("decision", "'CHANGED'"),
        ("memory_trust", "'CHANGED'"),
        ("policy_result", "'CHANGED'"),
        ("reasons_json", "'[\"changed\"]'::jsonb"),
        ("created_at", "created_at - interval '1 day'"),
        ("id", "'00000000-0000-0000-0000-000000000000'"),
    ],
)
async def test_decision_content_cannot_change(factory: RowFactory, tx_conn, column: str, value_sql: str) -> None:
    _, decision = await _decision(factory)
    before = await tx_conn.fetchrow("SELECT * FROM policy_decisions WHERE id = $1", decision)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="only execution_status may change"):
        async with tx_conn.transaction():
            await tx_conn.execute(f"UPDATE policy_decisions SET {column} = {value_sql} WHERE id = $1", decision)

    assert await tx_conn.fetchrow("SELECT * FROM policy_decisions WHERE id = $1", decision) == before


async def test_attaching_or_moving_references_is_refused(factory: RowFactory, tx_conn) -> None:
    tenant, decision = await _decision(factory)
    incident = await factory.create("incidents", tenant)
    agent = await factory.create("agents", tenant)
    other_proposal = await factory.create("tool_proposals", tenant, agent_id=agent)

    for column, value in (("incident_id", incident), ("proposal_id", other_proposal)):
        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
            async with tx_conn.transaction():
                await tx_conn.execute(f"UPDATE policy_decisions SET {column} = $1 WHERE id = $2", value, decision)


async def test_execution_status_can_still_be_updated(factory: RowFactory, tx_conn) -> None:
    _, decision = await _decision(factory)

    for status in ("TEST_STATUS_1", "TEST_STATUS_2"):
        await tx_conn.execute("UPDATE policy_decisions SET execution_status = $1 WHERE id = $2", status, decision)

    assert await tx_conn.fetchval("SELECT execution_status FROM policy_decisions WHERE id = $1", decision) == "TEST_STATUS_2"


async def test_decision_without_dependants_still_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    _, decision = await _decision(factory)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="DELETE is forbidden"):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM policy_decisions WHERE id = $1", decision)

    assert await tx_conn.fetchval("SELECT count(*) FROM policy_decisions WHERE id = $1", decision) == 1


async def test_incident_cited_by_a_decision_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    """The FK is ON DELETE SET NULL, but the decision's incident_id is permanent, so the delete is refused."""
    tenant = await factory.tenant()
    incident = await factory.create("incidents", tenant)
    decision = await factory.create("policy_decisions", tenant, incident_id=incident)

    with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM incidents WHERE id = $1", incident)

    assert await tx_conn.fetchval("SELECT incident_id FROM policy_decisions WHERE id = $1", decision) == incident


async def test_uncited_incident_can_still_be_deleted(factory: RowFactory, tx_conn) -> None:
    incident = await factory.create("incidents", await factory.tenant())

    await tx_conn.execute("DELETE FROM incidents WHERE id = $1", incident)

    assert await tx_conn.fetchval("SELECT count(*) FROM incidents WHERE id = $1", incident) == 0
