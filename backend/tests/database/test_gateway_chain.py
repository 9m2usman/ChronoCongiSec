"""Gateway chain integrity added by migration 0007, checked with raw SQL.

Owner: M6
- An execution's decision must belong to the execution's own proposal.
- Proposal -> decision -> approval / execution is ON DELETE RESTRICT.
"""

import asyncpg
import pytest

from backend.tests.database.factory import RowFactory

pytestmark = pytest.mark.asyncio


async def _two_decided_proposals(factory: RowFactory) -> tuple[str, tuple[str, str], tuple[str, str]]:
    tenant = await factory.tenant()
    agent = await factory.create("agents", tenant)
    pairs = []
    for _ in range(2):
        proposal = await factory.create("tool_proposals", tenant, agent_id=agent)
        decision = await factory.create("policy_decisions", tenant, proposal_id=proposal)
        pairs.append((proposal, decision))
    return tenant, pairs[0], pairs[1]


async def test_execution_with_its_own_decision_is_accepted(factory: RowFactory, tx_conn) -> None:
    tenant, (proposal, decision), _ = await _two_decided_proposals(factory)

    execution = await factory.create("tool_executions", tenant, proposal_id=proposal, decision_id=decision)

    row = await tx_conn.fetchrow("SELECT proposal_id, decision_id FROM tool_executions WHERE id = $1", execution)
    assert (row["proposal_id"], row["decision_id"]) == (proposal, decision)


async def test_execution_citing_another_proposals_decision_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, (proposal_a, _), (_, decision_b) = await _two_decided_proposals(factory)

    with pytest.raises(asyncpg.ForeignKeyViolationError, match="fk_tool_executions_decision_matches_proposal"):
        async with tx_conn.transaction():
            await factory.create("tool_executions", tenant, proposal_id=proposal_a, decision_id=decision_b)


async def test_repointing_an_execution_to_another_decision_is_rejected(factory: RowFactory, tx_conn) -> None:
    tenant, (proposal_a, decision_a), (_, decision_b) = await _two_decided_proposals(factory)
    execution = await factory.create("tool_executions", tenant, proposal_id=proposal_a, decision_id=decision_a)

    with pytest.raises(asyncpg.ForeignKeyViolationError, match="fk_tool_executions_decision_matches_proposal"):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE tool_executions SET decision_id = $1 WHERE id = $2", decision_b, execution)

    assert await tx_conn.fetchval("SELECT decision_id FROM tool_executions WHERE id = $1", execution) == decision_a


async def test_execution_without_decision_is_rejected(factory: RowFactory, tx_conn) -> None:
    """DOC-006 Day 4 exit criterion: no tool execution recorded without decision."""
    tenant, (proposal, _), _ = await _two_decided_proposals(factory)

    with pytest.raises(asyncpg.NotNullViolationError):
        async with tx_conn.transaction():
            await factory.create("tool_executions", tenant, proposal_id=proposal, decision_id=None)


async def test_factory_builds_a_consistent_execution_by_default(factory: RowFactory, tx_conn) -> None:
    execution = await factory.create("tool_executions", await factory.tenant())

    row = await tx_conn.fetchrow(
        """
        SELECT e.proposal_id, d.proposal_id AS decision_proposal
        FROM tool_executions e JOIN policy_decisions d ON d.id = e.decision_id WHERE e.id = $1
        """,
        execution,
    )
    assert row["proposal_id"] == row["decision_proposal"]


@pytest.mark.parametrize(
    ("table", "column"),
    [("tool_proposals", "proposal"), ("policy_decisions", "decision")],
)
async def test_chain_parents_with_dependants_cannot_be_deleted(factory: RowFactory, tx_conn, table, column) -> None:
    tenant, (proposal, decision), _ = await _two_decided_proposals(factory)
    await factory.create("tool_executions", tenant, proposal_id=proposal, decision_id=decision)
    await factory.create("approvals", tenant, decision_id=decision)
    target = proposal if column == "proposal" else decision

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute(f"DELETE FROM {table} WHERE id = $1", target)

    for t, row_id in (("tool_proposals", proposal), ("policy_decisions", decision)):
        assert await tx_conn.fetchval(f"SELECT count(*) FROM {t} WHERE id = $1", row_id) == 1
    assert await tx_conn.fetchval("SELECT count(*) FROM tool_executions WHERE proposal_id = $1", proposal) == 1
    assert await tx_conn.fetchval("SELECT count(*) FROM approvals WHERE decision_id = $1", decision) == 1
