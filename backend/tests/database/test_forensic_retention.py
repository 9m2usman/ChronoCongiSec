"""Approver tenant consistency and forensic delete protection (migration 0003).

Owner: M6
- An approval's approver must be a member of the approval's tenant.
- Deleting an approver's membership (or the user) cannot erase "who approved".
- A tenant that owns audit / incident / gateway evidence cannot be physically
  deleted; deactivation (tenants.status) keeps every record.
- An agent with tool proposals cannot be deleted (it is isolated instead).
Raw SQL on purpose: these rules must hold even if the application is bypassed.
"""

import asyncpg
import pytest

from backend.tests.database.factory import RowFactory
from backend.tests.database.relationships import FORENSIC_TENANT_TABLES

pytestmark = pytest.mark.asyncio


async def _member(factory: RowFactory, tenant_id: str, user_id: str | None = None) -> tuple[str, str]:
    """Create a membership; return (membership id, user id)."""
    overrides = {"user_id": user_id} if user_id else {}
    membership_id = await factory.create("memberships", tenant_id, **overrides)
    uid = await factory.conn.fetchval("SELECT user_id FROM memberships WHERE id = $1", membership_id)
    return membership_id, uid


# -- approver -------------------------------------------------------------------


async def test_same_company_approver_is_accepted(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    _, approver = await _member(factory, tenant_a)

    approval = await factory.create("approvals", tenant_a, approver_user_id=approver)

    assert await tx_conn.fetchval("SELECT approver_user_id FROM approvals WHERE id = $1", approval) == approver


async def test_cross_company_approver_is_rejected(factory: RowFactory) -> None:
    tenant_a, tenant_b = await factory.tenant(), await factory.tenant()
    _, outsider = await _member(factory, tenant_b)  # exists globally, member of B only

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await factory.create("approvals", tenant_a, approver_user_id=outsider)


async def test_user_without_any_membership_cannot_approve(factory: RowFactory) -> None:
    tenant_a = await factory.tenant()
    user_id = await factory.create("users", None)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await factory.create("approvals", tenant_a, approver_user_id=user_id)


async def test_unassigned_approval_allows_null_approver(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()

    approval = await factory.create("approvals", tenant_a)

    assert await tx_conn.fetchval("SELECT approver_user_id FROM approvals WHERE id = $1", approval) is None


async def test_deleting_approver_membership_keeps_approval_evidence(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    membership_id, approver = await _member(factory, tenant_a)
    approval = await factory.create("approvals", tenant_a, approver_user_id=approver)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM memberships WHERE id = $1", membership_id)

    # Revocation is done through status, which keeps the evidence intact.
    await tx_conn.execute("UPDATE memberships SET status = 'REVOKED' WHERE id = $1", membership_id)
    assert await tx_conn.fetchval("SELECT approver_user_id FROM approvals WHERE id = $1", approval) == approver


async def test_deleting_approver_user_keeps_approval_evidence(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    _, approver = await _member(factory, tenant_a)
    approval = await factory.create("approvals", tenant_a, approver_user_id=approver)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM users WHERE id = $1", approver)

    assert await tx_conn.fetchval("SELECT approver_user_id FROM approvals WHERE id = $1", approval) == approver


async def test_user_who_never_approved_can_still_be_deleted(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    membership_id, user_id = await _member(factory, tenant_a)

    await tx_conn.execute("DELETE FROM users WHERE id = $1", user_id)

    assert await tx_conn.fetchval("SELECT count(*) FROM memberships WHERE id = $1", membership_id) == 0


# -- tenant deletion ----------------------------------------------------------------


@pytest.mark.parametrize("table", sorted(FORENSIC_TENANT_TABLES))
async def test_tenant_with_evidence_cannot_be_deleted(factory: RowFactory, tx_conn, table: str) -> None:
    tenant_a = await factory.tenant()
    row_id = await factory.create(table, tenant_a)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM tenants WHERE id = $1", tenant_a)

    assert await tx_conn.fetchval("SELECT count(*) FROM tenants WHERE id = $1", tenant_a) == 1
    assert await tx_conn.fetchval(f"SELECT count(*) FROM {table} WHERE id = $1", row_id) == 1


async def test_tenant_deactivation_keeps_all_evidence(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    _, approver = await _member(factory, tenant_a)
    audit = await factory.create("audit_events", tenant_a)
    incident = await factory.create("incidents", tenant_a)
    approval = await factory.create("approvals", tenant_a, approver_user_id=approver)

    await tx_conn.execute("UPDATE tenants SET status = 'INACTIVE' WHERE id = $1", tenant_a)

    for table, row_id in (("audit_events", audit), ("incidents", incident), ("approvals", approval)):
        assert await tx_conn.fetchval(f"SELECT count(*) FROM {table} WHERE id = $1", row_id) == 1


async def test_tenant_without_evidence_can_still_be_deleted(factory: RowFactory, tx_conn) -> None:
    """Non-forensic data keeps its CASCADE behaviour (unchanged from 0002)."""
    tenant_a = await factory.tenant()
    record = await factory.create("memory_records", tenant_a)
    branch = await factory.create("branches", tenant_a)

    await tx_conn.execute("DELETE FROM tenants WHERE id = $1", tenant_a)

    assert await tx_conn.fetchval("SELECT count(*) FROM memory_records WHERE id = $1", record) == 0
    assert await tx_conn.fetchval("SELECT count(*) FROM branches WHERE id = $1", branch) == 0


# -- agent deletion -------------------------------------------------------------------


async def test_agent_with_tool_history_cannot_be_deleted(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    agent = await factory.create("agents", tenant_a)
    proposal = await factory.create("tool_proposals", tenant_a, agent_id=agent)
    decision = await factory.create("policy_decisions", tenant_a, proposal_id=proposal)

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("DELETE FROM agents WHERE id = $1", agent)

    await tx_conn.execute("UPDATE agents SET status = 'ISOLATED' WHERE id = $1", agent)
    assert await tx_conn.fetchval("SELECT count(*) FROM policy_decisions WHERE id = $1", decision) == 1


async def test_agent_without_tool_history_can_be_deleted(factory: RowFactory, tx_conn) -> None:
    tenant_a = await factory.tenant()
    agent = await factory.create("agents", tenant_a)
    version = await factory.create("agent_versions", tenant_a, agent_id=agent)

    await tx_conn.execute("DELETE FROM agents WHERE id = $1", agent)

    assert await tx_conn.fetchval("SELECT count(*) FROM agent_versions WHERE id = $1", version) == 0
