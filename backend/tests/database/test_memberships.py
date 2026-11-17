"""Membership status contract for M1 authentication (migration 0003).

Owner: M6
The database stores one of ACTIVE / INACTIVE / SUSPENDED / REVOKED and returns it
unchanged. It never invents a membership and never accepts an unknown status.
M1 decides that only ACTIVE grants access.
"""

import uuid

import asyncpg
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError

from backend.app.database.models import Membership, Tenant, User
from backend.app.database.models.identity import MEMBERSHIP_STATUSES
from backend.app.database.repositories import MembershipRepository
from backend.tests.database.factory import RowFactory

pytestmark = pytest.mark.asyncio


def _id() -> str:
    return str(uuid.uuid4())


async def _tenant_and_user(session) -> tuple[str, str]:
    tenant = Tenant(id=_id(), name="Company", slug=f"co-{uuid.uuid4().hex[:8]}")
    user = User(id=_id(), email=f"{uuid.uuid4().hex[:8]}@example.com", hashed_password="x", full_name="U")
    session.add_all([tenant, user])
    await session.flush()
    return tenant.id, user.id


async def test_supported_statuses_are_exactly_the_agreed_set() -> None:
    assert MEMBERSHIP_STATUSES == ("ACTIVE", "INACTIVE", "SUSPENDED", "REVOKED")


@pytest.mark.parametrize("status", MEMBERSHIP_STATUSES)
async def test_membership_status_is_returned_unchanged(session, status: str) -> None:
    tenant_id, user_id = await _tenant_and_user(session)
    repo = MembershipRepository(session, tenant_id)
    await repo.add(Membership(id=_id(), user_id=user_id, role="SECURITY_ANALYST", status=status))
    session.expunge_all()  # force a real read from PostgreSQL

    membership = await repo.get_for_user(user_id)

    assert membership is not None
    assert membership.status == status
    assert membership.role == "SECURITY_ANALYST"


async def test_new_membership_defaults_to_active(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    membership_id = await factory.create("memberships", tenant_id)

    assert await tx_conn.fetchval("SELECT status FROM memberships WHERE id = $1", membership_id) == "ACTIVE"


@pytest.mark.parametrize("bad", ["active", "DELETED", "", "ACTIVE "])
async def test_invalid_status_is_rejected_on_insert(factory: RowFactory, bad: str) -> None:
    tenant_id = await factory.tenant()

    with pytest.raises(asyncpg.CheckViolationError):
        await factory.create("memberships", tenant_id, status=bad)


async def test_null_status_is_rejected(factory: RowFactory) -> None:
    tenant_id = await factory.tenant()

    with pytest.raises(asyncpg.NotNullViolationError):
        await factory.create("memberships", tenant_id, status=None)


async def test_invalid_status_is_rejected_on_update(factory: RowFactory, tx_conn) -> None:
    tenant_id = await factory.tenant()
    membership_id = await factory.create("memberships", tenant_id, status="ACTIVE")

    with pytest.raises(asyncpg.CheckViolationError):
        async with tx_conn.transaction():
            await tx_conn.execute("UPDATE memberships SET status = 'SUPERUSER' WHERE id = $1", membership_id)

    assert await tx_conn.fetchval("SELECT status FROM memberships WHERE id = $1", membership_id) == "ACTIVE"


async def test_invalid_status_is_rejected_through_orm(session) -> None:
    tenant_id, user_id = await _tenant_and_user(session)
    repo = MembershipRepository(session, tenant_id)

    with pytest.raises(DBAPIError):
        async with session.begin_nested():
            await repo.add(Membership(id=_id(), user_id=user_id, status="ADMIN"))


async def test_missing_membership_returns_none_and_creates_nothing(session) -> None:
    tenant_id, user_id = await _tenant_and_user(session)
    repo = MembershipRepository(session, tenant_id)
    count = select(func.count()).select_from(Membership).where(Membership.user_id == user_id)

    assert await repo.get_for_user(user_id) is None
    assert (await session.execute(count)).scalar_one() == 0


async def test_membership_in_other_tenant_is_not_returned(session) -> None:
    tenant_a, user_id = await _tenant_and_user(session)
    tenant_b, _ = await _tenant_and_user(session)
    await MembershipRepository(session, tenant_b).add(Membership(id=_id(), user_id=user_id))

    assert await MembershipRepository(session, tenant_a).get_for_user(user_id) is None
    assert (await MembershipRepository(session, tenant_b).get_for_user(user_id)).status == "ACTIVE"
