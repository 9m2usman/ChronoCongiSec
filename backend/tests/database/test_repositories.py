"""TenantScopedRepository isolation tests (ORM layer on real PostgreSQL).

Owner: M6
"""

import uuid

import pytest
from sqlalchemy.exc import DBAPIError

from backend.app.database.models import Agent, MemoryRecord, Role, Tenant
from backend.app.database.repositories import TenantScopedRepository, TenantScopeError

pytestmark = pytest.mark.asyncio


def _id() -> str:
    return str(uuid.uuid4())


async def _tenant(session) -> str:
    tenant = Tenant(id=_id(), name="Company", slug=f"co-{uuid.uuid4().hex[:8]}")
    session.add(tenant)
    await session.flush()
    return tenant.id


async def _two_tenants_with_agents(session):
    tenant_a, tenant_b = await _tenant(session), await _tenant(session)
    repo_a = TenantScopedRepository(session, tenant_a, model=Agent)
    repo_b = TenantScopedRepository(session, tenant_b, model=Agent)
    agent_a = await repo_a.add(Agent(id=_id(), name="A-bot"))
    agent_b = await repo_b.add(Agent(id=_id(), name="B-bot"))
    return repo_a, repo_b, agent_a, agent_b


async def test_add_stamps_tenant_id(session) -> None:
    tenant_a = await _tenant(session)
    repo = TenantScopedRepository(session, tenant_a, model=Agent)

    agent = await repo.add(Agent(id=_id(), name="Treasury Bot"))

    assert agent.tenant_id == tenant_a


async def test_add_rejects_entity_of_other_tenant(session) -> None:
    tenant_a, tenant_b = await _tenant(session), await _tenant(session)
    repo_a = TenantScopedRepository(session, tenant_a, model=Agent)

    with pytest.raises(TenantScopeError):
        await repo_a.add(Agent(id=_id(), tenant_id=tenant_b, name="Smuggled"))


async def test_get_is_tenant_isolated(session) -> None:
    repo_a, repo_b, agent_a, agent_b = await _two_tenants_with_agents(session)

    assert (await repo_a.get(agent_a.id)).id == agent_a.id
    assert await repo_a.get(agent_b.id) is None
    assert await repo_b.get(agent_a.id) is None


async def test_list_is_tenant_isolated(session) -> None:
    repo_a, repo_b, agent_a, agent_b = await _two_tenants_with_agents(session)

    assert [a.id for a in await repo_a.list()] == [agent_a.id]
    assert [a.id for a in await repo_b.list()] == [agent_b.id]


async def test_list_filters_stay_inside_tenant(session) -> None:
    repo_a, _, agent_a, agent_b = await _two_tenants_with_agents(session)

    assert await repo_a.list(name="B-bot") == []
    assert [a.id for a in await repo_a.list(name="A-bot")] == [agent_a.id]


async def test_list_rejects_unbounded_or_unknown_queries(session) -> None:
    repo = TenantScopedRepository(session, await _tenant(session), model=Agent)

    with pytest.raises(ValueError):
        await repo.list(limit=10_000)
    with pytest.raises(ValueError):
        await repo.list(not_a_column="x")


async def test_update_is_tenant_isolated(session) -> None:
    repo_a, repo_b, agent_a, agent_b = await _two_tenants_with_agents(session)

    assert await repo_a.update(agent_b.id, status="ISOLATED") is None
    assert (await repo_b.get(agent_b.id)).status == "ACTIVE"

    updated = await repo_a.update(agent_a.id, status="ISOLATED")
    assert updated.status == "ISOLATED"


async def test_update_cannot_change_tenant_or_id(session) -> None:
    repo_a, _, agent_a, agent_b = await _two_tenants_with_agents(session)

    with pytest.raises(TenantScopeError):
        await repo_a.update(agent_a.id, tenant_id=agent_b.tenant_id)
    with pytest.raises(TenantScopeError):
        await repo_a.update(agent_a.id, id=_id())


async def test_delete_is_tenant_isolated(session) -> None:
    repo_a, repo_b, agent_a, agent_b = await _two_tenants_with_agents(session)

    assert await repo_a.delete(agent_b.id) is False
    assert await repo_b.get(agent_b.id) is not None

    assert await repo_a.delete(agent_a.id) is True
    assert await repo_a.get(agent_a.id) is None


async def test_orm_tenant_change_is_blocked_by_database(session) -> None:
    """Even bypassing the repository, a flushed tenant_id change is rejected by the trigger."""
    repo_a, _, agent_a, agent_b = await _two_tenants_with_agents(session)

    with pytest.raises(DBAPIError, match="tenant_id is immutable"):
        async with session.begin_nested():
            agent_a.tenant_id = agent_b.tenant_id
            await session.flush()


async def test_cross_tenant_reference_through_orm_is_rejected(session) -> None:
    repo_a, _, _, agent_b = await _two_tenants_with_agents(session)
    records_a = TenantScopedRepository(session, repo_a.tenant_id, model=MemoryRecord)

    with pytest.raises(DBAPIError):
        async with session.begin_nested():
            await records_a.add(MemoryRecord(id=_id(), agent_id=agent_b.id))


async def test_repository_requires_tenant_and_tenant_owned_model(session) -> None:
    with pytest.raises(TenantScopeError):
        TenantScopedRepository(session, "", model=Agent)
    with pytest.raises(TypeError):
        TenantScopedRepository(session, _id(), model=Role)  # nullable tenant_id (global roles)
    with pytest.raises(TypeError):
        TenantScopedRepository(session, _id(), model=Tenant)  # global table
