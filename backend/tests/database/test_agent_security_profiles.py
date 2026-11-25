"""Database-backed tests for governed agent profile creation and branch scope."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.agents import AgentEntity, AgentVersionEntity
from backend.app.database.models.agents import Agent
from backend.app.database.models.identity import Branch, Tenant
from backend.app.database.repositories.agents import SqlAlchemyAgentRepository


@asynccontextmanager
async def _session_scope(bind):
    """Open an isolated session/savepoint on the database test transaction."""
    async with AsyncSession(
        bind=bind,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    ) as db_session:
        yield db_session


@pytest.mark.asyncio
async def test_agent_registration_persists_profile_and_branch_scope(session):
    tenant_id = "tenant-profile-test"
    branch_a = "branch-profile-a"
    branch_b = "branch-profile-b"
    now = datetime.now(timezone.utc)

    session.add(Tenant(id=tenant_id, name="Profile Test Co", slug="profile-test-co"))
    # Flush the parent tenant before inserting branches so the FK is satisfied
    # regardless of SQLAlchemy's insert ordering for unrelated mapped objects.
    await session.flush()
    session.add_all([
        Branch(id=branch_a, tenant_id=tenant_id, name="Branch A", code="A"),
        Branch(id=branch_b, tenant_id=tenant_id, name="Branch B", code="B"),
    ])
    await session.flush()

    repository = SqlAlchemyAgentRepository(
        lambda: _session_scope(session.bind)
    )
    agent = AgentEntity(
        id="agent-profile-test",
        tenant_id=tenant_id,
        name="Profile Test Agent",
        runtime="LANGCHAIN",
        model="test-model",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Test prompt",
        branch_id=branch_a,
        created_at=now,
        updated_at=now,
    )
    version = AgentVersionEntity(
        id="version-profile-test",
        tenant_id=tenant_id,
        agent_id=agent.id,
        version="v1.0.0",
        config_payload={"registered_by": "test-admin"},
        created_at=now,
    )

    await repository.create_agent_atomic(agent, version)

    profile = await repository.get_agent_profile(agent.id, tenant_id)
    assert profile is not None
    assert profile["branch_id"] == branch_a
    assert profile["governed_by_user_id"] == "test-admin"
    assert profile["status"] == "ACTIVE"

    fetched_agent = await repository.get_agent_by_id(agent.id, tenant_id)
    assert fetched_agent is not None
    assert fetched_agent.branch_id == branch_a

    branch_a_agents, _ = await repository.list_agents(tenant_id, branch_id=branch_a)
    branch_b_agents, _ = await repository.list_agents(tenant_id, branch_id=branch_b)
    assert [item.id for item in branch_a_agents] == [agent.id]
    assert branch_b_agents == []


@pytest.mark.asyncio
async def test_agent_without_governed_profile_is_not_given_synthetic_profile(session):
    tenant_id = "tenant-profile-missing"
    now = datetime.now(timezone.utc)
    session.add(Tenant(id=tenant_id, name="Missing Profile Co", slug="missing-profile-co"))
    await session.flush()
    session.add(
        Agent(
            id="agent-profile-missing",
            tenant_id=tenant_id,
            name="Unprofiled Agent",
            runtime="LANGCHAIN",
            model="test-model",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Test prompt",
            created_at=now,
            updated_at=now,
        )
    )
    await session.flush()

    repository = SqlAlchemyAgentRepository(
        lambda: _session_scope(session.bind)
    )
    assert await repository.get_agent_profile("agent-profile-missing", tenant_id) is None
