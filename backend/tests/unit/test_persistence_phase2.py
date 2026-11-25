"""Phase 2 Persistence & Fail-Closed Foundation Tests.

Validates:
1. Lifespan database engine wiring, session factory configuration, and persistent adapter attachment:
   - SqlAlchemyAgentRepository
   - DatabaseMemoryRepository
   - RecoveryService
2. Fail-closed production enforcement for persistent memory and agent repositories.
3. Transactional Outbox pattern implementation:
   - publish_outbox_event staging
   - OutboxProcessor batch handling and status transitions
   - Handler failure containment (status=FAILED)
4. Real async database CRUD & tenant boundary isolation:
   - SqlAlchemyAgentRepository
   - DatabaseMemoryRepository
"""

import hashlib
from typing import Any, Dict, List

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.api.agents import AgentEntity, AgentVersionEntity
from backend.app.core.config import Settings
from backend.app.core.exceptions import ValidationError
from backend.app.database.models.observability import OutboxEvent
from backend.app.database.repositories.agents import SqlAlchemyAgentRepository
from backend.app.main import create_app, lifespan
from backend.app.memory.adapters import DatabaseMemoryRepository
from backend.app.memory.models import (
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    TrustState,
)
from backend.app.recovery.orchestrator import RecoveryService
from backend.app.workers.outbox import OutboxProcessor, publish_outbox_event


# ---------------------------------------------------------------------------
# Schema DDL for Real SQLite-in-memory Integration Tests
# ---------------------------------------------------------------------------

AGENT_DDL = """
CREATE TABLE agents (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    runtime VARCHAR(64) DEFAULT 'LANGCHAIN' NOT NULL,
    model VARCHAR(64) DEFAULT 'gpt-4o' NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL,
    config_version VARCHAR(32) DEFAULT 'v1.0.0' NOT NULL,
    system_prompt TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE agent_versions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    agent_id VARCHAR(36) NOT NULL,
    version VARCHAR(32) NOT NULL,
    config_payload JSON DEFAULT '{}' NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (agent_id, version)
);
CREATE TABLE agent_security_profiles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    agent_id VARCHAR(36) NOT NULL UNIQUE,
    owner_department VARCHAR(128) NOT NULL,
    approved_purpose TEXT NOT NULL,
    approved_goals JSON DEFAULT '[]' NOT NULL,
    branch_id VARCHAR(36),
    data_scope JSON DEFAULT '[]' NOT NULL,
    operational_restrictions JSON DEFAULT '{}' NOT NULL,
    approval_requirements JSON DEFAULT '{}' NOT NULL,
    profile_version VARCHAR(32) DEFAULT 'v1.0.0' NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL,
    governed_by_user_id VARCHAR(36) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
"""

MEMORY_DDL = """
CREATE TABLE memory_records (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64),
    source_id VARCHAR(64),
    record_type VARCHAR(64) DEFAULT 'KNOWLEDGE' NOT NULL,
    trust_state VARCHAR(32) DEFAULT 'UNVERIFIED' NOT NULL,
    current_version INTEGER DEFAULT 1 NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE memory_versions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    record_id VARCHAR(64) NOT NULL,
    version INTEGER NOT NULL,
    content TEXT NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (record_id, version)
);
CREATE TABLE provenance_edges (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    from_record_id VARCHAR(64) NOT NULL,
    to_record_id VARCHAR(64) NOT NULL,
    relation_type VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


class DummyPersistentRepo:
    is_in_memory: bool = False
    is_persistent: bool = True


# ---------------------------------------------------------------------------
# 1. Lifespan and Engine Wiring
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lifespan_wires_persistent_repos_when_session_factory_active():
    """Verify lifespan automatically attaches persistent adapters when db_session_factory exists."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    settings = Settings(
        APP_ENV="development",
        ALLOW_IN_MEMORY_AUTH=True,
        AUTH_BACKEND="in_memory_demo",
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )
    app = create_app(settings=settings)
    app.state.db_session_factory = session_factory
    app.state.agent_repo = None
    app.state.memory_repo = None
    app.state.recovery_service = None

    async with lifespan(app):
        assert isinstance(app.state.agent_repo, SqlAlchemyAgentRepository)
        assert app.state.agent_repo.is_persistent is True
        assert app.state.agent_repo.is_in_memory is False

        assert isinstance(app.state.memory_repo, DatabaseMemoryRepository)
        assert app.state.memory_repo.is_persistent is True
        assert app.state.memory_repo.is_in_memory is False

        assert isinstance(app.state.recovery_service, RecoveryService)
        assert isinstance(app.state.outbox_processor, OutboxProcessor)


@pytest.mark.asyncio
async def test_lifespan_preserves_explicitly_configured_repositories():
    """Verify lifespan does not overwrite mocks or test doubles explicitly placed on app.state."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    settings = Settings(
        APP_ENV="development",
        ALLOW_IN_MEMORY_AUTH=True,
        AUTH_BACKEND="in_memory_demo",
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )
    app = create_app(settings=settings)
    app.state.db_session_factory = session_factory

    custom_agent_repo = DummyPersistentRepo()
    custom_mem_repo = DummyPersistentRepo()
    app.state.agent_repo = custom_agent_repo
    app.state.memory_repo = custom_mem_repo

    async with lifespan(app):
        assert app.state.agent_repo is custom_agent_repo
        assert app.state.memory_repo is custom_mem_repo


# ---------------------------------------------------------------------------
# 2. Production Fail-Closed Readiness Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_production_fails_closed_with_in_memory_memory_repository():
    """Verify production startup fails closed if memory repository is in-memory."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
        JWT_SECRET="a" * 40,
    )
    app = create_app(settings=prod_settings)
    app.state.auth_repo = DummyPersistentRepo()
    app.state.rate_limiter = DummyPersistentRepo()
    app.state.agent_repo = DummyPersistentRepo()
    app.state.gateway_repo = DummyPersistentRepo()
    app.state.incident_repo = DummyPersistentRepo()
    app.state.trace_repo = DummyPersistentRepo()

    # Simulate in-memory memory repo
    class InMemMemoryRepo:
        is_in_memory = True
        is_persistent = False

    app.state.memory_repo = InMemMemoryRepo()

    with pytest.raises(RuntimeError, match="Persistent database memory repository from M6 is not configured"):
        async with lifespan(app):
            pass


@pytest.mark.asyncio
async def test_production_fails_closed_with_in_memory_agent_repository():
    """Verify production startup fails closed if agent repository is in-memory."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
        JWT_SECRET="a" * 40,
    )
    app = create_app(settings=prod_settings)
    app.state.auth_repo = DummyPersistentRepo()
    app.state.rate_limiter = DummyPersistentRepo()
    app.state.memory_repo = DummyPersistentRepo()
    app.state.gateway_repo = DummyPersistentRepo()
    app.state.incident_repo = DummyPersistentRepo()
    app.state.trace_repo = DummyPersistentRepo()

    class InMemAgentRepo:
        is_in_memory = True
        is_persistent = False

    app.state.agent_repo = InMemAgentRepo()

    with pytest.raises(RuntimeError, match="Persistent database agent repository from M6 is not configured"):
        async with lifespan(app):
            pass


# ---------------------------------------------------------------------------
# 3. Transactional Outbox Pattern Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_outbox_publish_and_batch_processing():
    """Verify transactional outbox publishes and dispatches pending events atomically."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(OutboxEvent.__table__.create)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Stage events in an active session transaction
    async with session_factory() as session:
        async with session.begin():
            await publish_outbox_event(
                session=session,
                tenant_id="tenant-alpha",
                event_type="MEMORY_QUARANTINED",
                payload={"record_id": "rec-101", "reason": "Integrity hash mismatch"},
            )
            await publish_outbox_event(
                session=session,
                tenant_id="tenant-alpha",
                event_type="AGENT_PROMOTED",
                payload={"agent_id": "ag-202"},
            )

    received_quarantines: List[Dict[str, Any]] = []
    received_promotions: List[Dict[str, Any]] = []

    processor = OutboxProcessor(session_factory)
    processor.register_handler("MEMORY_QUARANTINED", lambda e: received_quarantines.append(e.payload))
    processor.register_handler("AGENT_PROMOTED", lambda e: received_promotions.append(e.payload))

    processed_count = await processor.process_batch(limit=10)
    assert processed_count == 2
    assert len(received_quarantines) == 1
    assert received_quarantines[0]["record_id"] == "rec-101"
    assert len(received_promotions) == 1
    assert received_promotions[0]["agent_id"] == "ag-202"

    # Second batch should have 0 pending events
    second_count = await processor.process_batch()
    assert second_count == 0


@pytest.mark.asyncio
async def test_outbox_processor_handler_failure_isolation():
    """Verify that a failing handler marks the event FAILED and does not block the worker."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(OutboxEvent.__table__.create)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        async with session.begin():
            await publish_outbox_event(
                session=session,
                tenant_id="tenant-err",
                event_type="FAILING_EVENT",
                payload={"attempt": 1},
            )

    def crashing_handler(_event: OutboxEvent):
        raise RuntimeError("Downstream webhook destination unavailable")

    processor = OutboxProcessor(session_factory)
    processor.register_handler("FAILING_EVENT", crashing_handler)

    count = await processor.process_batch()
    assert count == 0

    async with session_factory() as session:
        from sqlalchemy import select
        stmt = select(OutboxEvent).where(OutboxEvent.tenant_id == "tenant-err")
        event = (await session.execute(stmt)).scalar_one()
        assert event.status == "FAILED"


# ---------------------------------------------------------------------------
# 4. SqlAlchemyAgentRepository Real Async Database Operations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sqlalchemy_agent_repository_atomic_crud_and_isolation():
    """Verify SqlAlchemyAgentRepository handles atomic creation, versioning, and tenant isolation."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        for stmt in AGENT_DDL.strip().split(";"):
            if stmt.strip():
                await conn.execute(text(stmt))

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    repo = SqlAlchemyAgentRepository(session_factory)

    agent_a = AgentEntity(
        id="agent-prod-001",
        tenant_id="tenant-alpha",
        name="Production Analyzer",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Execute deep security audits.",
    )
    ver_a = AgentVersionEntity(
        id="agv-prod-001",
        tenant_id="tenant-alpha",
        agent_id="agent-prod-001",
        version="v1.0.0",
        config_payload={"model": "gpt-4o", "temperature": 0.2},
    )

    created = await repo.create_agent_atomic(agent_a, ver_a)
    assert created.id == "agent-prod-001"

    # Fetch agent within tenant boundary
    fetched = await repo.get_agent_by_id("agent-prod-001", "tenant-alpha")
    assert fetched is not None
    assert fetched.name == "Production Analyzer"

    # Cross-tenant isolation: tenant-beta must NOT be able to view tenant-alpha's agent
    assert await repo.get_agent_by_id("agent-prod-001", "tenant-beta") is None

    # Fetch historical config version snapshot
    ver_fetched = await repo.get_agent_version("agent-prod-001", "v1.0.0", "tenant-alpha")
    assert ver_fetched is not None
    assert ver_fetched.config_payload["temperature"] == 0.2
    assert await repo.get_agent_version("agent-prod-001", "v1.0.0", "tenant-beta") is None

    # Duplicate agent ID prevention
    with pytest.raises(ValidationError, match="already exists"):
        await repo.create_agent_atomic(agent_a, ver_a)

    # Agent listing with tenant scoping and pagination
    items, has_more = await repo.list_agents("tenant-alpha", limit=10)
    assert len(items) == 1
    assert has_more is False

    items_b, _ = await repo.list_agents("tenant-beta")
    assert len(items_b) == 0


# ---------------------------------------------------------------------------
# 5. DatabaseMemoryRepository Real Async Database Operations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_database_memory_repository_crud_and_version_chains():
    """Verify DatabaseMemoryRepository supports versioning, provenance, updates, and tenant isolation."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        for stmt in MEMORY_DDL.strip().split(";"):
            if stmt.strip():
                await conn.execute(text(stmt))

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    repo = DatabaseMemoryRepository(session_factory)

    # 1. Create base record
    record = MemoryRecord(
        id="mem-rec-001",
        tenant_id="tenant-alpha",
        agent_id="agent-prod-001",
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.TRUSTED,
        current_version=1,
    )
    created_rec = await repo.create_record(record)
    assert created_rec.id == "mem-rec-001"

    # 2. Add version 1
    c1 = "Confidential customer policy guidelines."
    h1 = hashlib.sha256(c1.encode("utf-8")).hexdigest()
    v1 = MemoryVersion(
        id="mem-ver-001",
        tenant_id="tenant-alpha",
        record_id="mem-rec-001",
        version=1,
        content=c1,
        checksum=h1,
    )
    await repo.create_version(v1)

    # 3. Add version 2
    c2 = "Updated confidential customer policy guidelines."
    h2 = hashlib.sha256(c2.encode("utf-8")).hexdigest()
    v2 = MemoryVersion(
        id="mem-ver-002",
        tenant_id="tenant-alpha",
        record_id="mem-rec-001",
        version=2,
        content=c2,
        checksum=h2,
    )
    await repo.create_version(v2)

    # 4. Verify version history ordering and latest version retrieval
    all_versions = await repo.get_versions("mem-rec-001", "tenant-alpha")
    assert len(all_versions) == 2
    assert [v.version for v in all_versions] == [1, 2]

    latest = await repo.get_latest_version("mem-rec-001", "tenant-alpha")
    assert latest is not None
    assert latest.version == 2
    assert latest.content == c2

    # 5. Update record state to QUARANTINED
    record.current_version = 2
    record.trust_state = TrustState.QUARANTINED
    updated = await repo.update_record(record)
    assert updated.current_version == 2
    assert updated.trust_state == TrustState.QUARANTINED

    # 6. Provenance edge creation & retrieval
    edge = ProvenanceEdge(
        id="edge-101",
        tenant_id="tenant-alpha",
        from_record_id="mem-rec-001",
        to_record_id="mem-rec-derived",
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )
    await repo.create_edge(edge)
    edges = await repo.get_edges_for_record("mem-rec-001", "tenant-alpha")
    assert len(edges) == 1
    assert edges[0].relation_type == ProvenanceRelationType.DERIVED_FROM

    # 7. Cross-tenant isolation: tenant-beta must NOT see tenant-alpha's memory records
    assert await repo.get_record("mem-rec-001", "tenant-beta") is None
    assert await repo.get_latest_version("mem-rec-001", "tenant-beta") is None
    assert len(await repo.get_versions("mem-rec-001", "tenant-beta")) == 0
    assert len(await repo.list_records("tenant-beta", only_trusted=False)) == 0


@pytest.mark.asyncio
async def test_outbox_processor_safe_limit_and_wildcard_handler():
    """Verify outbox processor safely clamps invalid limits and invokes wildcard handlers."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(OutboxEvent.__table__.create)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        async with session.begin():
            await publish_outbox_event(
                session=session,
                tenant_id="tenant-wild",
                event_type="UNMAPPED_CUSTOM_EVENT",
                payload={"data": "test-data"},
            )

    wildcard_events: List[OutboxEvent] = []
    processor = OutboxProcessor(session_factory)
    processor.register_handler("*", lambda e: wildcard_events.append(e))

    # Passing non-positive limit should be safely clamped to >= 1
    count = await processor.process_batch(limit=-5)
    assert count == 1
    assert len(wildcard_events) == 1
    assert wildcard_events[0].payload["data"] == "test-data"

    # Stop flag stops processor
    processor.stop()
    assert processor._running is False

