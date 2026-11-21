"""Contract tests for MemoryRepository protocol implementations.

Module: backend.app.memory.tests.contract.test_memory_repository_contract
Owner: M3 — Knowledge & Memory Systems Lead

Parametrized over implementations (InMemoryMemoryRepository, SqlAlchemyMemoryRepository).
The in-memory implementation always runs.
The PostgreSQL implementation runs ONLY when TEST_DATABASE_URL is set, using M6's helpers
(create temp database, alembic upgrade head) imported from backend/tests/database/helpers.py;
otherwise each such test is SKIPPED with reason 'TEST_DATABASE_URL not set'.

Also includes offline unit tests for ORM <-> Pydantic mapping functions, tenant-mismatch
refusal, and production guards.
"""

from datetime import datetime, timezone
import asyncio
import os
from unittest.mock import AsyncMock
import pytest
import pytest_asyncio

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.database.repositories.base import TenantScopeError
from backend.app.memory.adapters import (
    SqlAlchemyMemoryRepository,
    to_orm_agent,
    to_orm_memory_record,
    to_orm_memory_version,
    to_orm_provenance_edge,
    to_orm_source,
    to_pydantic_agent_record,
    to_pydantic_memory_record,
    to_pydantic_memory_version,
    to_pydantic_provenance_edge,
    to_pydantic_source_record,
)
from backend.app.memory.models import (
    AgentRecord,
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    SourceRecord,
    TrustState,
)
from backend.app.memory.repository import InMemoryMemoryRepository

VALID_CHECKSUM = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VALID_CHECKSUM_2 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- Fixtures ---

@pytest_asyncio.fixture(params=["in_memory", "postgres"])
async def contract_repo(request):
    """Parametrized repository fixture supplying both in-memory and PostgreSQL implementations.

    The PostgreSQL implementation runs ONLY when TEST_DATABASE_URL is present, creating
    a throwaway database via M6's helpers and running alembic upgrade head.
    """
    impl = request.param
    tenant_id = "tenant-contract-001"

    if impl == "in_memory":
        repo = InMemoryMemoryRepository()
        yield repo, tenant_id
    elif impl == "postgres":
        test_db_url = (os.environ.get("TEST_DATABASE_URL") or "").strip()
        if not test_db_url:
            pytest.skip("TEST_DATABASE_URL not set")

        from backend.tests.database import helpers
        db_name = await asyncio.to_thread(helpers.create_temp_database)
        try:
            await asyncio.to_thread(helpers.upgrade, db_name, "head")
            engine = create_async_engine(helpers.sqlalchemy_url(db_name), poolclass=NullPool)
            async with engine.connect() as conn:
                outer = await conn.begin()
                async with AsyncSession(
                    bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint"
                ) as session:
                    repo = SqlAlchemyMemoryRepository(session=session, tenant_id=tenant_id)
                    yield repo, tenant_id
                await outer.rollback()
            await engine.dispose()
        finally:
            await asyncio.to_thread(helpers.drop_temp_database, db_name)


# --- Contract Test Cases ---

@pytest.mark.asyncio
async def test_contract_create_and_get_record(contract_repo):
    """Case 1: Create and retrieve a memory record by ID within tenant boundary."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(
        id="rec-c1-001",
        tenant_id=tenant_id,
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.UNVERIFIED,
        current_version=1,
    )
    created = await repo.create_record(rec)
    assert created.id == "rec-c1-001"
    assert created.tenant_id == tenant_id

    fetched = await repo.get_record("rec-c1-001", tenant_id)
    assert fetched is not None
    assert fetched.id == "rec-c1-001"
    assert fetched.tenant_id == tenant_id
    assert fetched.current_version == 1

    missing = await repo.get_record("rec-missing-999", tenant_id)
    assert missing is None


@pytest.mark.asyncio
async def test_contract_tenant_isolation_on_every_method(contract_repo):
    """Case 2: Tenant isolation enforced on all read and query methods."""
    repo, tenant_id = contract_repo
    foreign_tenant = "tenant-foreign-999"

    rec = MemoryRecord(
        id="rec-iso-001",
        tenant_id=tenant_id,
        current_version=1,
    )
    await repo.create_record(rec)

    ver = MemoryVersion(
        id="ver-iso-001",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Tenant isolation test content",
        checksum=VALID_CHECKSUM,
    )
    await repo.create_version(ver)

    if isinstance(repo, SqlAlchemyMemoryRepository):
        # Bound tenant adapter strictly refuses operations referencing a foreign tenant
        with pytest.raises(TenantScopeError):
            await repo.get_record("rec-iso-001", foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.list_records(foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_versions("rec-iso-001", foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_version("rec-iso-001", 1, foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_latest_version("rec-iso-001", foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_edges_for_record("rec-iso-001", foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_agent("agent-iso-001", foreign_tenant)
        with pytest.raises(TenantScopeError):
            await repo.get_source("source-iso-001", foreign_tenant)
    else:
        # In-memory repository queries across tenant boundary return empty / None
        assert await repo.get_record("rec-iso-001", foreign_tenant) is None
        assert len(await repo.list_records(foreign_tenant)) == 0
        assert len(await repo.get_versions("rec-iso-001", foreign_tenant)) == 0
        assert await repo.get_version("rec-iso-001", 1, foreign_tenant) is None
        assert await repo.get_latest_version("rec-iso-001", foreign_tenant) is None
        assert len(await repo.get_edges_for_record("rec-iso-001", foreign_tenant)) == 0
        assert await repo.get_agent("agent-iso-001", foreign_tenant) is None
        assert await repo.get_source("source-iso-001", foreign_tenant) is None


@pytest.mark.asyncio
async def test_contract_versions_ordered_ascending(contract_repo):
    """Case 3: get_versions returns historical versions sorted by version ascending."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(id="rec-ver-order", tenant_id=tenant_id, current_version=3)
    await repo.create_record(rec)

    for v_num in (1, 2, 3):
        ver = MemoryVersion(
            id=f"ver-order-{v_num}",
            tenant_id=tenant_id,
            record_id=rec.id,
            version=v_num,
            content=f"Content version {v_num}",
            checksum=VALID_CHECKSUM,
        )
        await repo.create_version(ver)

    versions = await repo.get_versions(rec.id, tenant_id)
    assert len(versions) == 3
    assert [v.version for v in versions] == [1, 2, 3]


@pytest.mark.asyncio
async def test_contract_latest_version(contract_repo):
    """Case 4: get_latest_version returns the highest version of a record."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(id="rec-latest-001", tenant_id=tenant_id, current_version=2)
    await repo.create_record(rec)

    ver1 = MemoryVersion(
        id="ver-lat-1",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Version 1",
        checksum=VALID_CHECKSUM,
    )
    ver2 = MemoryVersion(
        id="ver-lat-2",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=2,
        content="Version 2",
        checksum=VALID_CHECKSUM_2,
    )
    await repo.create_version(ver1)
    await repo.create_version(ver2)

    latest = await repo.get_latest_version(rec.id, tenant_id)
    assert latest is not None
    assert latest.version == 2
    assert latest.checksum == VALID_CHECKSUM_2

    missing = await repo.get_latest_version("rec-nonexistent-999", tenant_id)
    assert missing is None


@pytest.mark.asyncio
async def test_contract_edges_found_by_from_or_to(contract_repo):
    """Case 5: get_edges_for_record returns edges where the record is either from or to."""
    repo, tenant_id = contract_repo
    rec_a = MemoryRecord(id="rec-edge-a", tenant_id=tenant_id, current_version=1)
    rec_b = MemoryRecord(id="rec-edge-b", tenant_id=tenant_id, current_version=1)
    rec_c = MemoryRecord(id="rec-edge-c", tenant_id=tenant_id, current_version=1)
    await repo.create_record(rec_a)
    await repo.create_record(rec_b)
    await repo.create_record(rec_c)

    # Edge 1: A -> B (A is from)
    edge1 = ProvenanceEdge(
        id="edge-c5-1",
        tenant_id=tenant_id,
        from_record_id=rec_a.id,
        to_record_id=rec_b.id,
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )
    # Edge 2: C -> A (A is to)
    edge2 = ProvenanceEdge(
        id="edge-c5-2",
        tenant_id=tenant_id,
        from_record_id=rec_c.id,
        to_record_id=rec_a.id,
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )
    await repo.create_edge(edge1)
    await repo.create_edge(edge2)

    edges_a = await repo.get_edges_for_record(rec_a.id, tenant_id)
    edge_ids = {e.id for e in edges_a}
    assert "edge-c5-1" in edge_ids
    assert "edge-c5-2" in edge_ids


@pytest.mark.asyncio
async def test_contract_duplicate_edge_idempotent(contract_repo):
    """Case 6: Duplicate provenance edge (same tenant, from, to, relation) is idempotent."""
    repo, tenant_id = contract_repo
    rec_a = MemoryRecord(id="rec-dup-a", tenant_id=tenant_id, current_version=1)
    rec_b = MemoryRecord(id="rec-dup-b", tenant_id=tenant_id, current_version=1)
    await repo.create_record(rec_a)
    await repo.create_record(rec_b)

    edge1 = ProvenanceEdge(
        id="edge-dup-1",
        tenant_id=tenant_id,
        from_record_id=rec_a.id,
        to_record_id=rec_b.id,
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )
    edge2 = ProvenanceEdge(
        id="edge-dup-2",
        tenant_id=tenant_id,
        from_record_id=rec_a.id,
        to_record_id=rec_b.id,
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )

    created1 = await repo.create_edge(edge1)
    created2 = await repo.create_edge(edge2)

    assert created1.from_record_id == rec_a.id
    assert created2.from_record_id == rec_a.id

    edges = await repo.get_edges_for_record(rec_a.id, tenant_id)
    assert len(edges) == 1


@pytest.mark.asyncio
async def test_contract_self_loop_rejected(contract_repo):
    """Case 7: Self-loop provenance edges (from_record_id == to_record_id) are rejected."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(id="rec-loop-1", tenant_id=tenant_id, current_version=1)
    await repo.create_record(rec)

    loop_edge = ProvenanceEdge(
        id="edge-self-loop",
        tenant_id=tenant_id,
        from_record_id=rec.id,
        to_record_id=rec.id,
        relation_type=ProvenanceRelationType.DERIVED_FROM,
    )
    with pytest.raises(ValueError) as exc:
        await repo.create_edge(loop_edge)
    assert "Self-loop" in str(exc.value)


@pytest.mark.asyncio
async def test_contract_list_pagination_and_only_trusted_filter(contract_repo):
    """Case 8: list_records supports bounded pagination and strict only_trusted filtering."""
    repo, tenant_id = contract_repo

    rec1 = MemoryRecord(id="rec-p-1", tenant_id=tenant_id, trust_state=TrustState.TRUSTED, current_version=1)
    rec2 = MemoryRecord(id="rec-p-2", tenant_id=tenant_id, trust_state=TrustState.UNVERIFIED, current_version=1)
    rec3 = MemoryRecord(id="rec-p-3", tenant_id=tenant_id, trust_state=TrustState.TRUSTED, current_version=1)
    await repo.create_record(rec1)
    await repo.create_record(rec2)
    await repo.create_record(rec3)

    # only_trusted=True (default) excludes UNVERIFIED rec2
    trusted_only = await repo.list_records(tenant_id=tenant_id, only_trusted=True)
    trusted_ids = {r.id for r in trusted_only}
    assert "rec-p-1" in trusted_ids
    assert "rec-p-3" in trusted_ids
    assert "rec-p-2" not in trusted_ids

    # only_trusted=False includes all 3 records
    all_recs = await repo.list_records(tenant_id=tenant_id, only_trusted=False)
    all_ids = {r.id for r in all_recs}
    assert {"rec-p-1", "rec-p-2", "rec-p-3"}.issubset(all_ids)

    # Pagination: limit=1, offset=0 vs offset=1
    page1 = await repo.list_records(tenant_id=tenant_id, only_trusted=False, limit=1, offset=0)
    page2 = await repo.list_records(tenant_id=tenant_id, only_trusted=False, limit=1, offset=1)
    assert len(page1) == 1
    assert len(page2) == 1
    assert page1[0].id != page2[0].id


@pytest.mark.asyncio
async def test_contract_transaction_rollback_leaves_nothing(contract_repo):
    """Case 9: A failed transaction rolls back all pending record and version writes."""
    repo, tenant_id = contract_repo

    with pytest.raises(ValueError):
        async with repo.transaction():
            rec = MemoryRecord(id="rec-tx-abort", tenant_id=tenant_id, current_version=1)
            await repo.create_record(rec)
            ver = MemoryVersion(
                id="ver-tx-abort",
                tenant_id=tenant_id,
                record_id=rec.id,
                version=1,
                content="Aborted transaction payload",
                checksum=VALID_CHECKSUM,
            )
            await repo.create_version(ver)
            raise ValueError("Injected abort condition")

    assert await repo.get_record("rec-tx-abort", tenant_id) is None
    assert len(await repo.get_versions("rec-tx-abort", tenant_id)) == 0


@pytest.mark.asyncio
async def test_contract_duplicate_version_refused(contract_repo):
    """Case 10: Attempting to insert duplicate (record_id, version) raises ValueError."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(id="rec-dup-v", tenant_id=tenant_id, current_version=1)
    await repo.create_record(rec)

    ver1 = MemoryVersion(
        id="ver-v1-original",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Original version 1",
        checksum=VALID_CHECKSUM,
    )
    await repo.create_version(ver1)

    dup_ver = MemoryVersion(
        id="ver-v1-duplicate",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Duplicate version 1",
        checksum=VALID_CHECKSUM_2,
    )
    with pytest.raises(ValueError) as exc:
        await repo.create_version(dup_ver)
    assert "already exists" in str(exc.value) or "uq_record_version" in str(exc.value)


@pytest.mark.asyncio
async def test_contract_checksum_column_round_trips(contract_repo):
    """Case 11: The checksum SHA-256 hex string round-trips exactly without corruption."""
    repo, tenant_id = contract_repo
    rec = MemoryRecord(id="rec-chk-rt", tenant_id=tenant_id, current_version=1)
    await repo.create_record(rec)

    ver = MemoryVersion(
        id="ver-chk-rt",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Checksum round trip verification text",
        checksum=VALID_CHECKSUM,
    )
    await repo.create_version(ver)

    fetched = await repo.get_version(rec.id, 1, tenant_id)
    assert fetched is not None
    assert fetched.checksum == VALID_CHECKSUM


@pytest.mark.asyncio
async def test_contract_agent_and_source_lookups(contract_repo):
    """Case 12: Agent and Source lookups return status (and trust_state for sources)."""
    repo, tenant_id = contract_repo

    agent = AgentRecord(
        id="agent-contract-01",
        tenant_id=tenant_id,
        name="Contract Agent",
        status="ACTIVE",
    )
    await repo.create_agent(agent)

    fetched_agent = await repo.get_agent("agent-contract-01", tenant_id)
    assert fetched_agent is not None
    assert fetched_agent.id == "agent-contract-01"
    assert fetched_agent.status == "ACTIVE"

    source = SourceRecord(
        id="source-contract-01",
        tenant_id=tenant_id,
        name="Contract Source",
        source_type="DOCUMENT_FEED",
        trust_state="UNVERIFIED",
        status="ACTIVE",
    )
    await repo.create_source(source)

    fetched_source = await repo.get_source("source-contract-01", tenant_id)
    assert fetched_source is not None
    assert fetched_source.id == "source-contract-01"
    assert fetched_source.status == "ACTIVE"
    assert fetched_source.trust_state == "UNVERIFIED"


# --- Unit Tests (No Database Required) ---

def test_unit_mapping_memory_record_round_trip():
    """Unit test: MemoryRecord explicit ORM <-> Pydantic mapping."""
    now = datetime.now(timezone.utc)
    pyd = MemoryRecord(
        id="rec-map-01",
        tenant_id="tenant-unit-01",
        agent_id="agent-unit-01",
        source_id="src-unit-01",
        record_type=RecordType.CONVERSATION,
        trust_state=TrustState.TRUSTED,
        current_version=3,
        created_at=now,
        updated_at=now,
    )
    orm = to_orm_memory_record(pyd, "tenant-unit-01")
    assert orm.id == pyd.id
    assert orm.tenant_id == pyd.tenant_id
    assert orm.agent_id == pyd.agent_id
    assert orm.source_id == pyd.source_id
    assert orm.record_type == "CONVERSATION"
    assert orm.trust_state == "TRUSTED"
    assert orm.current_version == 3

    mapped_back = to_pydantic_memory_record(orm)
    assert mapped_back.id == pyd.id
    assert mapped_back.record_type == RecordType.CONVERSATION
    assert mapped_back.trust_state == TrustState.TRUSTED
    assert mapped_back.current_version == 3


def test_unit_mapping_memory_version_round_trip():
    """Unit test: MemoryVersion explicit ORM <-> Pydantic mapping."""
    now = datetime.now(timezone.utc)
    pyd = MemoryVersion(
        id="ver-map-01",
        tenant_id="tenant-unit-01",
        record_id="rec-map-01",
        version=2,
        content="Test content mapping",
        checksum=VALID_CHECKSUM,
        created_at=now,
    )
    orm = to_orm_memory_version(pyd, "tenant-unit-01")
    assert orm.id == pyd.id
    assert orm.version == 2
    assert orm.checksum == VALID_CHECKSUM
    assert orm.content == "Test content mapping"

    mapped_back = to_pydantic_memory_version(orm)
    assert mapped_back.id == pyd.id
    assert mapped_back.checksum == VALID_CHECKSUM


def test_unit_mapping_provenance_edge_round_trip():
    """Unit test: ProvenanceEdge explicit ORM <-> Pydantic mapping."""
    now = datetime.now(timezone.utc)
    pyd = ProvenanceEdge(
        id="edge-map-01",
        tenant_id="tenant-unit-01",
        from_record_id="rec-a",
        to_record_id="rec-b",
        relation_type=ProvenanceRelationType.TRANSFORMED_INTO,
        created_at=now,
    )
    orm = to_orm_provenance_edge(pyd, "tenant-unit-01")
    assert orm.relation_type == "TRANSFORMED_INTO"
    mapped_back = to_pydantic_provenance_edge(orm)
    assert mapped_back.relation_type == ProvenanceRelationType.TRANSFORMED_INTO


def test_unit_mapping_agent_and_source_round_trip():
    """Unit test: Agent and Source explicit ORM <-> Pydantic mapping."""
    now = datetime.now(timezone.utc)
    agent_pyd = AgentRecord(
        id="agent-map-01",
        tenant_id="tenant-unit-01",
        name="Unit Agent",
        status="ACTIVE",
        created_at=now,
    )
    agent_orm = to_orm_agent(agent_pyd, "tenant-unit-01")
    assert agent_orm.status == "ACTIVE"
    mapped_agent = to_pydantic_agent_record(agent_orm)
    assert mapped_agent.status == "ACTIVE"

    src_pyd = SourceRecord(
        id="src-map-01",
        tenant_id="tenant-unit-01",
        name="Unit Source",
        source_type="DOCUMENT_FEED",
        trust_state="TRUSTED",
        status="ACTIVE",
        created_at=now,
    )
    src_orm = to_orm_source(src_pyd, "tenant-unit-01")
    assert src_orm.status == "ACTIVE"
    assert src_orm.trust_state == "TRUSTED"
    mapped_src = to_pydantic_source_record(src_orm)
    assert mapped_src.status == "ACTIVE"
    assert mapped_src.trust_state == "TRUSTED"


@pytest.mark.asyncio
async def test_unit_tenant_mismatch_refusal():
    """Unit test: SqlAlchemyMemoryRepository refuses operations referencing a mismatched tenant_id."""
    stub_session = AsyncMock(spec=AsyncSession)
    repo = SqlAlchemyMemoryRepository(session=stub_session, tenant_id="tenant-alpha")

    # Rejection on constructor with invalid tenant
    with pytest.raises(TenantScopeError):
        SqlAlchemyMemoryRepository(session=stub_session, tenant_id="")
    with pytest.raises(TenantScopeError):
        SqlAlchemyMemoryRepository(session=stub_session, tenant_id="   ")

    # Rejection on all methods with mismatched tenant_id
    foreign = "tenant-beta"
    with pytest.raises(TenantScopeError):
        await repo.get_record("r1", foreign)
    with pytest.raises(TenantScopeError):
        await repo.list_records(foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_versions("r1", foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_version("r1", 1, foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_latest_version("r1", foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_edges_for_record("r1", foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_agent("a1", foreign)
    with pytest.raises(TenantScopeError):
        await repo.get_source("s1", foreign)

    # Rejection on mutations with mismatched entity tenant_id
    with pytest.raises(TenantScopeError):
        await repo.create_record(MemoryRecord(id="r1", tenant_id=foreign, current_version=1))
    with pytest.raises(TenantScopeError):
        await repo.update_record(MemoryRecord(id="r1", tenant_id=foreign, current_version=1))
    with pytest.raises(TenantScopeError):
        await repo.create_version(
            MemoryVersion(id="v1", tenant_id=foreign, record_id="r1", version=1, content="x", checksum=VALID_CHECKSUM)
        )
    with pytest.raises(TenantScopeError):
        await repo.create_edge(
            ProvenanceEdge(id="e1", tenant_id=foreign, from_record_id="r1", to_record_id="r2")
        )
    with pytest.raises(TenantScopeError):
        await repo.create_agent(AgentRecord(id="a1", tenant_id=foreign, name="A"))
    with pytest.raises(TenantScopeError):
        await repo.create_source(SourceRecord(id="s1", tenant_id=foreign, name="S", status="ACTIVE"))


def test_unit_production_guard_qualification(monkeypatch):
    """Unit test: SqlAlchemyMemoryRepository qualifies under the production guard while in-memory repo is rejected."""
    assert SqlAlchemyMemoryRepository.is_persistent is True
    assert SqlAlchemyMemoryRepository.is_in_memory is False
    assert InMemoryMemoryRepository.is_persistent is False
    assert InMemoryMemoryRepository.is_in_memory is True

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "super_secret_jwt_key_that_is_32_chars_long_prod")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://user:pass@db.prod.internal:5432/amsc")
    monkeypatch.setenv("REDIS_URL", "redis://redis.prod.internal:6379/0")
    monkeypatch.setenv("ALLOW_IN_MEMORY_AUTH", "false")
    monkeypatch.setenv("AUTH_BACKEND", "database")
    monkeypatch.setenv("ALLOW_IN_MEMORY_RATE_LIMITER", "false")
    monkeypatch.setenv("RATE_LIMITER_BACKEND", "redis")

    from backend.app.core.config import get_settings
    from backend.app.main import create_app
    from fastapi.testclient import TestClient

    get_settings.cache_clear()
    settings = get_settings()

    # 1. In-memory repository strictly fails production startup
    app_in_memory = create_app(settings)
    app_in_memory.state.auth_repo = object()
    app_in_memory.state.rate_limiter = object()
    app_in_memory.state.memory_repo = InMemoryMemoryRepository()
    with pytest.raises(RuntimeError) as exc_info:
        with TestClient(app_in_memory):
            pass
    assert "In-memory memory repository is strictly forbidden in production" in str(exc_info.value)

    # 2. SqlAlchemyMemoryRepository qualifies and succeeds production startup
    app_persistent = create_app(settings)
    app_persistent.state.auth_repo = object()
    app_persistent.state.rate_limiter = object()
    app_persistent.state.memory_repo = SqlAlchemyMemoryRepository(
        session=AsyncMock(spec=AsyncSession), tenant_id="tenant-prod"
    )
    with TestClient(app_persistent):
        pass

    get_settings.cache_clear()
