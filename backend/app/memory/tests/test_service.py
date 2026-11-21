"""Unit and integration tests for memory service and repository."""

import sys
from pathlib import Path
import pytest

# Ensure repo root is in sys.path
repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.core.exceptions import ForbiddenError, ValidationError
from backend.app.memory.integrity import MemoryIntegrityError, sha256_hex
from backend.app.memory.models import AgentRecord, SourceRecord, TrustState
from backend.app.memory.repository import (
    InMemoryMemoryRepository,
    MemoryRepository,
    get_default_repository,
)
from backend.app.memory.ingestion import (
    MAX_PROVENANCE_DEPTH,
    MAX_TRAVERSAL_BUDGET,
    InvalidProvenanceError,
    _check_dag_cycle,
    ingest_memory,
)
from backend.app.memory.retrieval import (
    MemoryNotFoundError,
    get_memory_detail,
    retrieve_memory,
    transition_memory_trust_state,
)
from backend.app.memory.versioning import update_memory
from backend.app.memory.tests.trust_helpers import force_trust_state


@pytest.fixture
def repo():
    """Isolated in-memory repository for each test."""
    return InMemoryMemoryRepository()


def test_version_1_on_create(repo):
    """Ingesting memory must create MemoryRecord with version 1, UNVERIFIED trust state, and valid SHA-256."""
    content = "Standard Treasury wire verification threshold: $500.00."
    tenant_id = "tenant-alpha"

    # Pre-register active agent for tenant-alpha (GAP-003)
    repo.create_agent(
        AgentRecord(
            id="agent-001",
            tenant_id=tenant_id,
            name="Test Agent",
            status="ACTIVE",
        )
    )

    record, version = ingest_memory(
        tenant_id=tenant_id,
        content=content,
        agent_id="agent-001",
        record_type="KNOWLEDGE",
        repository=repo,
    )

    # Assert record properties
    assert record.current_version == 1
    assert record.trust_state == "UNVERIFIED"
    assert record.tenant_id == tenant_id
    assert record.agent_id == "agent-001"
    assert record.record_type == "KNOWLEDGE"

    # Assert version properties
    assert version.version == 1
    assert version.record_id == record.id
    assert version.tenant_id == tenant_id
    assert version.content == content
    assert version.checksum == sha256_hex(content)


def test_version_increments_on_update(repo):
    """Updating a memory record must increment current_version and create a new version."""
    tenant_id = "tenant-alpha"
    content_v1 = "Initial routing instruction: Account ACC-1234."
    content_v2 = "Updated routing instruction: Account ACC-5678."
    content_v3 = "Final routing instruction: Account ACC-9999."

    record, v1 = ingest_memory(tenant_id=tenant_id, content=content_v1, repository=repo)
    assert record.current_version == 1

    # First update -> version 2
    rec_v2, v2 = update_memory(
        tenant_id=tenant_id,
        record_id=record.id,
        content=content_v2,
        repository=repo,
    )
    assert rec_v2.current_version == 2
    assert v2.version == 2
    assert v2.content == content_v2
    assert v2.checksum == sha256_hex(content_v2)
    # Trust state must not be modified by update (M4 owns trust states)
    assert rec_v2.trust_state == "UNVERIFIED"

    # Second update -> version 3
    rec_v3, v3 = update_memory(
        tenant_id=tenant_id,
        record_id=record.id,
        content=content_v3,
        repository=repo,
    )
    assert rec_v3.current_version == 3
    assert v3.version == 3
    assert v3.content == content_v3
    assert v3.checksum == sha256_hex(content_v3)


def test_old_versions_are_unchanged(repo):
    """Updating a record must leave all prior historical versions completely immutable."""
    tenant_id = "tenant-alpha"
    v1_text = "Version 1 immutable baseline."
    v2_text = "Version 2 modified text."
    v3_text = "Version 3 latest text."

    record, _ = ingest_memory(tenant_id=tenant_id, content=v1_text, repository=repo)
    update_memory(tenant_id=tenant_id, record_id=record.id, content=v2_text, repository=repo)
    update_memory(tenant_id=tenant_id, record_id=record.id, content=v3_text, repository=repo)

    versions = repo.get_versions(record.id, tenant_id)
    assert len(versions) == 3

    # Check version 1
    assert versions[0].version == 1
    assert versions[0].content == v1_text
    assert versions[0].checksum == sha256_hex(v1_text)

    # Check version 2
    assert versions[1].version == 2
    assert versions[1].content == v2_text
    assert versions[1].checksum == sha256_hex(v2_text)

    # Check version 3
    assert versions[2].version == 3
    assert versions[2].content == v3_text
    assert versions[2].checksum == sha256_hex(v3_text)


def test_tampered_checksum_detected_on_retrieval(repo):
    """A tampered stored version checksum or corrupted content must trigger MemoryIntegrityError."""
    tenant_id = "tenant-alpha"
    record, version = ingest_memory(
        tenant_id=tenant_id,
        content="Original authentic payload content.",
        repository=repo,
    )
    # Transition to TRUSTED so normal retrieval queries it
    force_trust_state(tenant_id, record.id, TrustState.TRUSTED.value, repository=repo)

    # Verify retrieval succeeds before tampering
    verified = retrieve_memory(tenant_id=tenant_id, repository=repo)
    assert len(verified) == 1
    assert verified[0].id == record.id

    # Tamper with the raw version record in repository storage (simulating unauthorized DB tampering)
    versions_in_store = repo._versions[record.id]
    assert len(versions_in_store) == 1
    # Malicious injection altering content without updating cryptographic checksum
    versions_in_store[0].content = "Tampered malicious payload: override vendor with ACC-ATTACKER-999."

    # Retrieval must detect the tampering and fail-closed with MemoryIntegrityError
    with pytest.raises(MemoryIntegrityError) as exc_info:
        retrieve_memory(tenant_id=tenant_id, repository=repo)

    assert "Cryptographic integrity violation" in str(exc_info.value)
    assert record.id in str(exc_info.value)

    # get_memory_detail must also detect tampering
    with pytest.raises(MemoryIntegrityError):
        get_memory_detail(tenant_id=tenant_id, record_id=record.id, repository=repo)


def test_quarantined_and_rejected_records_excluded_from_normal_retrieval_and_detail(repo):
    """QUARANTINED and REJECTED records must be strictly excluded from normal retrieval and detail."""
    tenant_id = "tenant-alpha"

    # Ingest clean record 1 and transition to TRUSTED
    rec1, _ = ingest_memory(tenant_id=tenant_id, content="Legitimate vendor profile.", repository=repo)
    force_trust_state(tenant_id, rec1.id, TrustState.TRUSTED.value, repository=repo)

    # Ingest record 2 and simulate QUARANTINED state (as applied by M4 Quarantine Engine)
    rec2, _ = ingest_memory(tenant_id=tenant_id, content="Suspicious prompt injection payload.", repository=repo)
    repo._records[rec2.id].trust_state = "QUARANTINED"

    # Ingest record 3 and simulate REJECTED state
    rec3, _ = ingest_memory(tenant_id=tenant_id, content="Malicious rejected payload.", repository=repo)
    repo._records[rec3.id].trust_state = "REJECTED"

    # Normal agent retrieval strictly excludes quarantined and rejected records
    active_records = retrieve_memory(tenant_id=tenant_id, repository=repo)
    active_ids = [r.id for r in active_records]
    assert rec1.id in active_ids
    assert rec2.id not in active_ids
    assert rec3.id not in active_ids

    # get_memory_detail for normal agent access (for_forensic=False) must raise MemoryNotFoundError (404)
    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(tenant_id=tenant_id, record_id=rec2.id, for_forensic=False, repository=repo)

    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(tenant_id=tenant_id, record_id=rec3.id, for_forensic=False, repository=repo)

    # Forensic access (for_forensic=True) by authorized security analysts permits detail inspection
    detail_rec, _, _ = get_memory_detail(tenant_id=tenant_id, record_id=rec2.id, for_forensic=True, repository=repo)
    assert detail_rec.id == rec2.id
    assert detail_rec.trust_state == "QUARANTINED"


def test_tenant_isolation_cannot_read_other_tenant_records(repo):
    """Tenant B must never be able to retrieve, view detail, or update Tenant A's records."""
    tenant_a = "tenant-company-a"
    tenant_b = "tenant-company-b"

    rec_a, _ = ingest_memory(
        tenant_id=tenant_a,
        content="Confidential Company A financial strategy.",
        repository=repo,
    )
    force_trust_state(tenant_a, rec_a.id, TrustState.TRUSTED.value, repository=repo)

    # 1. Tenant B querying retrieve_memory gets an empty list
    tenant_b_records = retrieve_memory(tenant_id=tenant_b, repository=repo)
    assert len(tenant_b_records) == 0

    # 2. Tenant B attempting to get detail on Tenant A's record gets MemoryNotFoundError
    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(tenant_id=tenant_b, record_id=rec_a.id, repository=repo)

    # 3. Tenant B attempting to update Tenant A's record gets MemoryNotFoundError
    with pytest.raises(MemoryNotFoundError):
        update_memory(
            tenant_id=tenant_b,
            record_id=rec_a.id,
            content="Unauthorized tenant B overwrite attempt.",
            repository=repo,
        )

    # Verify Tenant A's record is completely unmodified
    a_records = retrieve_memory(tenant_id=tenant_a, repository=repo)
    assert len(a_records) == 1
    assert a_records[0].id == rec_a.id
    assert a_records[0].current_version == 1


def test_cross_tenant_parent_record_reference_rejected(repo):
    """Attempting to link a child record to another tenant's parent record must fail."""
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    parent_a, _ = ingest_memory(tenant_id=tenant_a, content="Parent doc in Tenant A.", repository=repo)

    # Tenant B tries to create a memory claiming parent_a as its parent_record_id
    with pytest.raises(MemoryNotFoundError) as exc_info:
        ingest_memory(
            tenant_id=tenant_b,
            content="Child doc in Tenant B attempting cross-tenant linkage.",
            parent_record_id=parent_a.id,
            repository=repo,
        )

    assert "not found for tenant" in str(exc_info.value)
    assert "Cross-tenant" in str(exc_info.value)


def test_nonexistent_parent_record_reference_rejected(repo):
    """Supplying a nonexistent parent_record_id must fail."""
    tenant_id = "tenant-alpha"

    with pytest.raises(MemoryNotFoundError):
        ingest_memory(
            tenant_id=tenant_id,
            content="Child doc referencing nonexistent parent.",
            parent_record_id="nonexistent-rec-uuid",
            repository=repo,
        )


def test_empty_content_rejected(repo):
    """Empty or whitespace-only memory content must be rejected."""
    tenant_id = "tenant-alpha"

    with pytest.raises(ValidationError):
        ingest_memory(tenant_id=tenant_id, content="", repository=repo)

    with pytest.raises(ValidationError):
        ingest_memory(tenant_id=tenant_id, content="   \n\t  ", repository=repo)


# ============================================================================
# Provenance DAG Traversal & Boundary Tests (Finding 4)
# ============================================================================

def test_provenance_normal_graph(repo):
    """Normal provenance hierarchy within depth limit succeeds."""
    tenant_id = "tenant-alpha"

    # Chain of depth 3: doc0 -> doc1 -> doc2
    doc0, _ = ingest_memory(tenant_id=tenant_id, content="Root source document.", repository=repo)
    doc1, _ = ingest_memory(tenant_id=tenant_id, content="Intermediate extraction.", parent_record_id=doc0.id, repository=repo)
    doc2, _ = ingest_memory(tenant_id=tenant_id, content="Final synthesis summary.", parent_record_id=doc1.id, repository=repo)

    edges = repo.get_edges_for_record(doc2.id, tenant_id)
    assert len(edges) == 1
    assert edges[0].from_record_id == doc1.id
    assert edges[0].to_record_id == doc2.id


def test_provenance_cyclic_graph_rejected(repo):
    """Direct and indirect cycle creation must be detected and rejected."""
    tenant_id = "tenant-alpha"

    docA, _ = ingest_memory(tenant_id=tenant_id, content="Node A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="Node B", parent_record_id=docA.id, repository=repo)

    # Attempting to link A to derive from B creates A -> B -> A cycle
    from backend.app.memory.provenance import _check_dag_cycle
    with pytest.raises(InvalidProvenanceError) as exc_info:
        _check_dag_cycle(repo, from_id=docB.id, to_id=docA.id, tenant_id=tenant_id)

    assert "Provenance cycle detected" in str(exc_info.value)


def test_provenance_graph_deeper_than_permitted_depth_rejected(repo):
    """Lineage chains exceeding MAX_PROVENANCE_DEPTH (5) must be rejected."""
    tenant_id = "tenant-alpha"

    # Build chain: d1 -> d2 -> d3 -> d4 -> d5 (depth 5 is allowed)
    prev, _ = ingest_memory(tenant_id=tenant_id, content="Root 1", repository=repo)
    for i in range(2, 6):
        prev, _ = ingest_memory(
            tenant_id=tenant_id,
            content=f"Descendant {i}",
            parent_record_id=prev.id,
            repository=repo,
        )

    # Attempting to add 6th level exceeds MAX_PROVENANCE_DEPTH (5)
    with pytest.raises(InvalidProvenanceError) as exc_info:
        ingest_memory(
            tenant_id=tenant_id,
            content="Descendant 6 (exceeds depth limit)",
            parent_record_id=prev.id,
            repository=repo,
        )

    assert "depth limit exceeded" in str(exc_info.value)


def test_provenance_large_graph_exceeding_budget_rejected(repo):
    """Traversals exceeding MAX_TRAVERSAL_BUDGET must fail safely."""
    tenant_id = "tenant-alpha"

    # Pre-populate repository with wide branching tree exceeding budget
    from backend.app.memory.models import MemoryRecord, ProvenanceEdge
    import uuid

    root_id = "root-node"
    repo.create_record(MemoryRecord(id=root_id, tenant_id=tenant_id, trust_state="UNVERIFIED"))

    # Create 55 outgoing edges from root
    for i in range(55):
        child_id = f"child-{i}"
        repo.create_record(MemoryRecord(id=child_id, tenant_id=tenant_id, trust_state="UNVERIFIED"))
        repo.create_edge(
            ProvenanceEdge(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                from_record_id=root_id,
                to_record_id=child_id,
            )
        )

    from backend.app.memory.provenance import _check_dag_cycle
    with pytest.raises(InvalidProvenanceError) as exc_info:
        _check_dag_cycle(repo, from_id="new-parent", to_id=root_id, tenant_id=tenant_id)

    assert "budget exceeded" in str(exc_info.value)


# ============================================================================
# Production Persistence Validation Tests (Finding 2)
# ============================================================================

class MockPersistentMemoryRepository(MemoryRepository):
    """Mock repository representing an approved persistent M6 PostgreSQL repository."""
    is_persistent: bool = True
    is_in_memory: bool = False

    def create_record(self, record): return record
    def get_record(self, record_id, tenant_id): return None
    def list_records(self, tenant_id, agent_id=None, trust_state=None, exclude_quarantined=True, only_trusted=True, limit=50, offset=0): return []
    def update_record(self, record): return record
    def create_version(self, version): return version
    def get_versions(self, record_id, tenant_id): return []
    def get_version(self, record_id, version, tenant_id): return None
    def get_latest_version(self, record_id, tenant_id): return None
    def create_edge(self, edge): return edge
    def get_edges_for_record(self, record_id, tenant_id): return []
    def get_agent(self, agent_id, tenant_id): return None
    def create_agent(self, agent): return agent
    def get_source(self, source_id, tenant_id): return None
    def create_source(self, source): return source


def test_production_rejects_missing_memory_repository(monkeypatch):
    """In production, application startup must fail if memory_repo is missing."""
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
    get_settings.cache_clear()

    settings = get_settings()
    app = create_app(settings)
    app.state.auth_repo = object()  # Mock real auth repo
    app.state.rate_limiter = object()  # Mock real rate limiter
    app.state.memory_repo = None  # Missing memory repo

    from fastapi.testclient import TestClient

    with pytest.raises(RuntimeError) as exc_info:
        with TestClient(app):
            pass

    assert "Persistent database memory repository from M6 is not configured" in str(exc_info.value)
    get_settings.cache_clear()


def test_production_rejects_in_memory_memory_repository(monkeypatch):
    """In production, application startup must fail if memory_repo is an in-memory repository."""
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
    app = create_app(settings)
    app.state.auth_repo = object()
    app.state.rate_limiter = object()
    app.state.memory_repo = InMemoryMemoryRepository()  # In-memory repo explicitly attached

    with pytest.raises(RuntimeError) as exc_info:
        with TestClient(app):
            pass

    assert "In-memory memory repository is strictly forbidden in production" in str(exc_info.value)
    get_settings.cache_clear()


def test_production_startup_succeeds_with_approved_persistent_repository(monkeypatch):
    """In production, application startup succeeds when an approved persistent repository is attached."""
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
    app = create_app(settings)
    app.state.auth_repo = object()
    app.state.rate_limiter = object()
    app.state.memory_repo = MockPersistentMemoryRepository()  # Approved persistent repo attached

    # Lifespan executes cleanly without error
    with TestClient(app):
        pass

    get_settings.cache_clear()


def test_development_and_test_environments_usable_with_in_memory_repository(repo):
    """Development and test environments continue to function seamlessly with in-memory storage."""
    record, ver = ingest_memory(tenant_id="dev-tenant", content="Dev content", repository=repo)
    assert record.id is not None
    assert ver.version == 1
    # Transition to TRUSTED for retrieval
    force_trust_state("dev-tenant", record.id, TrustState.TRUSTED.value, repository=repo)
    records = retrieve_memory(tenant_id="dev-tenant", repository=repo)
    assert len(records) == 1


# ============================================================================
# GAP-001, GAP-002, GAP-003, GAP-004 Dedicated P0 Security Tests
# ============================================================================

def test_gap_001_retrieval_returns_only_trusted_records(repo):
    """GAP-001: Normal memory retrieval must return ONLY eligible TRUSTED memory records.

    UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, and SUPERSEDED must be excluded.
    """
    tenant_id = "tenant-gap1"

    # Ingest records representing all lifecycle trust states
    states = [
        TrustState.UNVERIFIED.value,
        TrustState.SUSPICIOUS.value,
        TrustState.QUARANTINED.value,
        TrustState.REJECTED.value,
        TrustState.SUPERSEDED.value,
        TrustState.TRUSTED.value,
    ]
    created = {}
    for st in states:
        rec, _ = ingest_memory(tenant_id=tenant_id, content=f"Payload for state {st}", repository=repo)
        repo._records[rec.id].trust_state = st
        created[st] = rec

    # Normal agent retrieval must return exactly 1 record: the TRUSTED one
    results = retrieve_memory(tenant_id=tenant_id, repository=repo)
    assert len(results) == 1
    assert results[0].id == created[TrustState.TRUSTED.value].id
    assert results[0].trust_state == TrustState.TRUSTED.value

    # Passing any trust_state other than TRUSTED to retrieve_memory must fail-closed with ForbiddenError
    for invalid_filter in ["UNVERIFIED", "SUSPICIOUS", "QUARANTINED", "REJECTED", "SUPERSEDED"]:
        with pytest.raises(ForbiddenError):
            retrieve_memory(tenant_id=tenant_id, trust_state=invalid_filter, repository=repo)


def test_gap_002_update_invalidates_trust_state_to_unverified(repo):
    """GAP-002: Updating memory appends a new immutable version and invalidates trust state to UNVERIFIED."""
    tenant_id = "tenant-gap2"

    # 1. Ingest clean memory
    rec_v1, ver_v1 = ingest_memory(
        tenant_id=tenant_id,
        content="Original wire threshold $500.",
        repository=repo,
    )
    assert rec_v1.current_version == 1
    assert rec_v1.trust_state == TrustState.UNVERIFIED.value

    # 2. Simulate M4 validation promoting it to TRUSTED
    force_trust_state(tenant_id, rec_v1.id, TrustState.TRUSTED.value, repository=repo)
    assert repo.get_record(rec_v1.id, tenant_id).trust_state == TrustState.TRUSTED.value

    # Eligible for normal retrieval
    eligible = retrieve_memory(tenant_id=tenant_id, repository=repo)
    assert len(eligible) == 1

    # 3. Update memory with new content
    rec_v2, ver_v2 = update_memory(
        tenant_id=tenant_id,
        record_id=rec_v1.id,
        content="Updated wire threshold $50,000 (potential tampering).",
        repository=repo,
    )

    # Invariant checks:
    # - current_version incremented
    assert rec_v2.current_version == 2
    # - trust_state invalidated back to UNVERIFIED
    assert rec_v2.trust_state == TrustState.UNVERIFIED.value
    # - New version persisted
    assert ver_v2.version == 2
    assert ver_v2.checksum == sha256_hex("Updated wire threshold $50,000 (potential tampering).")
    # - Historical version 1 remains unchanged
    versions = repo.get_versions(rec_v1.id, tenant_id)
    assert len(versions) == 2
    assert versions[0].version == 1
    assert versions[0].content == "Original wire threshold $500."

    # - Because trust_state was invalidated to UNVERIFIED, normal retrieval now excludes it
    post_update_eligible = retrieve_memory(tenant_id=tenant_id, repository=repo)
    assert len(post_update_eligible) == 0


def test_gap_003_agent_validation(repo):
    """GAP-003: Ingestion validates agent existence, tenant ownership, and ACTIVE status."""
    tenant_a = "tenant-company-main"
    tenant_b = "tenant-company-other"

    # Register active agent for tenant_a
    repo.create_agent(
        AgentRecord(
            id="agent-active-001",
            tenant_id=tenant_a,
            name="Valid Active Agent",
            status="ACTIVE",
            branch_id="branch-lahore",
        )
    )
    # Register isolated (inactive) agent for tenant_a
    repo.create_agent(
        AgentRecord(
            id="agent-isolated-001",
            tenant_id=tenant_a,
            name="Compromised Isolated Agent",
            status="ISOLATED",
            branch_id="branch-lahore",
        )
    )
    # Register active agent for tenant_b
    repo.create_agent(
        AgentRecord(
            id="agent-b-001",
            tenant_id=tenant_b,
            name="Other Tenant Agent",
            status="ACTIVE",
        )
    )

    # 1. Valid active agent -> Success
    rec, _ = ingest_memory(
        tenant_id=tenant_a,
        content="Valid ingest from active agent.",
        agent_id="agent-active-001",
        repository=repo,
    )
    assert rec.agent_id == "agent-active-001"

    # 2. Nonexistent agent -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from nonexistent agent.",
            agent_id="agent-ghost-999",
            repository=repo,
        )
    assert "does not exist or does not belong to company" in str(exc.value)

    # 3. Cross-tenant agent -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from cross-tenant agent.",
            agent_id="agent-b-001",
            repository=repo,
        )
    assert "does not exist or does not belong to company" in str(exc.value)

    # 4. Inactive / ISOLATED agent -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from isolated agent.",
            agent_id="agent-isolated-001",
            repository=repo,
        )
    assert "is not ACTIVE" in str(exc.value)


def test_gap_003_source_validation(repo):
    """GAP-003: Ingestion validates source existence, tenant ownership, and ACTIVE status."""
    tenant_a = "tenant-company-main"
    tenant_b = "tenant-company-other"

    repo.create_source(
        SourceRecord(
            id="src-active-001",
            tenant_id=tenant_a,
            name="Active Document Source",
            source_type="DOCUMENT_FEED",
            status="ACTIVE",
        )
    )
    repo.create_source(
        SourceRecord(
            id="src-inactive-001",
            tenant_id=tenant_a,
            name="Revoked Source",
            source_type="DOCUMENT_FEED",
            status="INACTIVE",
        )
    )
    repo.create_source(
        SourceRecord(
            id="src-other-001",
            tenant_id=tenant_b,
            name="Tenant B Source",
            source_type="API_CONNECTOR",
            status="ACTIVE",
        )
    )

    # 1. Valid active source -> Success
    rec, _ = ingest_memory(
        tenant_id=tenant_a,
        content="Ingest from active source.",
        source_id="src-active-001",
        repository=repo,
    )
    assert rec.source_id == "src-active-001"

    # 2. Nonexistent source -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from nonexistent source.",
            source_id="src-nonexistent-999",
            repository=repo,
        )
    assert "does not exist or does not belong to company" in str(exc.value)

    # 3. Cross-tenant source -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from cross-tenant source.",
            source_id="src-other-001",
            repository=repo,
        )
    assert "does not exist or does not belong to company" in str(exc.value)

    # 4. Inactive source -> ValidationError
    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_a,
            content="Ingest from inactive source.",
            source_id="src-inactive-001",
            repository=repo,
        )
    assert "is not ACTIVE" in str(exc.value)


def test_gap_003_parent_record_state_validation(repo):
    """GAP-003: Ingestion rejects parent_record_id if parent is in QUARANTINED or REJECTED state."""
    tenant_id = "tenant-gap3-parent"

    # Parent in QUARANTINED state
    p_quarantine, _ = ingest_memory(tenant_id=tenant_id, content="Parent quarantined.", repository=repo)
    repo._records[p_quarantine.id].trust_state = TrustState.QUARANTINED.value

    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_id,
            content="Child referencing quarantined parent.",
            parent_record_id=p_quarantine.id,
            repository=repo,
        )
    assert "QUARANTINED" in str(exc.value)

    # Parent in REJECTED state
    p_rejected, _ = ingest_memory(tenant_id=tenant_id, content="Parent rejected.", repository=repo)
    repo._records[p_rejected.id].trust_state = TrustState.REJECTED.value

    with pytest.raises(ValidationError) as exc:
        ingest_memory(
            tenant_id=tenant_id,
            content="Child referencing rejected parent.",
            parent_record_id=p_rejected.id,
            repository=repo,
        )
    assert "REJECTED" in str(exc.value)


def test_gap_004_memory_detail_access_controls(repo):
    """GAP-004: Normal memory detail access returns 404 for non-TRUSTED records; forensic access permitted for M4."""
    tenant_id = "tenant-gap4"

    # Ingest record (defaults to UNVERIFIED)
    rec, _ = ingest_memory(tenant_id=tenant_id, content="Unverified initial memory.", repository=repo)
    assert rec.trust_state == TrustState.UNVERIFIED.value

    # Normal agent detail access (for_forensic=False) must raise MemoryNotFoundError (404)
    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(tenant_id=tenant_id, record_id=rec.id, for_forensic=False, repository=repo)

    # Transition to TRUSTED -> normal access succeeds
    force_trust_state(tenant_id, rec.id, TrustState.TRUSTED.value, repository=repo)
    normal_detail, _, _ = get_memory_detail(tenant_id=tenant_id, record_id=rec.id, for_forensic=False, repository=repo)
    assert normal_detail.id == rec.id
    assert normal_detail.trust_state == TrustState.TRUSTED.value

    # Change to SUSPICIOUS -> normal access fails with MemoryNotFoundError (404)
    repo._records[rec.id].trust_state = TrustState.SUSPICIOUS.value
    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(tenant_id=tenant_id, record_id=rec.id, for_forensic=False, repository=repo)

    # Forensic access (for_forensic=True) succeeds and returns the record for security investigation
    forensic_detail, _, _ = get_memory_detail(tenant_id=tenant_id, record_id=rec.id, for_forensic=True, repository=repo)
    assert forensic_detail.id == rec.id
    assert forensic_detail.trust_state == TrustState.SUSPICIOUS.value


def test_update_memory_trusted_becomes_unverified(repo):
    """Rule 2: Updating a TRUSTED record appends a new version and transitions trust_state to UNVERIFIED."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Trusted baseline", repository=repo)
    force_trust_state(tenant_id, rec.id, TrustState.TRUSTED.value, repository=repo)
    assert repo.get_record(rec.id, tenant_id).trust_state == TrustState.TRUSTED.value

    updated_rec, ver2 = update_memory(tenant_id=tenant_id, record_id=rec.id, content="Trusted edit", repository=repo)
    assert updated_rec.current_version == 2
    assert updated_rec.trust_state == TrustState.UNVERIFIED.value
    assert ver2.version == 2
    assert len(repo.get_versions(rec.id, tenant_id)) == 2


def test_update_memory_unverified_stays_unverified(repo):
    """Rule 3: Updating an UNVERIFIED record appends a new version and remains UNVERIFIED."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Initial unverified", repository=repo)
    assert rec.trust_state == TrustState.UNVERIFIED.value

    updated_rec, ver2 = update_memory(tenant_id=tenant_id, record_id=rec.id, content="Unverified edit", repository=repo)
    assert updated_rec.current_version == 2
    assert updated_rec.trust_state == TrustState.UNVERIFIED.value
    assert ver2.version == 2
    assert len(repo.get_versions(rec.id, tenant_id)) == 2


def test_update_memory_suspicious_stays_suspicious(repo):
    """Rule 4: Updating a SUSPICIOUS record appends a new version and stays SUSPICIOUS (an edit must never clear a flag)."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Suspicious content", repository=repo)
    transition_memory_trust_state(tenant_id, rec.id, TrustState.SUSPICIOUS.value, repository=repo)
    assert repo.get_record(rec.id, tenant_id).trust_state == TrustState.SUSPICIOUS.value

    updated_rec, ver2 = update_memory(tenant_id=tenant_id, record_id=rec.id, content="Suspicious edit attempting to clear flag", repository=repo)
    assert updated_rec.current_version == 2
    assert updated_rec.trust_state == TrustState.SUSPICIOUS.value
    assert ver2.version == 2
    assert len(repo.get_versions(rec.id, tenant_id)) == 2


def test_update_memory_refused_on_quarantined_record(repo):
    """Rule 1: Updating a QUARANTINED record is refused with ValidationError; leaves version count, trust_state and updated_at unchanged."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Malicious injection payload", repository=repo)
    transition_memory_trust_state(tenant_id, rec.id, TrustState.QUARANTINED.value, repository=repo)
    baseline_record = repo.get_record(rec.id, tenant_id)
    baseline_updated_at = baseline_record.updated_at

    with pytest.raises(ValidationError) as exc:
        update_memory(tenant_id=tenant_id, record_id=rec.id, content="Attempted fix on quarantined record", repository=repo)
    assert "QUARANTINED" in str(exc.value)

    # Invariants: version count, trust_state, and updated_at unchanged; no new version row
    after_rec = repo.get_record(rec.id, tenant_id)
    assert after_rec.current_version == 1
    assert after_rec.trust_state == TrustState.QUARANTINED.value
    assert after_rec.updated_at == baseline_updated_at
    assert len(repo.get_versions(rec.id, tenant_id)) == 1


def test_update_memory_refused_on_rejected_record(repo):
    """Rule 1: Updating a REJECTED record is refused with ValidationError; leaves version count, trust_state and updated_at unchanged."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Rejected content", repository=repo)
    force_trust_state(tenant_id, rec.id, TrustState.REJECTED.value, repository=repo)
    baseline_record = repo.get_record(rec.id, tenant_id)
    baseline_updated_at = baseline_record.updated_at

    with pytest.raises(ValidationError) as exc:
        update_memory(tenant_id=tenant_id, record_id=rec.id, content="Attempted fix on rejected record", repository=repo)
    assert "REJECTED" in str(exc.value)

    after_rec = repo.get_record(rec.id, tenant_id)
    assert after_rec.current_version == 1
    assert after_rec.trust_state == TrustState.REJECTED.value
    assert after_rec.updated_at == baseline_updated_at
    assert len(repo.get_versions(rec.id, tenant_id)) == 1


def test_update_memory_refused_on_superseded_record(repo):
    """Rule 1: Updating a SUPERSEDED record is refused with ValidationError; leaves version count, trust_state and updated_at unchanged."""
    tenant_id = "tenant-update-rules"
    rec, ver1 = ingest_memory(tenant_id=tenant_id, content="Superseded content", repository=repo)
    force_trust_state(tenant_id, rec.id, TrustState.SUPERSEDED.value, repository=repo)
    baseline_record = repo.get_record(rec.id, tenant_id)
    baseline_updated_at = baseline_record.updated_at

    with pytest.raises(ValidationError) as exc:
        update_memory(tenant_id=tenant_id, record_id=rec.id, content="Attempted fix on superseded record", repository=repo)
    assert "SUPERSEDED" in str(exc.value)

    after_rec = repo.get_record(rec.id, tenant_id)
    assert after_rec.current_version == 1
    assert after_rec.trust_state == TrustState.SUPERSEDED.value
    assert after_rec.updated_at == baseline_updated_at
    assert len(repo.get_versions(rec.id, tenant_id)) == 1


def test_update_memory_cross_tenant_refusal_fails_as_not_found(repo):
    """Updating a record owned by another tenant fails as MemoryNotFoundError even if the target record is in terminal/quarantined state."""
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"
    rec_a, _ = ingest_memory(tenant_id=tenant_a, content="Tenant A memory", repository=repo)
    transition_memory_trust_state(tenant_a, rec_a.id, TrustState.QUARANTINED.value, repository=repo)

    # Attempting to update tenant A's record from tenant B context raises MemoryNotFoundError
    with pytest.raises(MemoryNotFoundError) as exc:
        update_memory(tenant_id=tenant_b, record_id=rec_a.id, content="Cross-tenant update attempt", repository=repo)
    assert rec_a.id in str(exc.value)
