"""Unit and integration tests for memory service and repository."""

import sys
from pathlib import Path
import pytest

# Ensure repo root is in sys.path
repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.memory.hashing import sha256_hex
from backend.app.memory.models import TrustState
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.service import (
    MemoryIntegrityError,
    MemoryNotFoundError,
    get_memory_detail,
    ingest_memory,
    retrieve_memory,
    update_memory,
)


@pytest.fixture
def repo():
    """Isolated in-memory repository for each test."""
    return InMemoryMemoryRepository()


def test_version_1_on_create(repo):
    """Ingesting memory must create MemoryRecord with version 1, UNVERIFIED trust state, and valid SHA-256."""
    content = "Standard Treasury wire verification threshold: $500.00."
    tenant_id = "tenant-alpha"

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


def test_quarantined_records_excluded_by_default(repo):
    """QUARANTINED records must be excluded when exclude_quarantined=True, but retrievable when False."""
    tenant_id = "tenant-alpha"

    # Ingest clean record 1
    rec1, _ = ingest_memory(tenant_id=tenant_id, content="Legitimate vendor profile.", repository=repo)

    # Ingest record 2 and simulate quarantine state (as applied by M4 Quarantine Engine)
    rec2, _ = ingest_memory(tenant_id=tenant_id, content="Suspicious prompt injection payload.", repository=repo)
    rec2_obj = repo._records[rec2.id]
    rec2_obj.trust_state = "QUARANTINED"

    # By default, exclude_quarantined=True -> only rec1 returned
    active_records = retrieve_memory(tenant_id=tenant_id, exclude_quarantined=True, repository=repo)
    active_ids = [r.id for r in active_records]
    assert rec1.id in active_ids
    assert rec2.id not in active_ids

    # When exclude_quarantined=False (e.g., forensic view in Security Center) -> both returned
    all_records = retrieve_memory(tenant_id=tenant_id, exclude_quarantined=False, repository=repo)
    all_ids = [r.id for r in all_records]
    assert rec1.id in all_ids
    assert rec2.id in all_ids


def test_tenant_isolation_cannot_read_other_tenant_records(repo):
    """Tenant B must never be able to retrieve, view detail, or update Tenant A's records."""
    tenant_a = "tenant-company-a"
    tenant_b = "tenant-company-b"

    rec_a, _ = ingest_memory(
        tenant_id=tenant_a,
        content="Confidential Company A financial strategy.",
        repository=repo,
    )

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
