"""Memory & Provenance business service layer.

Implements Document 02 §13 & §15, Document 05 §3.3 & §5.1, and Document 06 M3 specifications.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .hashing import sha256_hex
from .models import (
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    RecordType,
    TrustState,
)
from .repository import MemoryRepository, get_default_repository


class MemoryIntegrityError(Exception):
    """Raised when cryptographic checksum verification fails for a memory record."""
    pass


class MemoryNotFoundError(Exception):
    """Raised when a requested memory record is not found."""
    pass


def ingest_memory(
    tenant_id: str,
    content: str,
    agent_id: Optional[str] = None,
    record_type: str = "KNOWLEDGE",
    source_id: Optional[str] = None,
    parent_record_id: Optional[str] = None,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Ingest a new memory chunk.

    Creates a MemoryRecord with trust_state UNVERIFIED (M4 owns trust state transitions)
    and a MemoryVersion with version 1 and cryptographic checksum from sha256_hex.
    Optionally records a DERIVED_FROM provenance edge if parent_record_id is supplied.
    """
    repo = repository or get_default_repository()
    now = datetime.now(timezone.utc)
    record_id = str(uuid.uuid4())
    version_id = str(uuid.uuid4())

    checksum = sha256_hex(content)

    # 1. Create MemoryRecord (Table 11: default trust_state is UNVERIFIED on ingestion)
    record = MemoryRecord(
        id=record_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        source_id=source_id,
        record_type=record_type,
        trust_state=TrustState.UNVERIFIED.value,
        current_version=1,
        created_at=now,
        updated_at=now,
    )
    repo.create_record(record)

    # 2. Create MemoryVersion (Table 12: version 1, immutable)
    version = MemoryVersion(
        id=version_id,
        tenant_id=tenant_id,
        record_id=record_id,
        version=1,
        content=content,
        checksum=checksum,
        created_at=now,
    )
    repo.create_version(version)

    # 3. Create ProvenanceEdge if derived from parent (Table 14)
    if parent_record_id:
        edge = ProvenanceEdge(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            from_record_id=parent_record_id,
            to_record_id=record_id,
            relation_type="DERIVED_FROM",
            created_at=now,
        )
        repo.create_edge(edge)

    return record, version


def update_memory(
    tenant_id: str,
    record_id: str,
    content: str,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Update a memory record with new content.

    Appends a new immutable version (current_version + 1) with an independent SHA-256
    checksum. Never edits or mutates historical versions.
    Does NOT alter trust_state (M4 owns trust state lifecycle).
    """
    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    now = datetime.now(timezone.utc)
    new_version_num = record.current_version + 1
    checksum = sha256_hex(content)

    # 1. Create new immutable version
    new_version = MemoryVersion(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        record_id=record_id,
        version=new_version_num,
        content=content,
        checksum=checksum,
        created_at=now,
    )
    repo.create_version(new_version)

    # 2. Update record metadata (current_version and updated_at only; trust_state preserved)
    record.current_version = new_version_num
    record.updated_at = now
    repo.update_record(record)

    return record, new_version


def retrieve_memory(
    tenant_id: str,
    agent_id: Optional[str] = None,
    trust_state: Optional[str] = None,
    exclude_quarantined: bool = True,
    repository: Optional[MemoryRepository] = None,
) -> List[MemoryRecord]:
    """Retrieve memory records for a tenant and optional agent.

    Enforces:
    1. Tenant scoping: only records belonging to `tenant_id` are returned.
    2. Quarantine exclusion: QUARANTINED records are excluded by default (exclude_quarantined=True).
    3. Cryptographic integrity: re-verifies stored checksums of all versions against content.
       If any checksum mismatch is detected, raises MemoryIntegrityError and does not return the record.
    """
    repo = repository or get_default_repository()
    records = repo.list_records(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trust_state=trust_state,
        exclude_quarantined=exclude_quarantined,
    )

    verified_records: List[MemoryRecord] = []
    for record in records:
        versions = repo.get_versions(record.id, tenant_id)
        for ver in versions:
            expected_checksum = ver.checksum
            computed_checksum = sha256_hex(ver.content)
            if computed_checksum != expected_checksum:
                raise MemoryIntegrityError(
                    f"Cryptographic integrity violation: MemoryRecord '{record.id}' "
                    f"Version {ver.version} checksum mismatch! "
                    f"Stored='{expected_checksum}', Computed='{computed_checksum}'."
                )
        verified_records.append(record)

    return verified_records


def get_memory_detail(
    tenant_id: str,
    record_id: str,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, List[MemoryVersion], List[ProvenanceEdge]]:
    """Fetch complete memory detail including full version history and provenance edges.

    Re-verifies checksums across all versions for tampering detection.
    """
    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    versions = repo.get_versions(record_id, tenant_id)
    for ver in versions:
        expected = ver.checksum
        computed = sha256_hex(ver.content)
        if computed != expected:
            raise MemoryIntegrityError(
                f"Cryptographic integrity violation: MemoryRecord '{record_id}' "
                f"Version {ver.version} checksum mismatch! "
                f"Stored='{expected}', Computed='{computed}'."
            )

    edges = repo.get_edges_for_record(record_id, tenant_id)
    return record, versions, edges
