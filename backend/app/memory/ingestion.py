"""Memory ingestion and provenance lineage establishment.

Module: backend.app.memory.ingestion
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §13 & §15 and Document 05 §5.1 specifications.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from backend.app.core.exceptions import ValidationError
from .integrity import sha256_hex
from .models import (
    MemoryRecord,
    MemoryVersion,
    ProvenanceRelationType,
    RecordType,
    TrustState,
)
from .provenance import (
    MAX_PROVENANCE_DEPTH,
    MAX_TRAVERSAL_BUDGET,
    InvalidProvenanceError,
    _check_dag_cycle,
    _get_lineage_depth,
    create_provenance_edge,
)
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError


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
    Strictly verifies parent record existence, tenant boundary, and DAG depth/acyclicity.
    """
    if content is None or not content.strip():
        raise ValidationError("Memory content must not be empty or whitespace only.")

    repo = repository or get_default_repository()
    now = datetime.now(timezone.utc)
    record_id = str(uuid.uuid4())
    version_id = str(uuid.uuid4())

    # 1. Validate parent record if provided
    if parent_record_id:
        parent = repo.get_record(parent_record_id, tenant_id)
        if not parent:
            raise MemoryNotFoundError(
                f"Parent memory record '{parent_record_id}' not found for tenant '{tenant_id}'. "
                f"Cross-tenant and nonexistent parent references are strictly prohibited."
            )
        _check_dag_cycle(repo, parent_record_id, record_id, tenant_id)

    checksum = sha256_hex(content)

    # 2. Create MemoryRecord (Table 11: default trust_state is UNVERIFIED on ingestion)
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

    # 3. Create MemoryVersion (Table 12: version 1, immutable)
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

    # 4. Create ProvenanceEdge if derived from parent using provenance.create_provenance_edge (Table 14)
    if parent_record_id:
        create_provenance_edge(
            tenant_id=tenant_id,
            from_record_id=parent_record_id,
            to_record_id=record_id,
            relation_type=ProvenanceRelationType.DERIVED_FROM.value,
            repository=repo,
        )

    return record, version


__all__ = [
    "ingest_memory",
    "create_provenance_edge",
    "InvalidProvenanceError",
    "MAX_PROVENANCE_DEPTH",
    "MAX_TRAVERSAL_BUDGET",
    "_check_dag_cycle",
    "_get_lineage_depth",
]
