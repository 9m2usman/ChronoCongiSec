"""Memory & Provenance business service layer.

Implements Document 02 §13 & §15, Document 05 §3.3 & §5.1, and Document 06 M3 specifications.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional, Set, Tuple

from backend.app.core.exceptions import AMSCException, NotFoundError, ValidationError
from .hashing import sha256_hex
from .models import (
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    TrustState,
)
from .repository import MemoryRepository, get_default_repository

# Documented governance limits for provenance DAG
MAX_PROVENANCE_DEPTH = 5
MAX_TRAVERSAL_BUDGET = 50


class MemoryIntegrityError(AMSCException):
    """Raised when cryptographic checksum verification fails for a memory record."""

    def __init__(
        self,
        message: str = "Cryptographic checksum verification failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            code="MEMORY_INTEGRITY_VIOLATION",
            status_code=500,
            details=details,
        )


class MemoryNotFoundError(NotFoundError):
    """Raised when a requested memory record is not found."""

    def __init__(
        self,
        message: str = "The requested memory record was not found.",
        details: Any = None,
    ):
        super().__init__(message=message, details=details)


class InvalidProvenanceError(AMSCException):
    """Raised when a provenance edge violates tenant scoping, parent existence, depth limits, or DAG acyclicity."""

    def __init__(
        self,
        message: str = "Invalid provenance relationship.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            code="INVALID_PROVENANCE",
            status_code=400,
            details=details,
        )


def _get_lineage_depth(
    repo: MemoryRepository,
    record_id: str,
    tenant_id: str,
    visited: Optional[Set[str]] = None,
    current_depth: int = 1,
) -> int:
    """Calculate the maximum upstream lineage depth leading into record_id within tenant scope."""
    if visited is None:
        visited = set()
    if record_id in visited:
        raise InvalidProvenanceError(f"Provenance cycle detected in ancestry for record '{record_id}'.")
    if current_depth > MAX_PROVENANCE_DEPTH:
        raise InvalidProvenanceError(
            f"Provenance lineage depth limit exceeded: lineage depth exceeds maximum of {MAX_PROVENANCE_DEPTH}."
        )
    if len(visited) >= MAX_TRAVERSAL_BUDGET:
        raise InvalidProvenanceError(
            f"Provenance traversal node budget exceeded: maximum allowable traversal budget is {MAX_TRAVERSAL_BUDGET} nodes."
        )

    visited.add(record_id)
    edges = repo.get_edges_for_record(record_id, tenant_id)
    incoming_parents = [
        edge.from_record_id
        for edge in edges
        if edge.to_record_id == record_id and edge.tenant_id == tenant_id
    ]

    if not incoming_parents:
        return current_depth

    max_ancestor_depth = current_depth
    for parent_id in incoming_parents:
        d = _get_lineage_depth(repo, parent_id, tenant_id, set(visited), current_depth + 1)
        if d > max_ancestor_depth:
            max_ancestor_depth = d
    return max_ancestor_depth


def _check_dag_cycle(
    repo: MemoryRepository,
    from_id: str,
    to_id: str,
    tenant_id: str,
) -> None:
    """Verify that adding an edge from_id -> to_id does not create a cycle or exceed depth/budget limits."""
    if from_id == to_id:
        raise InvalidProvenanceError(
            f"Self-referential provenance edge prohibited: record '{from_id}' cannot derive from itself."
        )

    # 1. Check upstream ancestry depth of parent
    parent_depth = _get_lineage_depth(repo, from_id, tenant_id)
    if parent_depth + 1 > MAX_PROVENANCE_DEPTH:
        raise InvalidProvenanceError(
            f"Provenance lineage depth limit exceeded: maximum allowable lineage depth is {MAX_PROVENANCE_DEPTH}."
        )

    # 2. Downstream search: check if from_id is reachable from to_id (cycle detection)
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(to_id, 1)]

    while queue:
        current, depth = queue.pop(0)
        if current == from_id:
            raise InvalidProvenanceError(
                f"Provenance cycle detected: adding edge from '{from_id}' to '{to_id}' creates a cyclic lineage."
            )
        if depth > MAX_PROVENANCE_DEPTH:
            raise InvalidProvenanceError(
                f"Provenance traversal depth limit exceeded: maximum allowable lineage depth is {MAX_PROVENANCE_DEPTH}."
            )
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > MAX_TRAVERSAL_BUDGET:
            raise InvalidProvenanceError(
                f"Provenance traversal node budget exceeded: maximum allowable traversal budget is {MAX_TRAVERSAL_BUDGET} nodes."
            )

        edges = repo.get_edges_for_record(current, tenant_id)
        for edge in edges:
            if edge.from_record_id == current and edge.to_record_id not in visited and edge.tenant_id == tenant_id:
                queue.append((edge.to_record_id, depth + 1))


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

    # 4. Create ProvenanceEdge if derived from parent (Table 14)
    if parent_record_id:
        edge = ProvenanceEdge(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            from_record_id=parent_record_id,
            to_record_id=record_id,
            relation_type=ProvenanceRelationType.DERIVED_FROM.value,
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
    if content is None or not content.strip():
        raise ValidationError("Updated memory content must not be empty.")

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
    limit: int = 50,
    offset: int = 0,
    repository: Optional[MemoryRepository] = None,
) -> List[MemoryRecord]:
    """Retrieve memory records for a tenant and optional agent.

    Enforces:
    1. Tenant scoping: only records belonging to `tenant_id` are returned.
    2. Quarantine exclusion: QUARANTINED and REJECTED records are strictly excluded when exclude_quarantined=True.
    3. Pagination: respects limit (max 100) and offset.
    4. Cryptographic integrity: re-verifies stored checksums of all versions against content.
       If any checksum mismatch is detected, raises MemoryIntegrityError and does not return the record.
    """
    repo = repository or get_default_repository()
    records = repo.list_records(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trust_state=trust_state,
        exclude_quarantined=exclude_quarantined,
        limit=limit,
        offset=offset,
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
    allow_quarantined: bool = False,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, List[MemoryVersion], List[ProvenanceEdge]]:
    """Fetch complete memory detail including full version history and provenance edges.

    Enforces:
    1. Tenant scoping: only records belonging to tenant_id are accessed.
    2. Quarantine safety: QUARANTINED and REJECTED records are hidden from normal agent access (returns 404).
    3. Cryptographic integrity: re-verifies checksums across all versions for tampering detection.
    """
    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    # Protect against unauthorized access to quarantined or rejected memory
    if not allow_quarantined and record.trust_state in ("QUARANTINED", "REJECTED"):
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
