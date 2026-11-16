"""Memory retrieval and detail querying operations.

Module: backend.app.memory.retrieval
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §13 & §15 and Document 05 §5.1 specifications.
"""

from typing import Any, List, Optional, Tuple

from backend.app.core.exceptions import NotFoundError
from .integrity import MemoryIntegrityError, verify_checksum
from .models import MemoryRecord, MemoryVersion, ProvenanceEdge
from .repository import MemoryRepository, get_default_repository


class MemoryNotFoundError(NotFoundError):
    """Raised when a requested memory record is not found."""

    def __init__(
        self,
        message: str = "The requested memory record was not found.",
        details: Any = None,
    ):
        super().__init__(message=message, details=details)


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
            if not verify_checksum(ver.content, ver.checksum):
                raise MemoryIntegrityError(
                    f"Cryptographic integrity violation: MemoryRecord '{record.id}' "
                    f"Version {ver.version} checksum mismatch! "
                    f"Stored='{ver.checksum}'."
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
        if not verify_checksum(ver.content, ver.checksum):
            raise MemoryIntegrityError(
                f"Cryptographic integrity violation: MemoryRecord '{record_id}' "
                f"Version {ver.version} checksum mismatch! "
                f"Stored='{ver.checksum}'."
            )

    edges = repo.get_edges_for_record(record_id, tenant_id)
    return record, versions, edges


__all__ = [
    "MemoryNotFoundError",
    "retrieve_memory",
    "get_memory_detail",
]
