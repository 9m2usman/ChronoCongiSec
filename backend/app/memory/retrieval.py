"""Memory retrieval and detail querying operations.

Module: backend.app.memory.retrieval
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §13 & §15 and Document 05 §5.1 specifications.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from backend.app.core.exceptions import ForbiddenError, NotFoundError, ValidationError
from .integrity import MemoryIntegrityError, sha256_hex, verify_checksum
from .models import MemoryRecord, MemoryVersion, ProvenanceEdge, TrustState
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
    limit: int = 50,
    offset: int = 0,
    for_forensic: bool = False,
    exclude_quarantined: bool = True,
    repository: Optional[MemoryRepository] = None,
) -> List[MemoryRecord]:
    """Retrieve memory records for a tenant and optional agent.

    Enforces GAP-001:
    1. Tenant scoping: only records belonging to `tenant_id` are returned.
    2. Trust state restriction: Normal agent retrieval returns ONLY eligible TRUSTED records.
       UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, and SUPERSEDED records are strictly excluded.
    3. Query parameter validation: Callers cannot request non-TRUSTED states unless for_forensic=True.
    4. Pagination: respects limit (max 100) and offset.
    5. Cryptographic integrity: re-verifies stored checksums of all versions against content.
       If any checksum mismatch is detected, raises MemoryIntegrityError and does not return the record.
    """
    repo = repository or get_default_repository()

    # Enforce GAP-001: Normal agent retrieval returns ONLY eligible TRUSTED memory
    if not for_forensic:
        if trust_state is not None and trust_state.upper() != TrustState.TRUSTED.value:
            raise ForbiddenError("Normal agent retrieval is strictly restricted to TRUSTED memory records.")
        target_trust = TrustState.TRUSTED.value
        only_trusted = True
    else:
        target_trust = trust_state
        only_trusted = False

    records = repo.list_records(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trust_state=target_trust,
        only_trusted=only_trusted,
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
    for_forensic: bool = False,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, List[MemoryVersion], List[ProvenanceEdge]]:
    """Fetch complete memory detail including full version history and provenance edges.

    Enforces GAP-004:
    1. Tenant scoping: only records belonging to tenant_id are accessed.
    2. Trust safety: Normal detail access applies the exact same trust invariant as list retrieval.
       Only eligible TRUSTED current memory may be exposed to normal agent-facing detail operations.
       Non-TRUSTED records (UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED) return 404.
    3. Forensic override: allow_quarantined=True or for_forensic=True permits authorized inspection.
    4. Cryptographic integrity: re-verifies checksums across all versions for tampering detection.
    """
    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    # Enforce GAP-004: Normal detail access requires TRUSTED state
    if not for_forensic and not allow_quarantined and record.trust_state != TrustState.TRUSTED.value:
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


def transition_memory_trust_state(
    tenant_id: str,
    record_id: str,
    new_trust_state: str,
    reason: str = "Authorized M4 security policy transition",
    analyst_id: Optional[str] = None,
    repository: Optional[MemoryRepository] = None,
) -> MemoryRecord:
    """Transition a memory record's trust state according to M4 Security Engine lifecycle rules.

    M4 owns trust decisions. This function allows authorized M4 workflows (and test harnesses)
    to transition a record from UNVERIFIED -> TRUSTED, or SUSPICIOUS, or QUARANTINED.
    """
    valid_states = {s.value for s in TrustState}
    target_state = new_trust_state.upper()
    if target_state not in valid_states:
        raise ValidationError(f"Invalid trust state '{new_trust_state}'. Must be one of {valid_states}.")

    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(f"Memory record '{record_id}' not found for tenant '{tenant_id}'.")

    record.trust_state = target_state
    record.updated_at = datetime.now(timezone.utc)
    return repo.update_record(record)


__all__ = [
    "MemoryNotFoundError",
    "retrieve_memory",
    "get_memory_detail",
    "transition_memory_trust_state",
]
