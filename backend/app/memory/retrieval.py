"""Memory retrieval and detail querying operations.

Module: backend.app.memory.retrieval
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §13 & §15 and Document 05 §5.1 specifications.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from backend.app.core.exceptions import ForbiddenError, NotFoundError, ValidationError
from .integrity import MemoryIntegrityError, sha256_hex
from .models import (
    MemoryRecord,
    MemoryRefCheck,
    MemoryRefStatus,
    MemoryVersion,
    ProvenanceEdge,
    TrustState,
)
from .repository import AwaitableList, MemoryRepository, get_default_repository


class AwaitableTuple(tuple):
    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


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

    SECURITY INVARIANT:
    Never expose the `for_forensic` parameter via public API query parameters or client request bodies.
    Callers requesting `for_forensic=True` must be strictly authenticated and authorized by M1/M4
    security workflows (e.g. specialized incident triage or audit roles).

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
        if not for_forensic and hasattr(repo, "get_edges_for_record"):
            edges_res = repo.get_edges_for_record(record.id, tenant_id)
            if isinstance(edges_res, (list, tuple)):
                has_restricted_parent = False
                for edge in edges_res:
                    if getattr(edge, "to_record_id", None) == record.id:
                        parent_res = repo.get_record(edge.from_record_id, tenant_id)
                        if hasattr(parent_res, "trust_state"):
                            p_state = (
                                parent_res.trust_state.value
                                if hasattr(parent_res.trust_state, "value")
                                else str(parent_res.trust_state)
                            )
                            if p_state in {TrustState.QUARANTINED.value, TrustState.REJECTED.value}:
                                has_restricted_parent = True
                                break
                if has_restricted_parent:
                    continue
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

    return AwaitableList(verified_records)


def get_memory_detail(
    tenant_id: str,
    record_id: str,
    for_forensic: bool = False,
    repository: Optional[MemoryRepository] = None,
    allow_quarantined: bool = False,
) -> Tuple[MemoryRecord, List[MemoryVersion], List[ProvenanceEdge]]:
    """Fetch complete memory detail including full version history and provenance edges.

    SECURITY INVARIANT:
    Never expose the `for_forensic` parameter via public API query parameters or client request bodies.
    Normal agent-facing API routes must strictly call `get_memory_detail(..., for_forensic=False)`.
    Callers requesting `for_forensic=True` must be gated by explicit M1/M4 authorization checks.

    Enforces GAP-004:
    1. Tenant scoping: only records belonging to tenant_id are accessed.
    2. Trust safety: Normal detail access applies the exact same trust invariant as list retrieval.
       Only eligible TRUSTED current memory may be exposed to normal agent-facing detail operations.
       Non-TRUSTED records (UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED) return 404.
    3. Forensic override: for_forensic=True permits authorized security analyst inspection.
    4. Cryptographic integrity: re-verifies checksums across all versions for tampering detection.
    """
    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    # Enforce GAP-004: Normal detail access requires TRUSTED state
    if not (for_forensic or allow_quarantined) and record.trust_state != TrustState.TRUSTED.value:
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
    if not (for_forensic or allow_quarantined) and isinstance(edges, (list, tuple)):
        for edge in edges:
            if getattr(edge, "to_record_id", None) == record_id:
                parent_res = repo.get_record(edge.from_record_id, tenant_id)
                if hasattr(parent_res, "trust_state"):
                    p_state = (
                        parent_res.trust_state.value
                        if hasattr(parent_res.trust_state, "value")
                        else str(parent_res.trust_state)
                    )
                    if p_state in {TrustState.QUARANTINED.value, TrustState.REJECTED.value}:
                        raise MemoryNotFoundError(
                            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
                        )
    return AwaitableTuple((record, versions, edges))


# Allowed trust state transitions according to TRD §15.3 and 19-rule transition matrix
ALLOWED_TRUST_TRANSITIONS: dict[str, set[str]] = {
    TrustState.UNVERIFIED.value: {TrustState.TRUSTED.value, TrustState.SUSPICIOUS.value, TrustState.QUARANTINED.value, TrustState.REJECTED.value},
    TrustState.TRUSTED.value: {TrustState.SUSPICIOUS.value, TrustState.QUARANTINED.value, TrustState.UNVERIFIED.value, TrustState.SUPERSEDED.value},
    TrustState.SUSPICIOUS.value: {TrustState.QUARANTINED.value, TrustState.UNVERIFIED.value, TrustState.REJECTED.value},
    TrustState.QUARANTINED.value: {TrustState.REJECTED.value, TrustState.UNVERIFIED.value},
    TrustState.SUPERSEDED.value: {TrustState.QUARANTINED.value, TrustState.REJECTED.value, TrustState.UNVERIFIED.value},
    TrustState.REJECTED.value: set(),  # Terminal state: REJECTED has no exits
}


# Restriction order used by M4 (backend.app.security.trust): higher = more restrictive.
_RESTRICTION_RANK = {
    TrustState.TRUSTED.value: 0,
    TrustState.UNVERIFIED.value: 1,
    TrustState.SUPERSEDED.value: 2,
    TrustState.SUSPICIOUS.value: 3,
    TrustState.QUARANTINED.value: 4,
    TrustState.REJECTED.value: 5,
}
# Targets this M3 primitive may set on its own: reversible restrictions only. TRUSTED (validation
# evidence), REJECTED (authorised actor, terminal), SUPERSEDED (successor evidence) and every
# relaxation require M4's TrustEvaluator, which writes through MemoryRepository.update_record.
_RESTRICT_ONLY_TARGETS = frozenset({
    TrustState.UNVERIFIED.value, TrustState.SUSPICIOUS.value, TrustState.QUARANTINED.value,
})


def transition_memory_trust_state(
    tenant_id: str,
    record_id: str,
    new_trust_state: str,
    reason: str = "Authorized M4 security policy transition",
    analyst_id: Optional[str] = None,
    repository: Optional[MemoryRepository] = None,
) -> MemoryRecord:
    """Restrict-only trust-state primitive (finding F-2).

    M4 owns trust decisions (TRD §15.3). This M3 function cannot see the transition matrix's
    evidence, actor or history, so it may only move a record to a MORE restrictive, reversible
    state: TRUSTED -> UNVERIFIED (invalidate), or to SUSPICIOUS / QUARANTINED from a less
    restrictive state. Everything else raises ``ValidationError``:

    - promotion to TRUSTED, and any relaxation (e.g. QUARANTINED -> UNVERIFIED);
    - REJECTED and SUPERSEDED targets (M4 requires an authorised actor / successor evidence);
    - exits from REJECTED (terminal) and unknown stored or requested states (fail closed).

    Promotions, releases and recovery go through ``backend.app.security.trust.TrustEvaluator``.
    Setting the current state again is an idempotent no-op.
    """
    if not isinstance(new_trust_state, str):
        raise ValidationError("Invalid trust state.")
    target_state = new_trust_state.strip().upper()
    if target_state not in _RESTRICTION_RANK:
        raise ValidationError(f"Invalid trust state '{new_trust_state}'.")

    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record or getattr(record, "tenant_id", None) != tenant_id:
        raise MemoryNotFoundError(f"Memory record '{record_id}' not found for tenant '{tenant_id}'.")

    current_state = record.trust_state.value if hasattr(record.trust_state, "value") else str(record.trust_state)
    if current_state not in _RESTRICTION_RANK:
        raise ValidationError(
            f"Illegal trust transition for record '{record_id}': stored trust state is unknown (fail closed)."
        )
    if current_state == target_state:
        return record
    if current_state == TrustState.REJECTED.value:
        raise ValidationError(
            f"Illegal trust transition for record '{record_id}': record is in terminal state 'REJECTED' with no exits."
        )
    if target_state not in _RESTRICT_ONLY_TARGETS or _RESTRICTION_RANK[target_state] <= _RESTRICTION_RANK[current_state]:
        raise ValidationError(
            f"Illegal trust transition for record '{record_id}': {current_state} -> {target_state} must be decided "
            "by the M4 TrustEvaluator (this primitive only applies reversible restrictions)."
        )

    record.trust_state = target_state
    record.updated_at = datetime.now(timezone.utc)
    return repo.update_record(record)


# Default maximum number of memory references evaluated in a single action proposal.
# Enforced as an M3 default pending M4/M2 formal confirmation.
MAX_MEMORY_REFS_PER_PROPOSAL = 100


# Interface not yet confirmed by M4/M2; shape may change.
def verify_memory_refs(
    tenant_id: str,
    memory_refs: Any,
    repository: Optional[MemoryRepository] = None,
) -> List[MemoryRefCheck]:
    """Verify memory references for an action proposal at the Security Gateway (Gate G4).

    Evaluates whether each referenced memory record exists within the tenant, verifies the
    cryptographic integrity of its current active version, and extracts its exact trust state
    and version for downstream policy evaluation by M4 Security Engine.

    SECURITY INVARIANTS:
    1. Read-only: Performs zero state transitions, updates, or writes (no record/version changes).
    2. Fail closed: Any unexpected exception evaluates to status=ERROR, never OK.
    3. Strict tenant isolation: Nonexistent records and records belonging to other tenants both
       return NOT_FOUND with identical sanitized reason messages (zero existence leakage).
    4. Exact trust reflection: Returns the record's trust_state exactly as stored without alteration.
       No ALLOW/BLOCK decision is made here; policy decision is exclusively owned by M4.
    5. Input safety: Empty, malformed, non-string, or oversized lists are safely handled without raising.
    6. Internal isolation: No imports from backend.app.security or backend.app.gateway.
    """
    repo = repository or get_default_repository()

    # Reject non-list inputs or oversized lists beyond maximum allowed boundary
    if not isinstance(memory_refs, list):
        return [
            MemoryRefCheck(
                record_id=None,
                status=MemoryRefStatus.INVALID_REF,
                trust_state=None,
                current_version=None,
                reason="Invalid memory_refs payload: expected a list of reference identifiers.",
            )
        ]

    if len(memory_refs) > MAX_MEMORY_REFS_PER_PROPOSAL:
        return [
            MemoryRefCheck(
                record_id=None,
                status=MemoryRefStatus.ERROR,
                trust_state=None,
                current_version=None,
                reason=f"Proposal exceeds maximum allowed memory references limit of {MAX_MEMORY_REFS_PER_PROPOSAL}.",
            )
        ]

    results: List[MemoryRefCheck] = []
    seen_ids: set = set()

    for ref in memory_refs:
        # Validate ref type and non-emptiness
        if not isinstance(ref, str) or not ref.strip():
            results.append(
                MemoryRefCheck(
                    record_id=ref if isinstance(ref, str) else None,
                    status=MemoryRefStatus.INVALID_REF,
                    trust_state=None,
                    current_version=None,
                    reason="Invalid reference: identifier must be a non-empty string.",
                )
            )
            continue

        ref_id = ref.strip()

        # Check for duplicates within the current proposal
        if ref_id in seen_ids:
            results.append(
                MemoryRefCheck(
                    record_id=ref_id,
                    status=MemoryRefStatus.DUPLICATE_REF,
                    trust_state=None,
                    current_version=None,
                    reason=f"Duplicate memory reference '{ref_id}' in proposal.",
                )
            )
            continue

        seen_ids.add(ref_id)

        try:
            # Query repository directly within strict tenant scoping boundary
            record = repo.get_record(ref_id, tenant_id)
            if not record or record.tenant_id != tenant_id:
                results.append(
                    MemoryRefCheck(
                        record_id=ref_id,
                        status=MemoryRefStatus.NOT_FOUND,
                        trust_state=None,
                        current_version=None,
                        reason="Memory record not found or inaccessible in tenant scope.",
                    )
                )
                continue

            # Fetch the current version of the record
            current_ver_num = record.current_version
            version_obj = repo.get_version(ref_id, current_ver_num, tenant_id)
            if not version_obj:
                results.append(
                    MemoryRefCheck(
                        record_id=ref_id,
                        status=MemoryRefStatus.INTEGRITY_FAILED,
                        trust_state=record.trust_state,
                        current_version=current_ver_num,
                        reason=f"Current version {current_ver_num} missing for record '{ref_id}'.",
                    )
                )
                continue

            # Verify cryptographic integrity of the current version's content
            expected_checksum = version_obj.checksum
            computed_checksum = sha256_hex(version_obj.content)
            if computed_checksum != expected_checksum:
                results.append(
                    MemoryRefCheck(
                        record_id=ref_id,
                        status=MemoryRefStatus.INTEGRITY_FAILED,
                        trust_state=record.trust_state,
                        current_version=current_ver_num,
                        reason="Cryptographic checksum mismatch on current record version.",
                    )
                )
                continue

            # Current version content matches checksum; return OK with exact stored trust state
            results.append(
                MemoryRefCheck(
                    record_id=ref_id,
                    status=MemoryRefStatus.OK,
                    trust_state=record.trust_state,
                    current_version=current_ver_num,
                    reason="Memory reference verified and current version integrity valid.",
                )
            )
        except Exception:
            # Fail closed: convert any unexpected repository or internal exception to ERROR
            results.append(
                MemoryRefCheck(
                    record_id=ref_id,
                    status=MemoryRefStatus.ERROR,
                    trust_state=None,
                    current_version=None,
                    reason="Unexpected error encountered during memory reference verification.",
                )
            )

    return results


__all__ = [
    "MemoryNotFoundError",
    "retrieve_memory",
    "get_memory_detail",
    "transition_memory_trust_state",
    "verify_memory_refs",
    "MAX_MEMORY_REFS_PER_PROPOSAL",
]
