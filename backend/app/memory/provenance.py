"""Provenance tracking and graph edge management.

Module: backend.app.memory.provenance
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 and Document 05 Table 14 (provenance_edges).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional, Set, Tuple, Union

from backend.app.core.exceptions import AMSCException, ValidationError
from .models import ProvenanceEdge, ProvenanceRelationType
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError

# Bounded graph governance limits (Document 02 Section 15.2 & TRD Performance Requirements)
MAX_PROVENANCE_DEPTH = 5
MAX_TRAVERSAL_BUDGET = 50

VALID_RELATION_TYPES = {
    ProvenanceRelationType.DERIVED_FROM.value,
    ProvenanceRelationType.TRANSFORMED_INTO.value,
    ProvenanceRelationType.SUPERSEDES.value,
}


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


def create_provenance_edge(
    tenant_id: str,
    from_record_id: str,
    to_record_id: str,
    relation_type: Union[ProvenanceRelationType, str] = "DERIVED_FROM",
    repository: Optional[MemoryRepository] = None,
) -> ProvenanceEdge:
    """Create a validated directional provenance edge between two memory records.

    Enforces:
    1. Relation Type: Must be DERIVED_FROM, TRANSFORMED_INTO, or SUPERSEDES.
    2. Self-Loop Rejection: from_record_id != to_record_id.
    3. Tenant Boundary: Both records must exist in the SAME tenant.
    4. Deduplication: Creating the same edge twice returns the existing edge without duplicating it.
    5. Acyclicity: Rejects any edge that would create a cycle.
    6. Bounded Depth: Rejects lineage exceeding MAX_PROVENANCE_DEPTH (5).
    """
    rel_type_str = (
        relation_type.value
        if isinstance(relation_type, ProvenanceRelationType)
        else str(relation_type)
    )
    if rel_type_str not in VALID_RELATION_TYPES:
        raise ValidationError(
            f"Invalid provenance relation_type '{rel_type_str}'. Must be one of {sorted(VALID_RELATION_TYPES)}."
        )

    # 1. Reject self-loops
    if from_record_id == to_record_id:
        raise InvalidProvenanceError(
            f"Self-referential provenance edge prohibited: record '{from_record_id}' cannot link to itself."
        )

    repo = repository or get_default_repository()

    # 2. Both records must exist in the SAME tenant
    from_record = repo.get_record(from_record_id, tenant_id)
    if not from_record:
        raise MemoryNotFoundError(
            f"Source memory record '{from_record_id}' not found for tenant '{tenant_id}'. "
            f"Cross-tenant and nonexistent parent references are strictly prohibited."
        )

    to_record = repo.get_record(to_record_id, tenant_id)
    if not to_record:
        raise MemoryNotFoundError(
            f"Target memory record '{to_record_id}' not found for tenant '{tenant_id}'. "
            f"Cross-tenant and nonexistent record references are strictly prohibited."
        )

    # 3. Deduplication: Creating the same edge twice must not duplicate it
    existing_edges = repo.get_edges_for_record(from_record_id, tenant_id)
    for existing in existing_edges:
        if (
            existing.tenant_id == tenant_id
            and existing.from_record_id == from_record_id
            and existing.to_record_id == to_record_id
            and existing.relation_type == rel_type_str
        ):
            return existing

    # 4. Cycle and depth validation
    _check_dag_cycle(repo, from_record_id, to_record_id, tenant_id)

    # 5. Persist edge
    now = datetime.now(timezone.utc)
    edge = ProvenanceEdge(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        from_record_id=from_record_id,
        to_record_id=to_record_id,
        relation_type=rel_type_str,
        created_at=now,
    )
    return repo.create_edge(edge)


__all__ = [
    "create_provenance_edge",
    "InvalidProvenanceError",
    "MAX_PROVENANCE_DEPTH",
    "MAX_TRAVERSAL_BUDGET",
    "VALID_RELATION_TYPES",
    "_check_dag_cycle",
    "_get_lineage_depth",
]
