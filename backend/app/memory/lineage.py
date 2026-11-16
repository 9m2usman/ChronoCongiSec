"""Provenance lineage traversal and blast radius discovery.

Module: backend.app.memory.lineage
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 (bounded graph depth rule <= 5) and BFS ancestry/descendant discovery.
Used by M4 Security Engine for blast-radius rollback calculation.
"""

from collections import deque
from typing import Any, List, Optional, Set, Tuple

from .provenance import MAX_PROVENANCE_DEPTH
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError


class LineageResult(list):
    """List of (record_id, depth) tuples with convenience helpers."""

    def record_ids(self) -> List[str]:
        """Extract just the record identifiers in breadth-first traversal order."""
        return [item[0] for item in self]

    def as_dict(self) -> dict:
        """Return a mapping of record_id -> traversal depth."""
        return {item[0]: item[1] for item in self}

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, str):
            return any(rec_id == item for rec_id, _ in self)
        return super().__contains__(item)


def get_descendants(
    tenant_id: str,
    record_id: str,
    max_depth: int = MAX_PROVENANCE_DEPTH,
    repository: Optional[MemoryRepository] = None,
) -> LineageResult:
    """Bounded breadth-first traversal finding all downstream descendants of record_id.

    Follows outgoing provenance edges (from_record_id == current -> to_record_id).
    Strictly tenant-scoped. Returns record IDs paired with their traversal depth.
    Used by M4 Security Engine for calculating blast radius during incident recovery.
    """
    repo = repository or get_default_repository()
    root = repo.get_record(record_id, tenant_id)
    if not root:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    bounded_limit = min(max_depth, MAX_PROVENANCE_DEPTH) if max_depth is not None else MAX_PROVENANCE_DEPTH

    results = LineageResult()
    visited: Set[str] = {record_id}
    queue: deque[Tuple[str, int]] = deque([(record_id, 0)])

    while queue:
        current_id, depth = queue.popleft()
        if depth >= bounded_limit:
            continue

        edges = repo.get_edges_for_record(current_id, tenant_id)
        for edge in edges:
            if edge.from_record_id == current_id and edge.tenant_id == tenant_id:
                child_id = edge.to_record_id
                if child_id not in visited:
                    visited.add(child_id)
                    child_depth = depth + 1
                    results.append((child_id, child_depth))
                    queue.append((child_id, child_depth))

    return results


def get_ancestors(
    tenant_id: str,
    record_id: str,
    max_depth: int = MAX_PROVENANCE_DEPTH,
    repository: Optional[MemoryRepository] = None,
) -> LineageResult:
    """Bounded breadth-first traversal finding all upstream ancestors of record_id.

    Follows incoming provenance edges (to_record_id == current -> from_record_id).
    Strictly tenant-scoped. Returns record IDs paired with their traversal depth.
    """
    repo = repository or get_default_repository()
    root = repo.get_record(record_id, tenant_id)
    if not root:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    bounded_limit = min(max_depth, MAX_PROVENANCE_DEPTH) if max_depth is not None else MAX_PROVENANCE_DEPTH

    results = LineageResult()
    visited: Set[str] = {record_id}
    queue: deque[Tuple[str, int]] = deque([(record_id, 0)])

    while queue:
        current_id, depth = queue.popleft()
        if depth >= bounded_limit:
            continue

        edges = repo.get_edges_for_record(current_id, tenant_id)
        for edge in edges:
            if edge.to_record_id == current_id and edge.tenant_id == tenant_id:
                parent_id = edge.from_record_id
                if parent_id not in visited:
                    visited.add(parent_id)
                    parent_depth = depth + 1
                    results.append((parent_id, parent_depth))
                    queue.append((parent_id, parent_depth))

    return results


__all__ = [
    "get_descendants",
    "get_ancestors",
    "LineageResult",
]
