"""Provenance lineage traversal and blast radius discovery.

Module: backend.app.memory.lineage
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 (bounded graph depth rule <= 5) and BFS ancestry/descendant discovery.
Used by M4 Security Engine for blast-radius rollback calculation.
"""

from collections import deque
from typing import Any, List, Optional, Set, Tuple

from .provenance import (
    DEFAULT_MAX_DEADLINE_SECONDS,
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_REPO_CALLS,
    MAX_PROVENANCE_DEPTH,
    TraversalBudget,
    TraversalBudgetExceededError,
)
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError


class LineageResult(list):
    """List of (record_id, depth) tuples with convenience helpers and traversal budget metadata."""

    def __init__(
        self,
        iterable=None,
        complete: bool = True,
        truncated_reason: Optional[str] = None,
    ):
        if iterable is not None:
            super().__init__(iterable)
        else:
            super().__init__()
        self.complete: bool = complete
        self.truncated_reason: Optional[str] = truncated_reason

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
    max_depth: Optional[int] = None,
    max_nodes: Optional[int] = None,
    max_edges: Optional[int] = None,
    max_repo_calls: Optional[int] = None,
    deadline_seconds: Optional[float] = None,
    budget: Optional[TraversalBudget] = None,
    repository: Optional[MemoryRepository] = None,
) -> LineageResult:
    """Bounded breadth-first traversal finding all downstream descendants of record_id.

    Follows outgoing provenance edges (from_record_id == current -> to_record_id).
    Strictly tenant-scoped. Returns record IDs paired with their traversal depth.
    Used by M4 Security Engine for calculating blast radius during incident recovery.

    Enforces TraversalBudget limits (max_depth, max_nodes, max_edges, max_repo_calls, deadline).
    Returns complete=False and sets truncated_reason if any budget threshold is hit.
    """
    repo = repository or get_default_repository()
    root = repo.get_record(record_id, tenant_id)
    if not root:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    t_budget = budget or TraversalBudget(
        max_depth=max_depth if max_depth is not None else MAX_PROVENANCE_DEPTH,
        max_nodes=max_nodes if max_nodes is not None else DEFAULT_MAX_NODES,
        max_edges=max_edges if max_edges is not None else DEFAULT_MAX_EDGES,
        max_repo_calls=max_repo_calls if max_repo_calls is not None else DEFAULT_MAX_REPO_CALLS,
        deadline_seconds=deadline_seconds if deadline_seconds is not None else DEFAULT_MAX_DEADLINE_SECONDS,
    )

    results = LineageResult(complete=True, truncated_reason=None)
    try:
        t_budget.record_visit(record_id)
    except TraversalBudgetExceededError as e:
        results.complete = False
        results.truncated_reason = e.reason
        return results

    queue: deque[Tuple[str, int]] = deque([(record_id, 0)])

    while queue:
        current_id, depth = queue.popleft()

        if depth >= t_budget.max_depth:
            results.complete = False
            results.truncated_reason = "depth"
            continue

        try:
            t_budget.record_repo_call()
        except TraversalBudgetExceededError as e:
            results.complete = False
            results.truncated_reason = e.reason
            break

        edges = repo.get_edges_for_record(current_id, tenant_id)
        budget_truncated = False

        for edge in edges:
            if edge.from_record_id == current_id and edge.tenant_id == tenant_id:
                try:
                    t_budget.record_edge()
                except TraversalBudgetExceededError as e:
                    results.complete = False
                    results.truncated_reason = e.reason
                    budget_truncated = True
                    break

                child_id = edge.to_record_id
                if child_id not in t_budget.visited:
                    try:
                        t_budget.record_visit(child_id)
                    except TraversalBudgetExceededError as e:
                        results.complete = False
                        results.truncated_reason = e.reason
                        budget_truncated = True
                        break

                    child_depth = depth + 1
                    results.append((child_id, child_depth))
                    queue.append((child_id, child_depth))

        if budget_truncated:
            break

    return results


def get_ancestors(
    tenant_id: str,
    record_id: str,
    max_depth: Optional[int] = None,
    max_nodes: Optional[int] = None,
    max_edges: Optional[int] = None,
    max_repo_calls: Optional[int] = None,
    deadline_seconds: Optional[float] = None,
    budget: Optional[TraversalBudget] = None,
    repository: Optional[MemoryRepository] = None,
) -> LineageResult:
    """Bounded breadth-first traversal finding all upstream ancestors of record_id.

    Follows incoming provenance edges (to_record_id == current -> from_record_id).
    Strictly tenant-scoped. Returns record IDs paired with their traversal depth.

    Enforces TraversalBudget limits (max_depth, max_nodes, max_edges, max_repo_calls, deadline).
    Returns complete=False and sets truncated_reason if any budget threshold is hit.
    """
    repo = repository or get_default_repository()
    root = repo.get_record(record_id, tenant_id)
    if not root:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    t_budget = budget or TraversalBudget(
        max_depth=max_depth if max_depth is not None else MAX_PROVENANCE_DEPTH,
        max_nodes=max_nodes if max_nodes is not None else DEFAULT_MAX_NODES,
        max_edges=max_edges if max_edges is not None else DEFAULT_MAX_EDGES,
        max_repo_calls=max_repo_calls if max_repo_calls is not None else DEFAULT_MAX_REPO_CALLS,
        deadline_seconds=deadline_seconds if deadline_seconds is not None else DEFAULT_MAX_DEADLINE_SECONDS,
    )

    results = LineageResult(complete=True, truncated_reason=None)
    try:
        t_budget.record_visit(record_id)
    except TraversalBudgetExceededError as e:
        results.complete = False
        results.truncated_reason = e.reason
        return results

    queue: deque[Tuple[str, int]] = deque([(record_id, 0)])

    while queue:
        current_id, depth = queue.popleft()

        if depth >= t_budget.max_depth:
            results.complete = False
            results.truncated_reason = "depth"
            continue

        try:
            t_budget.record_repo_call()
        except TraversalBudgetExceededError as e:
            results.complete = False
            results.truncated_reason = e.reason
            break

        edges = repo.get_edges_for_record(current_id, tenant_id)
        budget_truncated = False

        for edge in edges:
            if edge.to_record_id == current_id and edge.tenant_id == tenant_id:
                try:
                    t_budget.record_edge()
                except TraversalBudgetExceededError as e:
                    results.complete = False
                    results.truncated_reason = e.reason
                    budget_truncated = True
                    break

                parent_id = edge.from_record_id
                if parent_id not in t_budget.visited:
                    try:
                        t_budget.record_visit(parent_id)
                    except TraversalBudgetExceededError as e:
                        results.complete = False
                        results.truncated_reason = e.reason
                        budget_truncated = True
                        break

                    parent_depth = depth + 1
                    results.append((parent_id, parent_depth))
                    queue.append((parent_id, parent_depth))

        if budget_truncated:
            break

    return results


__all__ = [
    "get_descendants",
    "get_ancestors",
    "LineageResult",
]
