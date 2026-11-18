"""Provenance tracking and graph edge management.

Module: backend.app.memory.provenance
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 and Document 05 Table 14 (provenance_edges).
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional, Set, Tuple, Union

from backend.app.core.exceptions import AMSCException, ValidationError
from .models import ProvenanceEdge, ProvenanceRelationType
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError

# Bounded graph governance limits (Document 02 Section 15.2 & TRD Performance Requirements)
MAX_PROVENANCE_DEPTH = 5
MAX_TRAVERSAL_BUDGET = 50  # Max nodes visited in traversal

DEFAULT_MAX_NODES = 50
DEFAULT_MAX_EDGES = 100
DEFAULT_MAX_REPO_CALLS = 50
DEFAULT_MAX_DEADLINE_SECONDS = 5.0

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


class TraversalBudgetExceededError(AMSCException):
    """Raised when a traversal budget limit is hit during write validation."""

    def __init__(self, reason: str, details: Any = None):
        super().__init__(
            message=f"Provenance traversal budget exceeded: {reason}.",
            code="TRAVERSAL_BUDGET_EXCEEDED",
            status_code=400,
            details=details,
        )
        self.reason = reason


class TraversalBudget:
    """Unified traversal budget manager with a single shared visited set and shared counters."""

    def __init__(
        self,
        max_depth: int = MAX_PROVENANCE_DEPTH,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
        max_repo_calls: int = DEFAULT_MAX_REPO_CALLS,
        deadline_seconds: Optional[float] = DEFAULT_MAX_DEADLINE_SECONDS,
    ):
        self.max_depth = min(max_depth, MAX_PROVENANCE_DEPTH) if max_depth is not None else MAX_PROVENANCE_DEPTH
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.max_repo_calls = max_repo_calls
        self.start_time = time.monotonic()
        self.deadline_seconds = deadline_seconds

        self.visited: Set[str] = set()
        self.edge_count: int = 0
        self.repo_call_count: int = 0

    def check_deadline(self) -> None:
        if self.deadline_seconds is not None:
            if (time.monotonic() - self.start_time) > self.deadline_seconds:
                raise TraversalBudgetExceededError("deadline")

    def record_visit(self, node_id: str) -> None:
        self.check_deadline()
        if len(self.visited) >= self.max_nodes and node_id not in self.visited:
            raise TraversalBudgetExceededError("nodes")
        self.visited.add(node_id)

    def record_edge(self) -> None:
        self.check_deadline()
        self.edge_count += 1
        if self.edge_count > self.max_edges:
            raise TraversalBudgetExceededError("edges")

    def record_repo_call(self) -> None:
        self.check_deadline()
        self.repo_call_count += 1
        if self.repo_call_count > self.max_repo_calls:
            raise TraversalBudgetExceededError("repo_calls")


def _get_lineage_depth(
    repo: MemoryRepository,
    record_id: str,
    tenant_id: str,
    budget: Optional[TraversalBudget] = None,
    current_depth: int = 1,
) -> int:
    """Calculate the maximum upstream lineage depth leading into record_id within tenant scope.

    Uses a single shared TraversalBudget (no set(visited) branch copying).
    Fails closed if any budget is exceeded.
    """
    if budget is None:
        budget = TraversalBudget(
            max_depth=MAX_PROVENANCE_DEPTH,
            max_nodes=DEFAULT_MAX_NODES,
            max_edges=DEFAULT_MAX_EDGES,
            max_repo_calls=DEFAULT_MAX_REPO_CALLS,
        )

    if record_id in budget.visited:
        raise InvalidProvenanceError(f"Provenance cycle detected in ancestry for record '{record_id}'.")

    if current_depth > budget.max_depth:
        raise InvalidProvenanceError(
            f"Provenance lineage depth limit exceeded: lineage depth exceeds maximum of {budget.max_depth}."
        )

    try:
        budget.record_visit(record_id)
    except TraversalBudgetExceededError as e:
        raise InvalidProvenanceError(
            f"Provenance traversal node budget exceeded: maximum allowable traversal budget is {budget.max_nodes} nodes."
        ) from e

    try:
        budget.record_repo_call()
    except TraversalBudgetExceededError as e:
        raise InvalidProvenanceError(f"Provenance traversal repo call budget exceeded: {e.reason}.") from e

    edges = repo.get_edges_for_record(record_id, tenant_id)
    incoming_parents = []
    for edge in edges:
        if edge.to_record_id == record_id and edge.tenant_id == tenant_id:
            try:
                budget.record_edge()
            except TraversalBudgetExceededError as e:
                raise InvalidProvenanceError(f"Provenance traversal edge budget exceeded: {e.reason}.") from e
            incoming_parents.append(edge.from_record_id)

    if not incoming_parents:
        return current_depth

    max_ancestor_depth = current_depth
    for parent_id in incoming_parents:
        d = _get_lineage_depth(repo, parent_id, tenant_id, budget, current_depth + 1)
        if d > max_ancestor_depth:
            max_ancestor_depth = d
    return max_ancestor_depth


def _check_dag_cycle(
    repo: MemoryRepository,
    from_id: str,
    to_id: str,
    tenant_id: str,
    budget: Optional[TraversalBudget] = None,
) -> None:
    """Verify that adding an edge from_id -> to_id does not create a cycle or exceed depth/budget limits.

    Uses a single shared TraversalBudget across ancestry and downstream cycle checks.
    Fails closed on any budget exhaustion.
    """
    if from_id == to_id:
        raise InvalidProvenanceError(
            f"Self-referential provenance edge prohibited: record '{from_id}' cannot derive from itself."
        )

    if budget is None:
        budget = TraversalBudget(
            max_depth=MAX_PROVENANCE_DEPTH,
            max_nodes=DEFAULT_MAX_NODES,
            max_edges=DEFAULT_MAX_EDGES,
            max_repo_calls=DEFAULT_MAX_REPO_CALLS,
        )

    # 1. Check upstream ancestry depth of parent
    parent_depth = _get_lineage_depth(repo, from_id, tenant_id, budget)
    if parent_depth + 1 > budget.max_depth:
        raise InvalidProvenanceError(
            f"Provenance lineage depth limit exceeded: maximum allowable lineage depth is {budget.max_depth}."
        )

    # 2. Downstream search: check if from_id is reachable from to_id (cycle detection)
    downstream_budget = TraversalBudget(
        max_depth=budget.max_depth,
        max_nodes=budget.max_nodes,
        max_edges=budget.max_edges,
        max_repo_calls=budget.max_repo_calls,
        deadline_seconds=budget.deadline_seconds,
    )
    queue: List[Tuple[str, int]] = [(to_id, 1)]

    while queue:
        current, depth = queue.pop(0)
        if current == from_id:
            raise InvalidProvenanceError(
                f"Provenance cycle detected: adding edge from '{from_id}' to '{to_id}' creates a cyclic lineage."
            )
        if depth > downstream_budget.max_depth:
            raise InvalidProvenanceError(
                f"Provenance traversal depth limit exceeded: maximum allowable lineage depth is {downstream_budget.max_depth}."
            )
        if current in downstream_budget.visited:
            continue

        try:
            downstream_budget.record_visit(current)
        except TraversalBudgetExceededError as e:
            raise InvalidProvenanceError(
                f"Provenance traversal node budget exceeded: maximum allowable traversal budget is {downstream_budget.max_nodes} nodes."
            ) from e

        try:
            downstream_budget.record_repo_call()
        except TraversalBudgetExceededError as e:
            raise InvalidProvenanceError(f"Provenance traversal repo call budget exceeded: {e.reason}.") from e

        edges = repo.get_edges_for_record(current, tenant_id)
        for edge in edges:
            if edge.from_record_id == current and edge.tenant_id == tenant_id:
                try:
                    downstream_budget.record_edge()
                except TraversalBudgetExceededError as e:
                    raise InvalidProvenanceError(f"Provenance traversal edge budget exceeded: {e.reason}.") from e

                if edge.to_record_id not in downstream_budget.visited:
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
    6. Bounded Depth & Budgets: Rejects lineage exceeding depth or traversal budgets.
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
    "TraversalBudgetExceededError",
    "TraversalBudget",
    "MAX_PROVENANCE_DEPTH",
    "MAX_TRAVERSAL_BUDGET",
    "DEFAULT_MAX_NODES",
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_REPO_CALLS",
    "DEFAULT_MAX_DEADLINE_SECONDS",
    "VALID_RELATION_TYPES",
    "_check_dag_cycle",
    "_get_lineage_depth",
]
