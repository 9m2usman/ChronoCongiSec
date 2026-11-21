"""Knowledge graph projection and bounded topological traversal.

Module: backend.app.knowledge.knowledge_graph
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15 & §22 and Document 05 §3.6 specifications.
"""

from collections import deque
from datetime import datetime
import logging
from typing import Dict, List, Optional, Set, Tuple

from backend.app.core.exceptions import ValidationError
from backend.app.memory.models import (
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeGraphResponse,
    MemoryRecord,
    ProvenanceEdge,
)
from backend.app.memory.provenance import (
    TraversalBudget,
    TraversalBudgetExceededError,
)
from backend.app.memory.repository import MemoryRepository, get_default_repository

logger = logging.getLogger("amsc.knowledge.knowledge_graph")


async def build_graph(
    tenant_id: str,
    max_depth: int = 3,
    repository: Optional[MemoryRepository] = None,
) -> KnowledgeGraphResponse:
    """Build a bounded topological knowledge and provenance graph for a tenant.

    Rules & Invariants:
    1. Nodes are the tenant's memory records (id, record_type, trust_state, current_version, agent_id).
       CRITICAL: NO content field is included anywhere in the node or edge projection.
    2. Edges are provenance edges (id, from_record_id, to_record_id, relation_type).
       Edge direction is returned exactly as stored without team-undecided semantic reversal.
    3. Strict tenant filtering is enforced at every node and edge traversal step.
    4. max_depth is strictly validated between 1 and 5 (inclusive).
    5. Utilizes shared TraversalBudget from provenance.py (nodes, edges, repo calls, deadline).
    6. Traversal is seeded with the tenant's most recently updated memory records.
    7. Result carries complete (bool) and truncated_reason; never presents a truncated graph as complete.
    8. Only edges where both endpoints (from_record_id and to_record_id) are present in the
       included nodes list are returned.
    """
    if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 5:
        raise ValidationError("max_depth must be an integer between 1 and 5.")

    repo = repository or get_default_repository()
    budget = TraversalBudget(max_depth=max_depth)

    complete = True
    truncated_reason: Optional[str] = None

    # Step 1: Seed with the tenant's most recently updated records
    try:
        budget.record_repo_call()
        all_records = await repo.list_records(
            tenant_id=tenant_id,
            only_trusted=False,
            limit=10000,
            offset=0,
        )
    except TraversalBudgetExceededError as e:
        return KnowledgeGraphResponse(
            nodes=[],
            edges=[],
            complete=False,
            truncated_reason=f"Traversal budget exceeded: {e.reason}",
        )

    def _rec_sort_key(r: MemoryRecord):
        dt = r.updated_at or r.created_at
        if isinstance(dt, datetime):
            return dt.timestamp()
        if isinstance(dt, (int, float)):
            return float(dt)
        return 0.0

    # Sort descending by updated_at / created_at to prioritize recent memory
    sorted_seeds = sorted(all_records, key=_rec_sort_key, reverse=True)

    included_nodes_map: Dict[str, MemoryRecord] = {}
    collected_edges_map: Dict[str, ProvenanceEdge] = {}

    # BFS queue holding (record_id, current_depth)
    queue: deque[Tuple[str, int]] = deque()
    for seed in sorted_seeds:
        queue.append((seed.id, 1))

    # Step 2: Bounded BFS expansion
    while queue:
        rec_id, depth = queue.popleft()
        if rec_id in included_nodes_map:
            continue

        try:
            budget.record_visit(rec_id)
        except TraversalBudgetExceededError as e:
            complete = False
            truncated_reason = f"Traversal budget exceeded: {e.reason}"
            break

        # Look up record object
        try:
            budget.record_repo_call()
            rec = await repo.get_record(rec_id, tenant_id)
        except TraversalBudgetExceededError as e:
            complete = False
            truncated_reason = f"Traversal budget exceeded: {e.reason}"
            break

        if not rec or rec.tenant_id != tenant_id:
            continue

        included_nodes_map[rec_id] = rec

        if depth >= max_depth:
            continue

        # Fetch adjacent edges for this record
        try:
            budget.record_repo_call()
            record_edges = await repo.get_edges_for_record(rec_id, tenant_id)
        except TraversalBudgetExceededError as e:
            complete = False
            truncated_reason = f"Traversal budget exceeded: {e.reason}"
            break

        for edge in record_edges:
            # Strict tenant scoping on edges
            if edge.tenant_id != tenant_id:
                continue

            try:
                budget.record_edge()
            except TraversalBudgetExceededError as e:
                complete = False
                truncated_reason = f"Traversal budget exceeded: {e.reason}"
                break

            collected_edges_map[edge.id] = edge

            # Expand both upstream and downstream neighbors if within budget
            neighbors = []
            if edge.from_record_id == rec_id and edge.to_record_id not in included_nodes_map:
                neighbors.append(edge.to_record_id)
            elif edge.to_record_id == rec_id and edge.from_record_id not in included_nodes_map:
                neighbors.append(edge.from_record_id)

            for neighbor_id in neighbors:
                queue.append((neighbor_id, depth + 1))

        if not complete:
            break

    # Step 3: Format projected nodes (NO content)
    nodes: List[KnowledgeGraphNode] = [
        KnowledgeGraphNode(
            id=rec.id,
            record_type=rec.record_type,
            trust_state=rec.trust_state,
            current_version=rec.current_version,
            agent_id=rec.agent_id,
        )
        for rec in included_nodes_map.values()
    ]

    # Step 4: Include only edges whose both ends are included nodes
    included_ids: Set[str] = set(included_nodes_map.keys())
    final_edges: List[KnowledgeGraphEdge] = []

    for edge in collected_edges_map.values():
        if edge.tenant_id == tenant_id:
            if edge.from_record_id in included_ids and edge.to_record_id in included_ids:
                final_edges.append(
                    KnowledgeGraphEdge(
                        id=edge.id,
                        from_record_id=edge.from_record_id,
                        to_record_id=edge.to_record_id,
                        relation_type=edge.relation_type,
                    )
                )

    return KnowledgeGraphResponse(
        nodes=nodes,
        edges=final_edges,
        complete=complete,
        truncated_reason=truncated_reason,
    )


__all__ = [
    "build_graph",
]
