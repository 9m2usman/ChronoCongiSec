"""Unit and integration tests for memory provenance lineage traversal (ancestors and descendants).

Tests Document 02 §15.2 (bounded graph depth <= 5) and blast radius discovery.
"""

import sys
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.lineage import (
    LineageResult,
    get_ancestors,
    get_descendants,
)
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.retrieval import MemoryNotFoundError


@pytest.fixture
def repo():
    """Isolated in-memory repository for test isolation."""
    return InMemoryMemoryRepository()


def test_descendants_include_grandchildren(repo):
    """get_descendants must traverse child and grandchild records with accurate depth."""
    tenant_id = "tenant-alpha"

    # Hierarchy:
    #   root -> child1 -> grandchild1
    #   root -> child2
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root strategy doc", repository=repo)
    child1, _ = ingest_memory(tenant_id=tenant_id, content="Child 1 memo", parent_record_id=root.id, repository=repo)
    child2, _ = ingest_memory(tenant_id=tenant_id, content="Child 2 memo", parent_record_id=root.id, repository=repo)
    grandchild1, _ = ingest_memory(tenant_id=tenant_id, content="Grandchild 1 extraction", parent_record_id=child1.id, repository=repo)

    descendants = get_descendants(tenant_id=tenant_id, record_id=root.id, max_depth=5, repository=repo)

    assert isinstance(descendants, LineageResult)
    # Check that root itself is not in descendants
    assert root.id not in descendants.record_ids()

    # Children at depth 1
    depth_map = descendants.as_dict()
    assert depth_map[child1.id] == 1
    assert depth_map[child2.id] == 1

    # Grandchild at depth 2
    assert depth_map[grandchild1.id] == 2

    # Contains check supports string ID or tuple
    assert grandchild1.id in descendants
    assert (grandchild1.id, 2) in descendants


def test_ancestors_include_grandparents(repo):
    """get_ancestors must traverse parent and grandparent records with accurate depth."""
    tenant_id = "tenant-alpha"

    docA, _ = ingest_memory(tenant_id=tenant_id, content="Grandparent A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="Parent B", parent_record_id=docA.id, repository=repo)
    docC, _ = ingest_memory(tenant_id=tenant_id, content="Child C", parent_record_id=docB.id, repository=repo)

    ancestors = get_ancestors(tenant_id=tenant_id, record_id=docC.id, max_depth=5, repository=repo)

    assert docC.id not in ancestors.record_ids()
    depth_map = ancestors.as_dict()
    assert depth_map[docB.id] == 1
    assert depth_map[docA.id] == 2


def test_depth_limit_respected(repo):
    """Traversals must strictly respect max_depth and cap at MAX_PROVENANCE_DEPTH (5)."""
    tenant_id = "tenant-alpha"

    # Build chain of 5 nodes within MAX_PROVENANCE_DEPTH (5): N0 -> N1 -> N2 -> N3 -> N4
    nodes = []
    prev, _ = ingest_memory(tenant_id=tenant_id, content="Node 0", repository=repo)
    nodes.append(prev)
    for i in range(1, 5):
        prev, _ = ingest_memory(tenant_id=tenant_id, content=f"Node {i}", parent_record_id=prev.id, repository=repo)
        nodes.append(prev)

    # 1. Query with max_depth = 1 -> only N1 (depth 1) returned
    desc_depth_1 = get_descendants(tenant_id=tenant_id, record_id=nodes[0].id, max_depth=1, repository=repo)
    assert len(desc_depth_1) == 1
    assert desc_depth_1.record_ids() == [nodes[1].id]

    # 2. Query with max_depth = 2 -> only N1 (depth 1) and N2 (depth 2) returned
    desc_depth_2 = get_descendants(tenant_id=tenant_id, record_id=nodes[0].id, max_depth=2, repository=repo)
    assert len(desc_depth_2) == 2
    assert desc_depth_2.record_ids() == [nodes[1].id, nodes[2].id]

    # 3. Query with max_depth = 5 -> all 4 descendants N1..N4 returned
    desc_depth_5 = get_descendants(tenant_id=tenant_id, record_id=nodes[0].id, max_depth=5, repository=repo)
    assert len(desc_depth_5) == 4
    assert desc_depth_5.record_ids() == [nodes[1].id, nodes[2].id, nodes[3].id, nodes[4].id]

    # 4. Requesting max_depth > 5 is bounded to 5
    desc_depth_bounded = get_descendants(tenant_id=tenant_id, record_id=nodes[0].id, max_depth=100, repository=repo)
    assert len(desc_depth_bounded) == 4

    # 5. Ancestor depth limit check
    anc_depth_2 = get_ancestors(tenant_id=tenant_id, record_id=nodes[4].id, max_depth=2, repository=repo)
    assert len(anc_depth_2) == 2
    assert anc_depth_2.record_ids() == [nodes[3].id, nodes[2].id]


def test_tenant_isolation_in_lineage(repo):
    """Lineage traversal across tenant boundaries must be rejected or isolated."""
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    docA, _ = ingest_memory(tenant_id=tenant_a, content="Tenant A secret doc", repository=repo)

    # Tenant B attempting to query ancestors or descendants of Tenant A's record gets 404
    with pytest.raises(MemoryNotFoundError):
        get_descendants(tenant_id=tenant_b, record_id=docA.id, repository=repo)

    with pytest.raises(MemoryNotFoundError):
        get_ancestors(tenant_id=tenant_b, record_id=docA.id, repository=repo)
