import sys
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.lineage import get_ancestors, get_descendants
from backend.app.memory.provenance import (
    create_provenance_edge,
    InvalidProvenanceError,
    TraversalBudget,
)
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.models import MemoryRecord, ProvenanceEdge
import backend.app.main as main_app


@pytest.fixture
def repo():
    return InMemoryMemoryRepository()


def test_openapi_schema_forbids_forensic_and_quarantined_params():
    """Verify that no OpenAPI route accepts for_forensic or allow_quarantined."""
    openapi = main_app.app.openapi()
    paths = openapi.get("paths", {})
    for path, methods in paths.items():
        for method, spec in methods.items():
            parameters = spec.get("parameters", [])
            param_names = [p.get("name") for p in parameters]
            assert "for_forensic" not in param_names, f"Exposed for_forensic on {method.upper()} {path}"
            assert "allow_quarantined" not in param_names, f"Exposed allow_quarantined on {method.upper()} {path}"

            # Check request body schema if any
            req_body = spec.get("requestBody", {})
            content = req_body.get("content", {})
            json_schema = content.get("application/json", {}).get("schema", {})
            properties = json_schema.get("properties", {})
            assert "for_forensic" not in properties, f"Exposed for_forensic in body on {method.upper()} {path}"
            assert "allow_quarantined" not in properties, f"Exposed allow_quarantined in body on {method.upper()} {path}"


def test_traversal_deep_chain(repo):
    """Deep chain traversal respects max_depth and reports complete=False with 'depth' when truncated."""
    tenant_id = "tenant-gap5"
    prev, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)
    root_id = prev.id

    for i in range(1, 5):
        prev, _ = ingest_memory(tenant_id=tenant_id, content=f"Node {i}", parent_record_id=prev.id, repository=repo)

    # Walk with max_depth=2
    res = get_descendants(tenant_id=tenant_id, record_id=root_id, max_depth=2, repository=repo)
    assert len(res) == 2
    assert res.complete is False
    assert res.truncated_reason == "depth"


def test_traversal_wide_fan_out(repo):
    """Wide fan-out traversal handles high edge count and bounds safely."""
    tenant_id = "tenant-gap5"
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)

    for i in range(15):
        ingest_memory(tenant_id=tenant_id, content=f"Child {i}", parent_record_id=root.id, repository=repo)

    res = get_descendants(tenant_id=tenant_id, record_id=root.id, max_depth=5, max_nodes=50, repository=repo)
    assert len(res) == 15
    assert res.complete is True
    assert res.truncated_reason is None


def test_traversal_shared_descendants_counted_once(repo):
    """Shared descendants (diamond graph: A -> B, A -> C, B -> D, C -> D) are visited and counted once."""
    tenant_id = "tenant-gap5"
    docA, _ = ingest_memory(tenant_id=tenant_id, content="A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="B", parent_record_id=docA.id, repository=repo)
    docC, _ = ingest_memory(tenant_id=tenant_id, content="C", parent_record_id=docA.id, repository=repo)
    docD, _ = ingest_memory(tenant_id=tenant_id, content="D", parent_record_id=docB.id, repository=repo)
    # Link C -> D as well
    create_provenance_edge(tenant_id=tenant_id, from_record_id=docC.id, to_record_id=docD.id, repository=repo)

    budget = TraversalBudget(max_nodes=50)
    res = get_descendants(tenant_id=tenant_id, record_id=docA.id, budget=budget, repository=repo)
    # B, C, D -> 3 unique descendants
    assert len(res) == 3
    assert set(res.record_ids()) == {docB.id, docC.id, docD.id}
    # Visited set in budget has A, B, C, D (4 unique nodes)
    assert len(budget.visited) == 4
    assert res.complete is True


def test_traversal_multiple_parents(repo):
    """Traversing ancestors in a multiple-parent graph visits all parents with shared budget."""
    tenant_id = "tenant-gap5"
    p1, _ = ingest_memory(tenant_id=tenant_id, content="Parent 1", repository=repo)
    p2, _ = ingest_memory(tenant_id=tenant_id, content="Parent 2", repository=repo)
    child, _ = ingest_memory(tenant_id=tenant_id, content="Child", parent_record_id=p1.id, repository=repo)
    create_provenance_edge(tenant_id=tenant_id, from_record_id=p2.id, to_record_id=child.id, repository=repo)

    res = get_ancestors(tenant_id=tenant_id, record_id=child.id, repository=repo)
    assert len(res) == 2
    assert set(res.record_ids()) == {p1.id, p2.id}
    assert res.complete is True


def test_traversal_cycle_rejection(repo):
    """Cycle in graph is detected and rejected."""
    tenant_id = "tenant-gap5"
    docA, _ = ingest_memory(tenant_id=tenant_id, content="A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="B", parent_record_id=docA.id, repository=repo)

    # Attempting to link B -> A creates cycle
    with pytest.raises(InvalidProvenanceError) as exc:
        create_provenance_edge(tenant_id=tenant_id, from_record_id=docB.id, to_record_id=docA.id, repository=repo)
    assert "cycle detected" in str(exc.value).lower()


def test_traversal_cross_tenant_edge_ignored(repo):
    """Cross-tenant edges in repository are strictly ignored by tenant filtering."""
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"
    root, _ = ingest_memory(tenant_id=tenant_a, content="Root A", repository=repo)
    child, _ = ingest_memory(tenant_id=tenant_a, content="Child A", parent_record_id=root.id, repository=repo)

    # Manually inject a rogue cross-tenant edge with tenant_b in repo._edges
    repo._edges["rogue-edge"] = ProvenanceEdge(
        id="rogue-edge",
        tenant_id=tenant_b,
        from_record_id=root.id,
        to_record_id="rogue-child",
        relation_type="DERIVED_FROM",
    )

    res = get_descendants(tenant_id=tenant_a, record_id=root.id, repository=repo)
    assert res.record_ids() == [child.id]
    assert "rogue-child" not in res.record_ids()


def test_traversal_duplicate_edges_deduplicated(repo):
    """Duplicate provenance edges are deduplicated and do not consume multiple budget visits."""
    tenant_id = "tenant-gap5"
    docA, _ = ingest_memory(tenant_id=tenant_id, content="A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="B", parent_record_id=docA.id, repository=repo)

    # Re-call create_provenance_edge with identical parameters -> deduplicated
    create_provenance_edge(tenant_id=tenant_id, from_record_id=docA.id, to_record_id=docB.id, repository=repo)
    edges = repo.get_edges_for_record(docA.id, tenant_id)
    outgoing = [e for e in edges if e.from_record_id == docA.id]
    assert len(outgoing) == 1


def test_traversal_node_budget_exhaustion(repo):
    """Traversing past max_nodes terminates gracefully with complete=False and truncated_reason='nodes'."""
    tenant_id = "tenant-gap5"
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)
    for i in range(10):
        ingest_memory(tenant_id=tenant_id, content=f"Child {i}", parent_record_id=root.id, repository=repo)

    # Set max_nodes=5 (including root, will stop after 4 children)
    res = get_descendants(tenant_id=tenant_id, record_id=root.id, max_nodes=5, repository=repo)
    assert len(res) == 4
    assert res.complete is False
    assert res.truncated_reason == "nodes"


def test_traversal_edge_budget_exhaustion(repo):
    """Traversing past max_edges terminates with complete=False and truncated_reason='edges'."""
    tenant_id = "tenant-gap5"
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)
    for i in range(10):
        ingest_memory(tenant_id=tenant_id, content=f"Child {i}", parent_record_id=root.id, repository=repo)

    # Set max_edges=3
    res = get_descendants(tenant_id=tenant_id, record_id=root.id, max_edges=3, repository=repo)
    assert len(res) < 10
    assert res.complete is False
    assert res.truncated_reason == "edges"


def test_traversal_repo_call_budget_exhaustion(repo):
    """Traversing past max_repo_calls terminates with complete=False and truncated_reason='repo_calls'."""
    tenant_id = "tenant-gap5"
    # Chain: root -> n1 -> n2 -> n3
    n0, _ = ingest_memory(tenant_id=tenant_id, content="N0", repository=repo)
    n1, _ = ingest_memory(tenant_id=tenant_id, content="N1", parent_record_id=n0.id, repository=repo)
    n2, _ = ingest_memory(tenant_id=tenant_id, content="N2", parent_record_id=n1.id, repository=repo)
    n3, _ = ingest_memory(tenant_id=tenant_id, content="N3", parent_record_id=n2.id, repository=repo)

    # Set max_repo_calls=2 (can only query edges for n0 and n1)
    res = get_descendants(tenant_id=tenant_id, record_id=n0.id, max_repo_calls=2, repository=repo)
    assert res.complete is False
    assert res.truncated_reason == "repo_calls"


def test_traversal_deadline_exhaustion(repo):
    """Traversing past deadline terminates with complete=False and truncated_reason='deadline'."""
    tenant_id = "tenant-gap5"
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)
    for i in range(10):
        ingest_memory(tenant_id=tenant_id, content=f"Child {i}", parent_record_id=root.id, repository=repo)

    # Set deadline of 0.0 seconds (expired immediately)
    res = get_descendants(tenant_id=tenant_id, record_id=root.id, deadline_seconds=0.0, repository=repo)
    assert res.complete is False
    assert res.truncated_reason == "deadline"


def test_ingestion_rejected_when_cycle_check_incomplete(repo):
    """Fail closed on writes: if the ingestion cycle check cannot complete due to budget exhaustion, REJECT ingestion."""
    tenant_id = "tenant-gap5"
    root, _ = ingest_memory(tenant_id=tenant_id, content="Root", repository=repo)

    # Create 55 incoming parents to root in repo to exceed DEFAULT_MAX_NODES (50) during ancestry check
    import uuid
    for i in range(55):
        pid = f"parent-node-{i}"
        repo.create_record(MemoryRecord(id=pid, tenant_id=tenant_id, trust_state="UNVERIFIED"))
        repo.create_edge(
            ProvenanceEdge(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                from_record_id=pid,
                to_record_id=root.id,
            )
        )

    # Ingesting with parent_record_id=root.id triggers _check_dag_cycle which exhausts ancestry budget and fails closed
    with pytest.raises(InvalidProvenanceError) as exc:
        ingest_memory(
            tenant_id=tenant_id,
            content="Child attempting ingestion on saturated ancestry graph",
            parent_record_id=root.id,
            repository=repo,
        )
    assert "budget exceeded" in str(exc.value).lower()
