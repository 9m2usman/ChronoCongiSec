"""Tests for Knowledge Graph topological projection and bounding (Day 6).

Module: backend.app.knowledge.tests.test_knowledge_graph
Owner: M3 — Knowledge & Memory Systems Lead
"""

from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.api.knowledge import router as knowledge_router
from backend.app.api.memory import get_repository
from backend.app.core.config import get_settings
from backend.app.core.exceptions import ValidationError
from backend.app.core.security import create_access_token
from backend.app.knowledge.knowledge_graph import build_graph
from backend.app.main import create_app
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.models import AgentRecord, ProvenanceEdge, ProvenanceRelationType, SourceRecord
from backend.app.memory.repository import InMemoryMemoryRepository


@pytest.fixture
def repo():
    return InMemoryMemoryRepository()


@pytest.fixture
def test_client(repo):
    settings = get_settings()
    app = create_app(settings)
    app.state.memory_repo = repo
    app.dependency_overrides[get_repository] = lambda: repo
    app.include_router(knowledge_router, prefix="/api/v1")
    return TestClient(app), repo


def _make_auth_header(
    tenant_id: str = "tenant-a-uuid-001",
    user_id: str = "user-a-analyst-001",
    role: str = "SECURITY_ANALYST",
) -> dict:
    settings = get_settings()
    token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        settings=settings,
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": tenant_id,
    }


@pytest.mark.asyncio
async def test_build_graph_basic_nodes_and_edges(repo):
    """build_graph projects records and provenance edges without content."""
    tenant_id = "tenant-a-uuid-001"
    await repo.create_agent(AgentRecord(id="agent-001", tenant_id=tenant_id, name="Bot", status="ACTIVE"))
    await repo.create_source(SourceRecord(id="src-doc-001", tenant_id=tenant_id, name="Doc", source_type="DOC", status="ACTIVE"))

    r1, _ = await ingest_memory(
        tenant_id=tenant_id,
        content="Parent document content chunk 1",
        agent_id="agent-001",
        source_id="src-doc-001",
        repository=repo,
    )
    r2, _ = await ingest_memory(
        tenant_id=tenant_id,
        content="Child document derived chunk 2",
        agent_id="agent-001",
        source_id="src-doc-001",
        parent_record_id=r1.id,
        repository=repo,
    )

    graph_res = await build_graph(tenant_id=tenant_id, max_depth=3, repository=repo)

    assert graph_res.complete is True
    assert graph_res.truncated_reason is None
    assert len(graph_res.nodes) == 2
    assert len(graph_res.edges) == 1

    node_ids = {n.id for n in graph_res.nodes}
    assert r1.id in node_ids
    assert r2.id in node_ids

    # Critical security assertion: NO content field exists in nodes or edges
    for node in graph_res.nodes:
        assert not hasattr(node, "content")
        node_dict = node.model_dump()
        assert "content" not in node_dict

    edge = graph_res.edges[0]
    assert edge.from_record_id == r1.id
    assert edge.to_record_id == r2.id
    assert edge.relation_type == ProvenanceRelationType.DERIVED_FROM.value


@pytest.mark.asyncio
async def test_build_graph_strict_tenant_isolation(repo):
    """Records and edges from other tenants must NEVER appear in the graph."""
    tenant_a = "tenant-a-uuid-001"
    tenant_b = "tenant-b-uuid-002"

    await repo.create_agent(AgentRecord(id="agent-b", tenant_id=tenant_b, name="Bot B", status="ACTIVE"))
    await repo.create_source(SourceRecord(id="src-b", tenant_id=tenant_b, name="Source B", source_type="DOC", status="ACTIVE"))

    rec_a, _ = await ingest_memory(
        tenant_id=tenant_a,
        content="Tenant A knowledge",
        agent_id="agent-001",
        source_id="src-doc-001",
        repository=repo,
    )
    rec_b, _ = await ingest_memory(
        tenant_id=tenant_b,
        content="Tenant B confidential knowledge",
        agent_id="agent-b",
        source_id="src-b",
        repository=repo,
    )

    graph_a = await build_graph(tenant_id=tenant_a, max_depth=3, repository=repo)
    node_ids_a = {n.id for n in graph_a.nodes}

    assert rec_a.id in node_ids_a
    assert rec_b.id not in node_ids_a


@pytest.mark.asyncio
async def test_build_graph_invalid_max_depth_rejected(repo):
    """max_depth outside 1..5 is rejected with ValidationError."""
    tenant_id = "tenant-a-uuid-001"
    with pytest.raises(ValidationError):
        await build_graph(tenant_id=tenant_id, max_depth=0, repository=repo)

    with pytest.raises(ValidationError):
        await build_graph(tenant_id=tenant_id, max_depth=6, repository=repo)

    with pytest.raises(ValidationError):
        await build_graph(tenant_id=tenant_id, max_depth="invalid", repository=repo)


@pytest.mark.asyncio
async def test_build_graph_truncation_flagged_on_budget_exhaustion(repo):
    """When a budget limit is hit during traversal, complete=False and truncated_reason is set."""
    tenant_id = "tenant-a-uuid-001"

    # Ingest several independent records and shallow fan-out
    for i in range(10):
        await ingest_memory(
            tenant_id=tenant_id,
            content=f"Knowledge chunk {i}",
            agent_id="agent-001",
            source_id="src-doc-001",
            repository=repo,
        )

    # Monkeypatch TraversalBudget inside knowledge_graph to simulate node exhaustion
    from backend.app.knowledge import knowledge_graph

    orig_budget_cls = knowledge_graph.TraversalBudget

    class TinyBudget(orig_budget_cls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.max_nodes = 3

    knowledge_graph.TraversalBudget = TinyBudget
    try:
        res = await build_graph(tenant_id=tenant_id, max_depth=3, repository=repo)
        assert res.complete is False
        assert "nodes" in (res.truncated_reason or "")
        assert len(res.nodes) <= 3
    finally:
        knowledge_graph.TraversalBudget = orig_budget_cls


@pytest.mark.asyncio
async def test_build_graph_edges_only_included_if_both_nodes_present(repo):
    """An edge where one endpoint was pruned or excluded must not be returned."""
    tenant_id = "tenant-a-uuid-001"
    r1, _ = await ingest_memory(
        tenant_id=tenant_id,
        content="Chunk 1",
        agent_id="agent-001",
        source_id="src-doc-001",
        repository=repo,
    )
    r2, _ = await ingest_memory(
        tenant_id=tenant_id,
        content="Chunk 2",
        agent_id="agent-001",
        source_id="src-doc-001",
        parent_record_id=r1.id,
        repository=repo,
    )

    # Add a dangling edge pointing to a nonexistent record ID
    dangling_edge = ProvenanceEdge(
        id="edge-dangling-001",
        tenant_id=tenant_id,
        from_record_id=r1.id,
        to_record_id="nonexistent-record-id",
        relation_type=ProvenanceRelationType.DERIVED_FROM.value,
    )
    await repo.create_edge(dangling_edge)

    graph_res = await build_graph(tenant_id=tenant_id, max_depth=3, repository=repo)

    edge_ids = {e.id for e in graph_res.edges}
    assert "edge-dangling-001" not in edge_ids


@pytest.mark.asyncio
async def test_api_knowledge_graph_endpoint(test_client):
    """GET /api/v1/knowledge/graph returns topological projection."""
    client, repo = test_client
    tenant_id = "tenant-a-uuid-001"
    headers = _make_auth_header(tenant_id=tenant_id)

    r1, _ = await ingest_memory(
        tenant_id=tenant_id,
        content="Graph node test 1",
        agent_id="agent-001",
        source_id="src-doc-001",
        repository=repo,
    )

    resp = client.get("/api/v1/knowledge/graph?max_depth=3", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["complete"] is True
    assert len(data["nodes"]) >= 1
    assert data["nodes"][0]["id"] == r1.id
    assert "content" not in data["nodes"][0]
