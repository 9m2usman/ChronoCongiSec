"""Unit and integration tests for memory provenance edge creation and graph validation.

Tests Document 02 §15.2 and Document 05 Table 14 specifications.
"""

import sys
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.core.exceptions import ValidationError
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.models import ProvenanceRelationType
from backend.app.memory.provenance import (
    InvalidProvenanceError,
    create_provenance_edge,
)
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.retrieval import MemoryNotFoundError


@pytest.fixture
def repo():
    """Isolated in-memory repository for test isolation."""
    return InMemoryMemoryRepository()


def test_child_links_to_parent(repo):
    """Child record must link to parent record with specified relation type."""
    tenant_id = "tenant-alpha"
    parent, _ = ingest_memory(tenant_id=tenant_id, content="Parent document.", repository=repo)
    child, _ = ingest_memory(tenant_id=tenant_id, content="Child extraction.", repository=repo)

    edge = create_provenance_edge(
        tenant_id=tenant_id,
        from_record_id=parent.id,
        to_record_id=child.id,
        relation_type="DERIVED_FROM",
        repository=repo,
    )

    assert edge.from_record_id == parent.id
    assert edge.to_record_id == child.id
    assert edge.relation_type == "DERIVED_FROM"
    assert edge.tenant_id == tenant_id

    # Verify edge is stored and retrieved in repo
    edges = repo.get_edges_for_record(child.id, tenant_id)
    assert len(edges) == 1
    assert edges[0].id == edge.id

    # Also test TRANSFORMED_INTO and SUPERSEDES relation types
    child2, _ = ingest_memory(tenant_id=tenant_id, content="Transformed document.", repository=repo)
    edge_trans = create_provenance_edge(
        tenant_id=tenant_id,
        from_record_id=child.id,
        to_record_id=child2.id,
        relation_type=ProvenanceRelationType.TRANSFORMED_INTO,
        repository=repo,
    )
    assert edge_trans.relation_type == "TRANSFORMED_INTO"


def test_cycle_rejected(repo):
    """Attempting to create an edge forming a cycle (A->B->C then C->A) must be rejected."""
    tenant_id = "tenant-alpha"
    docA, _ = ingest_memory(tenant_id=tenant_id, content="Document A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_id, content="Document B", repository=repo)
    docC, _ = ingest_memory(tenant_id=tenant_id, content="Document C", repository=repo)

    create_provenance_edge(tenant_id, docA.id, docB.id, "DERIVED_FROM", repository=repo)
    create_provenance_edge(tenant_id, docB.id, docC.id, "DERIVED_FROM", repository=repo)

    # Attempting to link C -> A creates cycle A -> B -> C -> A
    with pytest.raises(InvalidProvenanceError) as exc_info:
        create_provenance_edge(tenant_id, docC.id, docA.id, "DERIVED_FROM", repository=repo)

    assert "cycle detected" in str(exc_info.value).lower()


def test_self_loop_rejected(repo):
    """A record attempting to link to itself must be rejected immediately."""
    tenant_id = "tenant-alpha"
    doc, _ = ingest_memory(tenant_id=tenant_id, content="Single document", repository=repo)

    with pytest.raises(InvalidProvenanceError) as exc_info:
        create_provenance_edge(tenant_id, doc.id, doc.id, "DERIVED_FROM", repository=repo)

    assert "Self-referential" in str(exc_info.value) or "cannot link to itself" in str(exc_info.value)


def test_cross_tenant_edge_rejected(repo):
    """Creating an edge across different tenants must fail with authorization/not found error."""
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"

    docA, _ = ingest_memory(tenant_id=tenant_a, content="Doc in tenant A", repository=repo)
    docB, _ = ingest_memory(tenant_id=tenant_b, content="Doc in tenant B", repository=repo)

    # Attempting to link docA -> docB in tenant_a (docB does not exist in tenant_a)
    with pytest.raises((InvalidProvenanceError, MemoryNotFoundError)):
        create_provenance_edge(tenant_a, docA.id, docB.id, "DERIVED_FROM", repository=repo)

    # Attempting to link docA -> docB in tenant_b (docA does not exist in tenant_b)
    with pytest.raises((InvalidProvenanceError, MemoryNotFoundError)):
        create_provenance_edge(tenant_b, docA.id, docB.id, "DERIVED_FROM", repository=repo)


def test_duplicate_not_duplicated(repo):
    """Calling create_provenance_edge twice with identical parameters must return the existing edge without duplication."""
    tenant_id = "tenant-alpha"
    parent, _ = ingest_memory(tenant_id=tenant_id, content="Source memo.", repository=repo)
    child, _ = ingest_memory(tenant_id=tenant_id, content="Derived insight.", repository=repo)

    edge1 = create_provenance_edge(tenant_id, parent.id, child.id, "DERIVED_FROM", repository=repo)
    edge2 = create_provenance_edge(tenant_id, parent.id, child.id, "DERIVED_FROM", repository=repo)

    assert edge1.id == edge2.id

    # Verify only one edge exists in storage
    edges = repo.get_edges_for_record(child.id, tenant_id)
    assert len(edges) == 1


def test_invalid_relation_type_rejected(repo):
    """Invalid relation types not in {DERIVED_FROM, TRANSFORMED_INTO, SUPERSEDES} must be rejected."""
    tenant_id = "tenant-alpha"
    parent, _ = ingest_memory(tenant_id=tenant_id, content="Doc 1", repository=repo)
    child, _ = ingest_memory(tenant_id=tenant_id, content="Doc 2", repository=repo)

    with pytest.raises((ValidationError, InvalidProvenanceError)):
        create_provenance_edge(tenant_id, parent.id, child.id, "INVALID_RELATION", repository=repo)
