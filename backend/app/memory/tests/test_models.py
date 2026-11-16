"""Tests for MemoryRecord, MemoryVersion, and ProvenanceEdge Pydantic models."""

import sys
from datetime import datetime
from pathlib import Path

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from backend.app.memory.models import (
        MemoryRecord,
        MemoryVersion,
        ProvenanceEdge,
        ProvenanceRelationType,
        RecordType,
        TrustState,
    )
except ModuleNotFoundError:
    from ..models import (
        MemoryRecord,
        MemoryVersion,
        ProvenanceEdge,
        ProvenanceRelationType,
        RecordType,
        TrustState,
    )


def test_memory_record_fields_and_defaults():
    """Verify MemoryRecord fields match Document 05 Table 11."""
    record = MemoryRecord(
        id="rec-001",
        tenant_id="tenant-alpha",
    )
    assert record.id == "rec-001"
    assert record.tenant_id == "tenant-alpha"
    assert record.agent_id is None
    assert record.source_id is None
    assert record.record_type == "KNOWLEDGE"
    assert record.trust_state == "UNVERIFIED"
    assert record.current_version == 1
    assert isinstance(record.created_at, datetime)
    assert isinstance(record.updated_at, datetime)


def test_memory_record_custom_values():
    """Verify MemoryRecord accepts custom valid values."""
    record = MemoryRecord(
        id="rec-002",
        tenant_id="tenant-beta",
        agent_id="agent-777",
        source_id="src-doc-12",
        record_type=RecordType.CONVERSATION,
        trust_state=TrustState.SUSPICIOUS,
        current_version=3,
    )
    assert record.agent_id == "agent-777"
    assert record.source_id == "src-doc-12"
    assert record.record_type == "CONVERSATION"
    assert record.trust_state == "SUSPICIOUS"
    assert record.current_version == 3


def test_memory_version_fields():
    """Verify MemoryVersion fields match Document 05 Table 12."""
    version = MemoryVersion(
        id="ver-001",
        tenant_id="tenant-alpha",
        record_id="rec-001",
        version=1,
        content="Baseline treasury operating procedure.",
        checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert version.id == "ver-001"
    assert version.tenant_id == "tenant-alpha"
    assert version.record_id == "rec-001"
    assert version.version == 1
    assert version.content == "Baseline treasury operating procedure."
    assert len(version.checksum) == 64
    assert isinstance(version.created_at, datetime)


def test_provenance_edge_fields_and_defaults():
    """Verify ProvenanceEdge fields match Document 05 Table 14."""
    edge = ProvenanceEdge(
        id="edge-001",
        tenant_id="tenant-alpha",
        from_record_id="rec-parent-001",
        to_record_id="rec-child-002",
    )
    assert edge.id == "edge-001"
    assert edge.tenant_id == "tenant-alpha"
    assert edge.from_record_id == "rec-parent-001"
    assert edge.to_record_id == "rec-child-002"
    assert edge.relation_type == "DERIVED_FROM"
    assert isinstance(edge.created_at, datetime)


def test_provenance_edge_custom_relation():
    """Verify ProvenanceEdge accepts relations such as TRANSFORMED_INTO and SUPERSEDES."""
    edge = ProvenanceEdge(
        id="edge-002",
        tenant_id="tenant-alpha",
        from_record_id="rec-old-001",
        to_record_id="rec-new-002",
        relation_type=ProvenanceRelationType.SUPERSEDES,
    )
    assert edge.relation_type == "SUPERSEDES"
