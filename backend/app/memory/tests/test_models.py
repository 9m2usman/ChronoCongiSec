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


# ============================================================================
# Security Hardening & Strict Validation Regression Tests (M3 Day 1)
# ============================================================================

def test_invalid_record_type_rejected():
    """Verify MemoryRecord rejects unrecognized record_type values."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        MemoryRecord(
            id="rec-inv-01",
            tenant_id="tenant-alpha",
            record_type="INVALID_TYPE",
        )


def test_invalid_trust_state_rejected():
    """Verify MemoryRecord rejects unrecognized trust_state values."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        MemoryRecord(
            id="rec-inv-02",
            tenant_id="tenant-alpha",
            trust_state="TRUSTED_BOGUS",
        )


def test_invalid_provenance_relation_type_rejected():
    """Verify ProvenanceEdge rejects unrecognized relation_type values."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProvenanceEdge(
            id="edge-inv-01",
            tenant_id="tenant-alpha",
            from_record_id="rec-001",
            to_record_id="rec-002",
            relation_type="INVALID_RELATION",
        )


def test_version_zero_and_negative_rejected_in_memory_version():
    """Verify MemoryVersion strictly requires version >= 1."""
    import pytest
    from pydantic import ValidationError

    valid_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-0",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=0,
            content="content",
            checksum=valid_checksum,
        )

    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-neg",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=-1,
            content="content",
            checksum=valid_checksum,
        )


def test_current_version_zero_and_negative_rejected_in_memory_record():
    """Verify MemoryRecord strictly requires current_version >= 1."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        MemoryRecord(
            id="rec-0",
            tenant_id="tenant-alpha",
            current_version=0,
        )

    with pytest.raises(ValidationError):
        MemoryRecord(
            id="rec-neg",
            tenant_id="tenant-alpha",
            current_version=-5,
        )


def test_invalid_checksum_length_rejected():
    """Verify MemoryVersion rejects SHA-256 checksums whose length is not exactly 64."""
    import pytest
    from pydantic import ValidationError

    # 63 characters (too short)
    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-short",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=1,
            content="content",
            checksum="a" * 63,
        )

    # 65 characters (too long)
    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-long",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=1,
            content="content",
            checksum="a" * 65,
        )


def test_invalid_checksum_characters_rejected():
    """Verify MemoryVersion rejects non-hexadecimal characters in checksum."""
    import pytest
    from pydantic import ValidationError

    # 'g' is not a hex character
    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-nonhex-g",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=1,
            content="content",
            checksum="g" * 64,
        )

    # non-hex symbol
    with pytest.raises(ValidationError):
        MemoryVersion(
            id="ver-nonhex-sym",
            tenant_id="tenant-alpha",
            record_id="rec-001",
            version=1,
            content="content",
            checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85!",
        )


def test_valid_uppercase_and_lowercase_checksums_accepted():
    """Verify valid 64-char uppercase and lowercase hex checksums are accepted without silent mutation."""
    lower_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    upper_checksum = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

    ver_lower = MemoryVersion(
        id="ver-lower",
        tenant_id="tenant-alpha",
        record_id="rec-001",
        version=1,
        content="content",
        checksum=lower_checksum,
    )
    assert ver_lower.checksum == lower_checksum

    ver_upper = MemoryVersion(
        id="ver-upper",
        tenant_id="tenant-alpha",
        record_id="rec-001",
        version=1,
        content="content",
        checksum=upper_checksum,
    )
    # Checksum must be preserved as supplied, not silently lowercased
    assert ver_upper.checksum == upper_checksum


def test_memory_ingest_request_invalid_record_type_rejected():
    """Verify MemoryIngestRequest rejects unrecognized record_type values at validation boundary."""
    import pytest
    from pydantic import ValidationError
    from backend.app.memory.models import MemoryIngestRequest

    with pytest.raises(ValidationError):
        MemoryIngestRequest(
            content="Valid test memory content",
            record_type="INVALID_RECORD_TYPE",
        )


def test_memory_record_response_invalid_checksum_rejected():
    """Verify MemoryRecordResponse rejects malformed SHA-256 checksum strings."""
    import pytest
    from pydantic import ValidationError
    from backend.app.memory.models import MemoryRecordResponse

    with pytest.raises(ValidationError):
        MemoryRecordResponse(
            id="rec-001",
            tenant_id="tenant-alpha",
            checksum="too-short-checksum",
        )
