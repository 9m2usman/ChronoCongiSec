"""Pydantic models for MemoryRecord, MemoryVersion, and ProvenanceEdge.

Matches database schema in Document 05 (Section 3.3 Knowledge, Memory & Provenance) exactly.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RecordType(str, Enum):
    """Memory record types as defined in Document 05 Table 11."""
    KNOWLEDGE = "KNOWLEDGE"
    CONVERSATION = "CONVERSATION"
    SCRATCHPAD = "SCRATCHPAD"


class TrustState(str, Enum):
    """Dynamic memory trust states as defined in Document 02 §15.3 and Document 05 Table 11."""
    UNVERIFIED = "UNVERIFIED"
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class ProvenanceRelationType(str, Enum):
    """Provenance edge relation types as defined in Document 02 §15.2 and Document 05 Table 14."""
    DERIVED_FROM = "DERIVED_FROM"
    TRANSFORMED_INTO = "TRANSFORMED_INTO"
    SUPERSEDES = "SUPERSEDES"


class MemoryRecord(BaseModel):
    """Memory record entity matching Document 05 Table 11 (memory_records)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: Optional[str] = None
    source_id: Optional[str] = None
    record_type: str = "KNOWLEDGE"
    trust_state: str = "TRUSTED"
    current_version: int = 1
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class MemoryVersion(BaseModel):
    """Memory version entity matching Document 05 Table 12 (memory_versions)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    record_id: str
    version: int
    content: str
    checksum: str
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ProvenanceEdge(BaseModel):
    """Provenance edge entity matching Document 05 Table 14 (provenance_edges)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    from_record_id: str
    to_record_id: str
    relation_type: str = "DERIVED_FROM"
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class MemoryIngestRequest(BaseModel):
    """Request payload for POST /memory matching Document 05 Section 5.1 Route Catalog."""
    content: str
    record_type: str = "KNOWLEDGE"
    source_id: Optional[str] = None
    parent_record_id: Optional[str] = None
    agent_id: Optional[str] = None


class MemoryRecordResponse(BaseModel):
    """Response item for memory record query."""
    id: str
    tenant_id: str
    agent_id: Optional[str] = None
    source_id: Optional[str] = None
    record_type: str = "KNOWLEDGE"
    trust_state: str = "TRUSTED"
    current_version: int = 1
    checksum: Optional[str] = None
    content: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class MemoryDetailResponse(BaseModel):
    """Response payload for GET /memory/{id} matching Document 05 Section 5.1."""
    record: MemoryRecord
    versions: List[MemoryVersion] = []
    provenance: List[ProvenanceEdge] = []
