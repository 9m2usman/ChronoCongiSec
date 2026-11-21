"""Pydantic models for MemoryRecord, MemoryVersion, and ProvenanceEdge.

Matches database schema in Document 05 (Section 3.3 Knowledge, Memory & Provenance) exactly.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


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


class MemoryRefStatus(str, Enum):
    """Status outcomes for memory reference verification by Gateway (Gate G4)."""
    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    INVALID_REF = "INVALID_REF"
    DUPLICATE_REF = "DUPLICATE_REF"
    ERROR = "ERROR"


class MemoryRefCheck(BaseModel):
    """Outcome of validating a single memory reference in an action proposal.
    
    Holds verification status, trust state (if found), version, and reason.
    """
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    record_id: Optional[str] = None
    status: MemoryRefStatus
    trust_state: Optional[str] = None
    current_version: Optional[int] = None
    reason: str


class ProvenanceRelationType(str, Enum):
    """Provenance edge relation types as defined in Document 02 §15.2 and Document 05 Table 14."""
    DERIVED_FROM = "DERIVED_FROM"
    TRANSFORMED_INTO = "TRANSFORMED_INTO"
    SUPERSEDES = "SUPERSEDES"


class MemoryRecord(BaseModel):
    """Memory record entity matching Document 05 Table 11 (memory_records)."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    agent_id: Optional[str] = None
    source_id: Optional[str] = None
    record_type: RecordType = RecordType.KNOWLEDGE
    trust_state: TrustState = TrustState.UNVERIFIED
    current_version: int = Field(default=1, ge=1)
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class MemoryVersion(BaseModel):
    """Memory version entity matching Document 05 Table 12 (memory_versions)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    record_id: str
    version: int = Field(..., ge=1)
    content: str
    checksum: str
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("checksum")
    @classmethod
    def validate_checksum(cls, v: str) -> str:
        if not isinstance(v, str) or not SHA256_HEX_REGEX.match(v):
            raise ValueError("Checksum must be a 64-character hexadecimal SHA-256 string.")
        return v

    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class ProvenanceEdge(BaseModel):
    """Provenance edge entity matching Document 05 Table 14 (provenance_edges)."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    from_record_id: str
    to_record_id: str
    relation_type: ProvenanceRelationType = ProvenanceRelationType.DERIVED_FROM
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class AgentRecord(BaseModel):
    """Agent entity contract matching Document 05 Table 5 (agents)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    runtime: str = "LANGCHAIN"
    model: str = "gpt-4o"
    status: str = "ACTIVE"
    branch_id: Optional[str] = None
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


SOURCE_STATUSES = ("ACTIVE", "INACTIVE")


class SourceRecord(BaseModel):
    """Source entity contract matching Document 05 Table 9 (sources)."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    source_type: str = "DOCUMENT_FEED"
    uri: Optional[str] = None
    trust_state: str = "UNVERIFIED"
    status: str = "ACTIVE"
    branch_id: Optional[str] = None
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in SOURCE_STATUSES:
            raise ValueError(f"status must be one of {SOURCE_STATUSES}, got '{v}'")
        return v

    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class MemoryIngestRequest(BaseModel):
    """Request payload for POST /memory matching Document 05 Section 5.1 Route Catalog."""
    model_config = ConfigDict(use_enum_values=True)

    content: str = Field(..., min_length=1, max_length=1_000_000, description="Memory content chunk")
    record_type: RecordType = Field(default=RecordType.KNOWLEDGE)
    source_id: Optional[str] = Field(None, max_length=128)
    parent_record_id: Optional[str] = Field(None, max_length=128)
    agent_id: Optional[str] = Field(None, max_length=128)


class MemoryRecordResponse(BaseModel):
    """Response item for memory record query."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    agent_id: Optional[str] = None
    source_id: Optional[str] = None
    record_type: RecordType = RecordType.KNOWLEDGE
    trust_state: TrustState = TrustState.UNVERIFIED
    current_version: int = Field(default=1, ge=1)
    checksum: Optional[str] = None
    content: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @field_validator("checksum")
    @classmethod
    def validate_checksum(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            if not isinstance(v, str) or not SHA256_HEX_REGEX.match(v):
                raise ValueError("Checksum must be a 64-character hexadecimal SHA-256 string.")
        return v


class MemoryDetailResponse(BaseModel):
    """Response payload for GET /memory/{id} matching Document 05 Section 5.1."""
    model_config = ConfigDict(from_attributes=True)

    record: MemoryRecord
    versions: List[MemoryVersion] = []
    provenance: List[ProvenanceEdge] = []


class LineDiffItem(BaseModel):
    """Individual added or removed line with line number."""
    line_number: int
    text: str


class VersionCompareResponse(BaseModel):
    """Response payload for GET /chronimem/records/{id}/compare matching Document 05 Section 5.1."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    record_id: str
    v_from: int
    v_to: int
    trust_state: str
    checksum_from: str
    checksum_to: str
    unified_diff: str
    added_lines: List[LineDiffItem] = Field(default_factory=list)
    removed_lines: List[LineDiffItem] = Field(default_factory=list)
    truncated: bool = False


class TimelineEvent(BaseModel):
    """Timeline entry for GET /chronimem/timeline matching Document 05 Section 5.1."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    record_id: str
    version: int
    checksum: str
    created_at: Optional[datetime] = None
    trust_state: str
    record_type: str


class KnowledgeGraphNode(BaseModel):
    """Node in topological knowledge graph (MemoryRecord projection without content)."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    record_type: str
    trust_state: str
    current_version: int
    agent_id: Optional[str] = None


class KnowledgeGraphEdge(BaseModel):
    """Edge in topological knowledge graph (ProvenanceEdge projection)."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    from_record_id: str
    to_record_id: str
    relation_type: str


class KnowledgeGraphResponse(BaseModel):
    """Response payload for GET /knowledge/graph matching Document 05 Section 5.1."""
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    nodes: List[KnowledgeGraphNode] = Field(default_factory=list)
    edges: List[KnowledgeGraphEdge] = Field(default_factory=list)
    complete: bool = True
    truncated_reason: Optional[str] = None


class MismatchedVersionItem(BaseModel):
    """Item indicating a mismatched cryptographic checksum for a specific version."""
    model_config = ConfigDict(from_attributes=True)

    record_id: str
    version: int


class MemoryIntegrityReport(BaseModel):
    """Comprehensive integrity report from audit_memory_integrity."""
    model_config = ConfigDict(from_attributes=True)

    total_records: int
    total_versions: int
    matched: int
    mismatched: List[MismatchedVersionItem] = Field(default_factory=list)
    missing_versions: List[str] = Field(default_factory=list)
    match_percentage: float
    started_at: datetime
    finished_at: datetime

