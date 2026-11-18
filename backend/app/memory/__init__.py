"""Memory and provenance subsystem.

Module: backend.app.memory
Owner: M3 — Knowledge & Memory Systems Lead
"""

from .ingestion import ingest_memory
from .integrity import (
    MemoryIntegrityError,
    audit_memory_integrity,
    sha256_hex,
    verify_checksum,
)
from .lineage import LineageResult, get_ancestors, get_descendants
from .models import (
    AgentRecord,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    KnowledgeGraphResponse,
    LineDiffItem,
    MemoryDetailResponse,
    MemoryIngestRequest,
    MemoryIntegrityReport,
    MemoryRecord,
    MemoryRecordResponse,
    MemoryRefCheck,
    MemoryRefStatus,
    MemoryVersion,
    MismatchedVersionItem,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    SourceRecord,
    TimelineEvent,
    TrustState,
    VersionCompareResponse,
)
from .provenance import (
    MAX_PROVENANCE_DEPTH,
    MAX_TRAVERSAL_BUDGET,
    VALID_RELATION_TYPES,
    InvalidProvenanceError,
    create_provenance_edge,
)
from .repository import (
    InMemoryMemoryRepository,
    MemoryRepository,
    get_default_repository,
    reset_default_repository,
)
from .retrieval import (
    MAX_MEMORY_REFS_PER_PROPOSAL,
    MemoryNotFoundError,
    get_memory_detail,
    retrieve_memory,
    transition_memory_trust_state,
    verify_memory_refs,
)
from .versioning import (
    MAX_DIFF_LINES,
    compare_versions,
    get_timeline,
    update_memory,
)

__all__ = [
    "MemoryRecord",
    "MemoryVersion",
    "ProvenanceEdge",
    "AgentRecord",
    "SourceRecord",
    "RecordType",
    "TrustState",
    "ProvenanceRelationType",
    "MemoryIngestRequest",
    "MemoryRecordResponse",
    "MemoryDetailResponse",
    "MemoryRepository",
    "InMemoryMemoryRepository",
    "get_default_repository",
    "reset_default_repository",
    "ingest_memory",
    "update_memory",
    "retrieve_memory",
    "get_memory_detail",
    "transition_memory_trust_state",
    "create_provenance_edge",
    "get_ancestors",
    "get_descendants",
    "LineageResult",
    "MemoryIntegrityError",
    "MemoryNotFoundError",
    "InvalidProvenanceError",
    "MAX_PROVENANCE_DEPTH",
    "MAX_TRAVERSAL_BUDGET",
    "VALID_RELATION_TYPES",
    "sha256_hex",
    "verify_checksum",
    "MemoryRefCheck",
    "MemoryRefStatus",
    "verify_memory_refs",
    "MAX_MEMORY_REFS_PER_PROPOSAL",
    "compare_versions",
    "get_timeline",
    "MAX_DIFF_LINES",
    "audit_memory_integrity",
    "LineDiffItem",
    "VersionCompareResponse",
    "TimelineEvent",
    "KnowledgeGraphNode",
    "KnowledgeGraphEdge",
    "KnowledgeGraphResponse",
    "MismatchedVersionItem",
    "MemoryIntegrityReport",
]
