"""Memory and provenance subsystem.

Module: backend.app.memory
Owner: M3 — Knowledge & Memory Systems Lead
"""

from .ingestion import ingest_memory
from .integrity import MemoryIntegrityError, sha256_hex, verify_checksum
from .lineage import LineageResult, get_ancestors, get_descendants
from .models import (
    AgentRecord,
    MemoryDetailResponse,
    MemoryIngestRequest,
    MemoryRecord,
    MemoryRecordResponse,
    MemoryVersion,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    SourceRecord,
    TrustState,
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
    MemoryNotFoundError,
    get_memory_detail,
    retrieve_memory,
    transition_memory_trust_state,
)
from .versioning import update_memory

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
]
