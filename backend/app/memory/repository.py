"""Repository interface and in-memory implementation for Memory & Provenance entities.

Matches Document 05 Section 3.3 (tables: memory_records, memory_versions, provenance_edges).
"""

from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Dict, List, Optional

from .models import MemoryRecord, MemoryVersion, ProvenanceEdge


class MemoryRepository(ABC):
    """Abstract interface for memory persistence, matching M6 relational tables."""

    @abstractmethod
    def create_record(self, record: MemoryRecord) -> MemoryRecord:
        """Persist a new memory record."""
        pass

    @abstractmethod
    def get_record(self, record_id: str, tenant_id: str) -> Optional[MemoryRecord]:
        """Fetch a memory record by ID within tenant boundary."""
        pass

    @abstractmethod
    def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        exclude_quarantined: bool = True,
    ) -> List[MemoryRecord]:
        """Query memory records with optional filters and strict tenant scoping."""
        pass

    @abstractmethod
    def update_record(self, record: MemoryRecord) -> MemoryRecord:
        """Update an existing memory record (e.g. current_version, updated_at)."""
        pass

    @abstractmethod
    def create_version(self, version: MemoryVersion) -> MemoryVersion:
        """Persist a new immutable memory version."""
        pass

    @abstractmethod
    def get_versions(self, record_id: str, tenant_id: str) -> List[MemoryVersion]:
        """Fetch all historical versions of a record, sorted by version asc."""
        pass

    @abstractmethod
    def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        """Fetch a specific version of a record within tenant."""
        pass

    @abstractmethod
    def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        """Fetch the latest version of a record within tenant."""
        pass

    @abstractmethod
    def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        """Persist a provenance edge."""
        pass

    @abstractmethod
    def get_edges_for_record(self, record_id: str, tenant_id: str) -> List[ProvenanceEdge]:
        """Fetch all provenance edges connecting to or from a record within tenant."""
        pass


class InMemoryMemoryRepository(MemoryRepository):
    """In-memory reference implementation of MemoryRepository for standalone operation and tests."""

    def __init__(self) -> None:
        # Key: record_id -> MemoryRecord
        self._records: Dict[str, MemoryRecord] = {}
        # Key: record_id -> List[MemoryVersion]
        self._versions: Dict[str, List[MemoryVersion]] = {}
        # Key: edge_id -> ProvenanceEdge
        self._edges: Dict[str, ProvenanceEdge] = {}

    def create_record(self, record: MemoryRecord) -> MemoryRecord:
        stored = deepcopy(record)
        self._records[stored.id] = stored
        if stored.id not in self._versions:
            self._versions[stored.id] = []
        return deepcopy(stored)

    def get_record(self, record_id: str, tenant_id: str) -> Optional[MemoryRecord]:
        rec = self._records.get(record_id)
        if rec and rec.tenant_id == tenant_id:
            return deepcopy(rec)
        return None

    def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        exclude_quarantined: bool = True,
    ) -> List[MemoryRecord]:
        results: List[MemoryRecord] = []
        for rec in self._records.values():
            if rec.tenant_id != tenant_id:
                continue
            if agent_id is not None and rec.agent_id != agent_id:
                continue
            if trust_state is not None and rec.trust_state != trust_state:
                continue
            if exclude_quarantined and rec.trust_state == "QUARANTINED":
                continue
            results.append(deepcopy(rec))
        # Sort by created_at asc
        results.sort(key=lambda r: (r.created_at or 0))
        return results

    def update_record(self, record: MemoryRecord) -> MemoryRecord:
        existing = self._records.get(record.id)
        if not existing or existing.tenant_id != record.tenant_id:
            raise KeyError(f"Memory record {record.id} not found for tenant {record.tenant_id}")
        self._records[record.id] = deepcopy(record)
        return deepcopy(record)

    def create_version(self, version: MemoryVersion) -> MemoryVersion:
        stored = deepcopy(version)
        versions_list = self._versions.setdefault(stored.record_id, [])
        for existing in versions_list:
            if existing.version == stored.version:
                raise ValueError(
                    f"Version {stored.version} already exists for record {stored.record_id} "
                    f"(violates uq_record_version constraint)"
                )
        versions_list.append(stored)
        versions_list.sort(key=lambda v: v.version)
        return deepcopy(stored)

    def get_versions(self, record_id: str, tenant_id: str) -> List[MemoryVersion]:
        record = self.get_record(record_id, tenant_id)
        if not record:
            return []
        versions = self._versions.get(record_id, [])
        return [deepcopy(v) for v in versions if v.tenant_id == tenant_id]

    def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        for v in self.get_versions(record_id, tenant_id):
            if v.version == version:
                return deepcopy(v)
        return None

    def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        versions = self.get_versions(record_id, tenant_id)
        if versions:
            return deepcopy(versions[-1])
        return None

    def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        stored = deepcopy(edge)
        self._edges[stored.id] = stored
        return deepcopy(stored)

    def get_edges_for_record(self, record_id: str, tenant_id: str) -> List[ProvenanceEdge]:
        edges: List[ProvenanceEdge] = []
        for edge in self._edges.values():
            if edge.tenant_id != tenant_id:
                continue
            if edge.from_record_id == record_id or edge.to_record_id == record_id:
                edges.append(deepcopy(edge))
        return edges


# Global in-memory repository instance for runtime dependency injection
_default_repository = InMemoryMemoryRepository()


def get_default_repository() -> InMemoryMemoryRepository:
    """Return the default singleton in-memory repository."""
    return _default_repository


def reset_default_repository() -> None:
    """Reset repository storage, primarily used for test fixture cleanup."""
    global _default_repository
    _default_repository = InMemoryMemoryRepository()
