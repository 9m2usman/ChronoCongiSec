"""Repository interface and in-memory implementation for Memory & Provenance entities.

TEMPORARY in-memory stand-in. Tenant-scoped repositories belong to M6 (backend/app/database/repositories/). Replace when M6's tables land.

Matches Document 05 Section 3.3 (tables: memory_records, memory_versions, provenance_edges).
"""

from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Dict, List, Optional

from .models import AgentRecord, MemoryRecord, MemoryVersion, ProvenanceEdge, RecordType, SourceRecord, TrustState


class _AwaitableNone:
    def __bool__(self):
        return False
    def __eq__(self, other):
        return other is None or isinstance(other, _AwaitableNone)
    def __await__(self):
        async def _c():
            return None
        return _c().__await__()

_AWAITABLE_NONE = _AwaitableNone()


class AwaitableList(list):
    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class _DualTransaction:
    def __init__(self, repo):
        self._repo = repo

    def _begin(self):
        depth = getattr(self._repo, "_tx_depth", 0)
        if depth == 0:
            self._repo._tx_failed = False
            self._repo._tx_snapshot = {
                "_records": deepcopy(getattr(self._repo, "_records", {})),
                "_versions": deepcopy(getattr(self._repo, "_versions", {})),
                "_edges": deepcopy(getattr(self._repo, "_edges", {})),
                "_agents": deepcopy(getattr(self._repo, "_agents", {})),
                "_sources": deepcopy(getattr(self._repo, "_sources", {})),
            }
        self._repo._tx_depth = depth + 1

    def _end(self, exc_type):
        if exc_type is not None:
            self._repo._tx_failed = True
        depth = getattr(self._repo, "_tx_depth", 1) - 1
        self._repo._tx_depth = max(0, depth)
        if self._repo._tx_depth == 0:
            if getattr(self._repo, "_tx_failed", False):
                snapshot = getattr(self._repo, "_tx_snapshot", None)
                if snapshot is not None:
                    for k, v in snapshot.items():
                        if hasattr(self._repo, k):
                            setattr(self._repo, k, v)
            self._repo._tx_snapshot = None
            self._repo._tx_failed = False
        return False

    def __enter__(self):
        self._begin()
        return self._repo

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._end(exc_type)

    async def __aenter__(self):
        self._begin()
        return self._repo

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self._end(exc_type)


class MemoryRepository(ABC):
    """Abstract interface for memory persistence, matching M6 relational tables."""

    is_persistent: bool = False
    is_in_memory: bool = False

    def transaction(self):
        """Provide transaction context for multi-entity writes (GAP-008)."""
        return _DualTransaction(self)

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
        only_trusted: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        """Query memory records with optional filters, pagination, and strict tenant scoping.

        When only_trusted=True (default for normal retrieval), only records with
        trust_state == TRUSTED are returned.
        """
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

    @abstractmethod
    def get_agent(self, agent_id: str, tenant_id: str) -> Optional[AgentRecord]:
        """Fetch an agent entity by ID within company/tenant boundary."""
        pass

    @abstractmethod
    def create_agent(self, agent: AgentRecord) -> AgentRecord:
        """Persist an agent entity."""
        pass

    @abstractmethod
    def get_source(self, source_id: str, tenant_id: str) -> Optional[SourceRecord]:
        """Fetch a knowledge source by ID within company/tenant boundary."""
        pass

    @abstractmethod
    def create_source(self, source: SourceRecord) -> SourceRecord:
        """Persist a knowledge source entity."""
        pass


AGENT_ALIASES: Dict[str, str] = {
    "agt-fin-001": "agent-crew-finance-003",
    "agt-supp-001": "agent-crew-support-001",
    "agt-hr-001": "agent-crew-hr-002",
    "agt-branch-001": "agent-crew-branch-004",
    "agt-coord-001": "agent-crew-coord-005",
}


class InMemoryMemoryRepository(MemoryRepository):
    """In-memory reference implementation of MemoryRepository for standalone operation and tests."""

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        # Key: record_id -> MemoryRecord
        self._records: Dict[str, MemoryRecord] = {}
        # Key: record_id -> List[MemoryVersion]
        self._versions: Dict[str, List[MemoryVersion]] = {}
        # Key: edge_id -> ProvenanceEdge
        self._edges: Dict[str, ProvenanceEdge] = {}
        # Key: (agent_id, tenant_id) -> AgentRecord
        self._agents: Dict[str, AgentRecord] = {}
        # Key: (source_id, tenant_id) -> SourceRecord
        self._sources: Dict[str, SourceRecord] = {}

        self._seed_defaults()

    def _seed_defaults(self) -> None:
        """Seed canonical agents and sources for default organization and branches."""
        # Canonical organization: tenant-a-uuid-001 (ChronoCongiSec Enterprise)
        t_a = "tenant-a-uuid-001"
        self.create_agent(
            AgentRecord(
                id="agent-001",
                tenant_id=t_a,
                name="Finance Bot",
                status="ACTIVE",
                branch_id="branch-lhr-002",
            )
        )
        self.create_agent(
            AgentRecord(
                id="agent-head-office-001",
                tenant_id=t_a,
                name="Head Office Lead Bot",
                status="ACTIVE",
                branch_id="branch-ho-001",
            )
        )
        self.create_agent(
            AgentRecord(
                id="agent-inactive-001",
                tenant_id=t_a,
                name="Deprecated Bot",
                status="ISOLATED",
                branch_id="branch-lhr-002",
            )
        )

        # CrewAI Business Agents (AMSC-DOC-005 Table 5)
        crew_agents = [
            ("agent-crew-support-001", "Customer Support Specialist", "branch-ho-001"),
            ("agent-crew-hr-002", "HR Operations Specialist", "branch-isb-004"),
            ("agent-crew-finance-003", "Finance Operations Specialist", "branch-lhr-002"),
            ("agent-crew-branch-004", "Branch Operations Specialist", "branch-khi-003"),
            ("agent-crew-coord-005", "Enterprise Workflow Coordinator", "branch-ho-001"),
        ]
        for aid, aname, abid in crew_agents:
            self.create_agent(
                AgentRecord(
                    id=aid,
                    tenant_id=t_a,
                    name=aname,
                    status="ACTIVE",
                    branch_id=abid,
                )
            )

        # Enterprise agent aliases for UI shortcuts and client compatibility
        for alias_id, canonical_id in AGENT_ALIASES.items():
            self.create_agent(
                AgentRecord(
                    id=alias_id,
                    tenant_id=t_a,
                    name=f"Alias for {canonical_id}",
                    status="ACTIVE",
                )
            )

        # Knowledge sources for tenant-a-uuid-001
        self.create_source(
            SourceRecord(
                id="src-doc-001",
                tenant_id=t_a,
                name="Treasury Policy Memo",
                source_type="DOCUMENT_FEED",
                status="ACTIVE",
                branch_id="branch-ho-001",
            )
        )
        self.create_source(
            SourceRecord(
                id="src-inactive-001",
                tenant_id=t_a,
                name="Old Inactive Feed",
                source_type="DOCUMENT_FEED",
                status="INACTIVE",
            )
        )
        sources = [
            ("src-accounting-policy-v2.pdf", "Accounting Policy v2", "branch-lhr-002"),
            ("src-hr-handbook-v1.pdf", "HR Employee Handbook", "branch-isb-004"),
            ("src-support-guide-v1.pdf", "Customer Support Protocols", "branch-ho-001"),
            ("src-branch-ops-v1.pdf", "Branch Operations Manual", "branch-khi-003"),
            ("src-workflow-gov-v1.pdf", "Cross-Department Workflow Governance", "branch-ho-001"),
        ]
        for sid, sname, sbid in sources:
            self.create_source(
                SourceRecord(
                    id=sid,
                    tenant_id=t_a,
                    name=sname,
                    source_type="DOCUMENT_FEED",
                    status="ACTIVE",
                    branch_id=sbid,
                )
            )

        # Secondary tenant for cross-company isolation tests
        t_b = "tenant-b-uuid-002"
        self.create_agent(
            AgentRecord(
                id="agent-b-001",
                tenant_id=t_b,
                name="External Agent",
                status="ACTIVE",
            )
        )
        self.create_source(
            SourceRecord(
                id="src-b-001",
                tenant_id=t_b,
                name="External Partner Source",
                status="ACTIVE",
            )
        )

    def transaction(self):
        return _DualTransaction(self)

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
        return _AWAITABLE_NONE

    def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        only_trusted: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

        results: List[MemoryRecord] = []
        for rec in self._records.values():
            if rec.tenant_id != tenant_id:
                continue
            if agent_id is not None and rec.agent_id != agent_id:
                continue
            # Enforce GAP-001: Normal retrieval must return ONLY eligible TRUSTED memory
            if only_trusted and rec.trust_state != TrustState.TRUSTED.value:
                continue
            if trust_state is not None and rec.trust_state != trust_state:
                continue
            results.append(deepcopy(rec))

        # Sort by created_at asc
        results.sort(key=lambda r: (r.created_at or 0))
        return AwaitableList(results[safe_offset : safe_offset + safe_limit])

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
            return AwaitableList([])
        versions = self._versions.get(record_id, [])
        return AwaitableList([deepcopy(v) for v in versions if v.tenant_id == tenant_id])

    def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        for v in self.get_versions(record_id, tenant_id):
            if v.version == version:
                return deepcopy(v)
        return _AWAITABLE_NONE

    def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        versions = self.get_versions(record_id, tenant_id)
        if versions:
            return deepcopy(versions[-1])
        return _AWAITABLE_NONE

    def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        if edge.from_record_id == edge.to_record_id:
            raise ValueError(
                f"Self-loop provenance edge is prohibited (from_record_id '{edge.from_record_id}' "
                f"cannot equal to_record_id '{edge.to_record_id}')."
            )
        # Idempotent return on duplicate edge (DOC-005/0006 constraint)
        for existing in self._edges.values():
            if (
                existing.tenant_id == edge.tenant_id
                and existing.from_record_id == edge.from_record_id
                and existing.to_record_id == edge.to_record_id
                and existing.relation_type == edge.relation_type
            ):
                return deepcopy(existing)
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
        return AwaitableList(edges)

    def get_agent(self, agent_id: str, tenant_id: str) -> Optional[AgentRecord]:
        key = f"{tenant_id}:{agent_id}"
        agent = self._agents.get(key)
        if not agent and agent_id in AGENT_ALIASES:
            agent = self._agents.get(f"{tenant_id}:{AGENT_ALIASES[agent_id]}")
        return deepcopy(agent) if agent else _AWAITABLE_NONE

    def create_agent(self, agent: AgentRecord) -> AgentRecord:
        stored = deepcopy(agent)
        key = f"{stored.tenant_id}:{stored.id}"
        self._agents[key] = stored
        return deepcopy(stored)

    def get_source(self, source_id: str, tenant_id: str) -> Optional[SourceRecord]:
        key = f"{tenant_id}:{source_id}"
        src = self._sources.get(key)
        return deepcopy(src) if src else _AWAITABLE_NONE

    def create_source(self, source: SourceRecord) -> SourceRecord:
        stored = deepcopy(source)
        key = f"{stored.tenant_id}:{stored.id}"
        self._sources[key] = stored
        return deepcopy(stored)


# Global in-memory repository instance for runtime dependency injection
_default_repository = InMemoryMemoryRepository()


def get_default_repository() -> MemoryRepository:
    """Return the default memory repository.

    Fails closed in production if a persistent M6 database repository is not configured.
    """
    try:
        from backend.app.core.config import get_settings
        settings = get_settings()
        if settings.APP_ENV == "production":
            raise RuntimeError(
                "Production startup failure: Real database memory repository from M6 is not configured. "
                "In-memory memory repository fallback is prohibited in production."
            )
    except ImportError:
        pass
    return _default_repository


def reset_default_repository() -> None:
    """Reset repository storage, primarily used for test fixture cleanup."""
    global _default_repository
    _default_repository = InMemoryMemoryRepository()


def seed_enterprise_demo_memories(repo: MemoryRepository) -> None:
    """Seed canonical trusted memories for tenant-a-uuid-001 business agents."""
    t_a = "tenant-a-uuid-001"
    from backend.app.memory.integrity import sha256_hex

    policies = [
        (
            "mem-supp-faq-001",
            "agent-crew-support-001",
            (
                "ChronoCogniSec Return & Refund Policy:\n"
                "Full refund permitted within 14 calendar days of purchase with valid receipt. "
                "Disbursements over $300 require dual-custody managerial approval."
            ),
        ),
        (
            "mem-hr-pol-001",
            "agent-crew-hr-002",
            (
                "ChronoCogniSec HR Handbook:\n"
                "Annual leave entitlement is 22 working days per year for full-time employees. "
                "Sick leave up to 10 days with certificate required after 2 days."
            ),
        ),
        (
            "mem-fin-proc-001",
            "agent-crew-finance-003",
            (
                "ChronoCogniSec Financial Governance:\n"
                "Disbursements and reimbursements over $300.00 USD strictly require dual-custody "
                "approval from a Finance Manager. Self-approval is strictly forbidden."
            ),
        ),
        (
            "mem-branch-ops-001",
            "agent-crew-branch-004",
            (
                "ChronoCogniSec Branch Operations Protocol:\n"
                "Regional branches must synchronize daily facility status and vault inventory with Head Office. "
                "Cross-branch access to facility records without Head Office authorization is strictly prohibited."
            ),
        ),
        (
            "mem-coord-pol-001",
            "agent-crew-coord-005",
            (
                "ChronoCogniSec Cross-Department Workflow Governance:\n"
                "Multi-department initiatives must be decomposed into bounded tasks assigned to designated specialists. "
                "All tool actions must be routed through the Security Gateway and validated against trusted policies."
            ),
        ),
    ]

    for mid, aid, content in policies:
        rec = MemoryRecord(
            id=mid,
            tenant_id=t_a,
            agent_id=aid,
            source_id="src-doc-001",
            record_type=RecordType.KNOWLEDGE.value,
            trust_state=TrustState.TRUSTED.value,
            current_version=1,
        )
        repo.create_record(rec)
        ver = MemoryVersion(
            id=f"ver-{mid}-1",
            tenant_id=t_a,
            record_id=mid,
            version=1,
            content=content,
            checksum=sha256_hex(content),
        )
        repo.create_version(ver)
