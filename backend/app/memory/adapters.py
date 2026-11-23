"""SQLAlchemy PostgreSQL adapter for Memory & Provenance entities (AMSC-DOC-005 §3.3).

Module: backend.app.memory.adapters
Owner: M3 — Knowledge & Memory Systems Lead

Implements the async ``MemoryRepository`` protocol on top of M6's ``TenantScopedRepository``
and SQLAlchemy models (``memory_records``, ``memory_versions``, ``provenance_edges``, ``agents``, ``sources``).

# Field-by-Field Mapping Table

## 1. MemoryRecord (ORM: memory_records <-> Pydantic: MemoryRecord)
| Pydantic Field   | Pydantic Type              | ORM Column       | ORM Type              | Conversion / Notes                                    |
|------------------|----------------------------|------------------|-----------------------|-------------------------------------------------------|
| id               | str                        | id               | String(64), PK        | Direct 1:1 string                                     |
| tenant_id        | str                        | tenant_id        | String(64), NOT NULL  | Direct 1:1 string, composite FK tenant boundary       |
| agent_id         | Optional[str]              | agent_id         | String(64), Nullable  | Direct 1:1, references agents.id                      |
| source_id        | Optional[str]              | source_id        | String(64), Nullable  | Direct 1:1, references sources.id                     |
| record_type      | RecordType (enum/str)      | record_type      | String(64), NOT NULL  | Enum value string (default: 'KNOWLEDGE')              |
| trust_state      | TrustState (enum/str)      | trust_state      | String(32), NOT NULL  | Enum value string (default: 'UNVERIFIED')             |
| current_version  | int                        | current_version  | Integer, NOT NULL     | Direct 1:1 integer (>= 1, default: 1)                 |
| created_at       | Optional[datetime]         | created_at       | DateTime(tz), server  | Timezone-aware datetime                               |
| updated_at       | Optional[datetime]         | updated_at       | DateTime(tz), server  | Timezone-aware datetime                               |

## 2. MemoryVersion (ORM: memory_versions <-> Pydantic: MemoryVersion)
| Pydantic Field   | Pydantic Type              | ORM Column       | ORM Type              | Conversion / Notes                                    |
|------------------|----------------------------|------------------|-----------------------|-------------------------------------------------------|
| id               | str                        | id               | String(64), PK        | Direct 1:1 string                                     |
| tenant_id        | str                        | tenant_id        | String(64), NOT NULL  | Direct 1:1 string, composite FK tenant boundary       |
| record_id        | str                        | record_id        | String(64), NOT NULL  | Direct 1:1, references memory_records.id              |
| version          | int                        | version          | Integer, NOT NULL     | Direct 1:1 integer (>= 1)                             |
| content          | str                        | content          | Text, NOT NULL        | Raw text content                                      |
| checksum         | str                        | checksum         | String(64), NOT NULL  | 64-character hex SHA-256 string                       |
| created_at       | Optional[datetime]         | created_at       | DateTime(tz), server  | Timezone-aware datetime                               |

## 3. ProvenanceEdge (ORM: provenance_edges <-> Pydantic: ProvenanceEdge)
| Pydantic Field   | Pydantic Type              | ORM Column       | ORM Type              | Conversion / Notes                                    |
|------------------|----------------------------|------------------|-----------------------|-------------------------------------------------------|
| id               | str                        | id               | String(64), PK        | Direct 1:1 string                                     |
| tenant_id        | str                        | tenant_id        | String(64), NOT NULL  | Direct 1:1 string, composite FK tenant boundary       |
| from_record_id   | str                        | from_record_id   | String(64), NOT NULL  | Direct 1:1, references memory_records.id              |
| to_record_id     | str                        | to_record_id     | String(64), NOT NULL  | Direct 1:1, references memory_records.id              |
| relation_type    | ProvenanceRelationType     | relation_type    | String(64), NOT NULL  | Enum value string ('DERIVED_FROM', etc.)              |
| created_at       | Optional[datetime]         | created_at       | DateTime(tz), server  | Timezone-aware datetime                               |

## 4. AgentRecord (ORM: agents <-> Pydantic: AgentRecord)
| Pydantic Field   | Pydantic Type              | ORM Column       | ORM Type              | Conversion / Notes                                    |
|------------------|----------------------------|------------------|-----------------------|-------------------------------------------------------|
| id               | str                        | id               | String(64), PK        | Direct 1:1 string                                     |
| tenant_id        | str                        | tenant_id        | String(64), NOT NULL  | Direct 1:1 string                                     |
| name             | str                        | name             | String(255), NOT NULL | Agent display name                                    |
| runtime          | str                        | runtime          | String(64), NOT NULL  | Runtime framework (default: 'LANGCHAIN')              |
| model            | str                        | model            | String(64), NOT NULL  | LLM model identifier (default: 'gpt-4o')              |
| status           | str                        | status           | String(32), NOT NULL  | Lifecycle status ('ACTIVE', 'ISOLATED')               |
| created_at       | Optional[datetime]         | created_at       | DateTime(tz), server  | Timezone-aware datetime                               |

## 5. SourceRecord (ORM: sources <-> Pydantic: SourceRecord)
| Pydantic Field   | Pydantic Type              | ORM Column       | ORM Type              | Conversion / Notes                                    |
|------------------|----------------------------|------------------|-----------------------|-------------------------------------------------------|
| id               | str                        | id               | String(64), PK        | Direct 1:1 string                                     |
| tenant_id        | str                        | tenant_id        | String(64), NOT NULL  | Direct 1:1 string                                     |
| name             | str                        | name             | String(255), NOT NULL | Source label / name                                   |
| source_type      | str                        | source_type      | String(64), NOT NULL  | Ingestion feed type (default: 'DOCUMENT_FEED')         |
| uri              | Optional[str]              | uri              | String(1024), Nullable| Source document or resource URI                       |
| trust_state      | str                        | trust_state      | String(32), NOT NULL  | Dynamic trust state (default: 'UNVERIFIED')           |
| status           | str                        | status           | String(32), NOT NULL  | Lifecycle status ('ACTIVE', 'INACTIVE')               |
| created_at       | Optional[datetime]         | created_at       | DateTime(tz), server  | Timezone-aware datetime                               |
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.agents import Agent as OrmAgent
from backend.app.database.models.memory import (
    MemoryRecord as OrmMemoryRecord,
    MemoryVersion as OrmMemoryVersion,
    ProvenanceEdge as OrmProvenanceEdge,
    Source as OrmSource,
)
from backend.app.database.repositories.base import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    TenantScopedRepository,
    TenantScopeError,
)
from backend.app.database.repositories.memory import (
    MemoryVersionRepository,
    ProvenanceEdgeRepository,
)
from backend.app.memory.models import (
    AgentRecord,
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    ProvenanceRelationType,
    RecordType,
    SourceRecord,
    TrustState,
)
from backend.app.memory.repository import MemoryRepository

logger = logging.getLogger("amsc.memory.adapters")


# --- Explicit Model Mapping Functions ---

def to_pydantic_memory_record(row: OrmMemoryRecord) -> MemoryRecord:
    """Map ORM MemoryRecord row to Pydantic MemoryRecord."""
    rec_type = row.record_type
    try:
        parsed_type = RecordType(rec_type)
    except (ValueError, KeyError):
        parsed_type = RecordType.KNOWLEDGE

    trust_st = row.trust_state
    try:
        parsed_trust = TrustState(trust_st)
    except (ValueError, KeyError):
        parsed_trust = TrustState.UNVERIFIED

    return MemoryRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        agent_id=row.agent_id,
        source_id=row.source_id,
        record_type=parsed_type,
        trust_state=parsed_trust,
        current_version=row.current_version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def to_orm_memory_record(model: MemoryRecord, tenant_id: str) -> OrmMemoryRecord:
    """Map Pydantic MemoryRecord to ORM MemoryRecord row."""
    rec_type = model.record_type.value if hasattr(model.record_type, "value") else str(model.record_type)
    trust_st = model.trust_state.value if hasattr(model.trust_state, "value") else str(model.trust_state)
    return OrmMemoryRecord(
        id=model.id,
        tenant_id=tenant_id,
        agent_id=model.agent_id,
        source_id=model.source_id,
        record_type=rec_type,
        trust_state=trust_st,
        current_version=model.current_version,
        created_at=model.created_at or datetime.now(timezone.utc),
        updated_at=model.updated_at or datetime.now(timezone.utc),
    )


def to_pydantic_memory_version(row: OrmMemoryVersion) -> MemoryVersion:
    """Map ORM MemoryVersion row to Pydantic MemoryVersion."""
    return MemoryVersion(
        id=row.id,
        tenant_id=row.tenant_id,
        record_id=row.record_id,
        version=row.version,
        content=row.content,
        checksum=row.checksum,
        created_at=row.created_at,
    )


def to_orm_memory_version(model: MemoryVersion, tenant_id: str) -> OrmMemoryVersion:
    """Map Pydantic MemoryVersion to ORM MemoryVersion row."""
    return OrmMemoryVersion(
        id=model.id,
        tenant_id=tenant_id,
        record_id=model.record_id,
        version=model.version,
        content=model.content,
        checksum=model.checksum,
        created_at=model.created_at or datetime.now(timezone.utc),
    )


def to_pydantic_provenance_edge(row: OrmProvenanceEdge) -> ProvenanceEdge:
    """Map ORM ProvenanceEdge row to Pydantic ProvenanceEdge."""
    try:
        rel = ProvenanceRelationType(row.relation_type)
    except (ValueError, KeyError):
        rel = ProvenanceRelationType.DERIVED_FROM
    return ProvenanceEdge(
        id=row.id,
        tenant_id=row.tenant_id,
        from_record_id=row.from_record_id,
        to_record_id=row.to_record_id,
        relation_type=rel,
        created_at=row.created_at,
    )


def to_orm_provenance_edge(model: ProvenanceEdge, tenant_id: str) -> OrmProvenanceEdge:
    """Map Pydantic ProvenanceEdge to ORM ProvenanceEdge row."""
    rel = model.relation_type.value if hasattr(model.relation_type, "value") else str(model.relation_type)
    return OrmProvenanceEdge(
        id=model.id,
        tenant_id=tenant_id,
        from_record_id=model.from_record_id,
        to_record_id=model.to_record_id,
        relation_type=rel,
        created_at=model.created_at or datetime.now(timezone.utc),
    )


def to_pydantic_agent_record(row: OrmAgent) -> AgentRecord:
    """Map ORM Agent row to Pydantic AgentRecord."""
    return AgentRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        runtime=row.runtime,
        model=row.model,
        status=row.status,
        created_at=row.created_at,
    )


def to_orm_agent(model: AgentRecord, tenant_id: str) -> OrmAgent:
    """Map Pydantic AgentRecord to ORM Agent row."""
    now = datetime.now(timezone.utc)
    return OrmAgent(
        id=model.id,
        tenant_id=tenant_id,
        name=model.name,
        runtime=model.runtime,
        model=model.model,
        status=model.status,
        created_at=model.created_at or now,
        updated_at=now,
    )


def to_pydantic_source_record(row: OrmSource) -> SourceRecord:
    """Map ORM Source row to Pydantic SourceRecord."""
    return SourceRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        source_type=row.source_type,
        uri=row.uri,
        trust_state=row.trust_state,
        status=row.status,
        created_at=row.created_at,
    )


def to_orm_source(model: SourceRecord, tenant_id: str) -> OrmSource:
    """Map Pydantic SourceRecord to ORM Source row."""
    return OrmSource(
        id=model.id,
        tenant_id=tenant_id,
        name=model.name,
        source_type=model.source_type,
        uri=model.uri,
        trust_state=model.trust_state,
        status=model.status,
        created_at=model.created_at or datetime.now(timezone.utc),
    )


def sanitize_integrity_error(exc: IntegrityError) -> IntegrityError:
    """Sanitize SQLAlchemy IntegrityError to prevent leaking internal SQL, schema details, or connection credentials.

    ASSUMPTION (M3): Re-raising a sanitized IntegrityError with stripped SQL statement and parameter details
    ensures security compliance while preserving the underlying exception type for database layers.
    """
    sanitized_msg = "Database integrity constraint violated: the requested operation failed relational validation."
    return IntegrityError(
        statement=sanitized_msg,
        params=None,
        orig=Exception(sanitized_msg),
    )


# --- Persistent SQLAlchemy Repository Adapter ---

class SqlAlchemyMemoryRepository(MemoryRepository):
    """Production PostgreSQL adapter implementing the async MemoryRepository protocol on top of M6 tables.

    Bound to a single tenant_id at construction time. Every query and mutation enforces tenant isolation,
    bounded query limits, and atomic transaction semantics.
    """

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session: AsyncSession, tenant_id: str) -> None:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise TenantScopeError("A non-empty tenant_id is required for SqlAlchemyMemoryRepository.")
        self.session = session
        self.tenant_id = tenant_id

        # M6 TenantScopedRepository instances for underlying models
        self._record_repo = TenantScopedRepository(session, tenant_id, model=OrmMemoryRecord)
        self._version_repo = MemoryVersionRepository(session, tenant_id)
        self._edge_repo = ProvenanceEdgeRepository(session, tenant_id)
        self._agent_repo = TenantScopedRepository(session, tenant_id, model=OrmAgent)
        self._source_repo = TenantScopedRepository(session, tenant_id, model=OrmSource)

    def _assert_tenant(self, tenant_id: str) -> None:
        """Fail closed if the requested tenant_id does not match the bound tenant."""
        if tenant_id != self.tenant_id:
            raise TenantScopeError(
                f"Tenant mismatch: repository bound to '{self.tenant_id}', operation requested for '{tenant_id}'."
            )

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator["SqlAlchemyMemoryRepository"]:
        """Provide an atomic transaction context for multi-entity writes (GAP-008).

        Conforms to M6 session conventions: uses begin_nested() if an outer transaction
        is already active on the session; otherwise uses session.begin().
        """
        # ASSUMPTION (M3): Checking session.in_transaction() allows seamless nesting within an outer unit of work
        # or test transaction fixture using SAVEPOINTs without premature commit.
        if self.session.in_transaction():
            async with self.session.begin_nested():
                yield self
        else:
            async with self.session.begin():
                yield self

    async def create_record(self, record: MemoryRecord) -> MemoryRecord:
        """Persist a new memory record row within the bound tenant."""
        self._assert_tenant(record.tenant_id)
        try:
            async with self.session.begin_nested():
                orm_rec = to_orm_memory_record(record, self.tenant_id)
                self.session.add(orm_rec)
                await self.session.flush()
                return to_pydantic_memory_record(orm_rec)
        except IntegrityError as exc:
            raise sanitize_integrity_error(exc)

    async def get_record(self, record_id: str, tenant_id: str) -> Optional[MemoryRecord]:
        """Fetch a memory record by ID, strictly filtered by tenant."""
        self._assert_tenant(tenant_id)
        row = await self._record_repo.get(record_id)
        return to_pydantic_memory_record(row) if row is not None else None

    async def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        only_trusted: bool = True,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        """Query memory records with optional filters, bounded pagination, and strict tenant scoping.

        Uses private select() because M6's base repository list() does not express only_trusted filtering
        or created_at ordering.
        """
        self._assert_tenant(tenant_id)
        safe_limit = max(1, min(limit, MAX_PAGE_SIZE))
        safe_offset = max(0, offset)

        stmt = select(OrmMemoryRecord).where(OrmMemoryRecord.tenant_id == self.tenant_id)
        if agent_id is not None:
            stmt = stmt.where(OrmMemoryRecord.agent_id == agent_id)
        if only_trusted:
            stmt = stmt.where(OrmMemoryRecord.trust_state == TrustState.TRUSTED.value)
        if trust_state is not None:
            stmt = stmt.where(OrmMemoryRecord.trust_state == trust_state)

        stmt = (
            stmt.order_by(OrmMemoryRecord.created_at.asc(), OrmMemoryRecord.id.asc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return [to_pydantic_memory_record(r) for r in rows]

    async def update_record(self, record: MemoryRecord) -> MemoryRecord:
        """Update fields of an existing memory record within the bound tenant."""
        self._assert_tenant(record.tenant_id)
        rec_type = record.record_type.value if hasattr(record.record_type, "value") else str(record.record_type)
        trust_st = record.trust_state.value if hasattr(record.trust_state, "value") else str(record.trust_state)

        updated_row = await self._record_repo.update(
            record.id,
            agent_id=record.agent_id,
            source_id=record.source_id,
            record_type=rec_type,
            trust_state=trust_st,
            current_version=record.current_version,
            updated_at=record.updated_at or datetime.now(timezone.utc),
        )
        if updated_row is None:
            raise KeyError(f"Memory record {record.id} not found for tenant {record.tenant_id}")
        return to_pydantic_memory_record(updated_row)

    async def create_version(self, version: MemoryVersion) -> MemoryVersion:
        """Persist a new immutable memory version.

        Raises ValueError on duplicate (record_id, version) to match Prompt 1 contract.
        """
        self._assert_tenant(version.tenant_id)
        try:
            async with self.session.begin_nested():
                orm_version = to_orm_memory_version(version, self.tenant_id)
                self.session.add(orm_version)
                await self.session.flush()
                return to_pydantic_memory_version(orm_version)
        except IntegrityError as exc:
            err_str = str(exc.orig) if hasattr(exc, "orig") else str(exc)
            if "uq_record_version" in err_str or "version" in err_str.lower():
                raise ValueError(
                    f"Version {version.version} already exists for record {version.record_id} "
                    f"(violates uq_record_version constraint)"
                )
            raise sanitize_integrity_error(exc)

    async def get_versions(self, record_id: str, tenant_id: str) -> List[MemoryVersion]:
        """Fetch all historical versions of a record, ordered by version asc with bounded limit."""
        self._assert_tenant(tenant_id)
        # Verify the record exists and belongs to this tenant first
        rec = await self._record_repo.get(record_id)
        if rec is None:
            return []

        # ASSUMPTION (M3): Private select() used here because M6's base list() orders by id rather than version asc.
        stmt = (
            select(OrmMemoryVersion)
            .where(
                OrmMemoryVersion.tenant_id == self.tenant_id,
                OrmMemoryVersion.record_id == record_id,
            )
            .order_by(OrmMemoryVersion.version.asc())
            .limit(MAX_PAGE_SIZE)
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return [to_pydantic_memory_version(r) for r in rows]

    async def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        """Fetch a specific version of a record within the bound tenant."""
        self._assert_tenant(tenant_id)
        stmt = (
            select(OrmMemoryVersion)
            .where(
                OrmMemoryVersion.tenant_id == self.tenant_id,
                OrmMemoryVersion.record_id == record_id,
                OrmMemoryVersion.version == version,
            )
            .limit(1)
        )
        row = (await self.session.execute(stmt)).scalar_one_or_none()
        return to_pydantic_memory_version(row) if row is not None else None

    async def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        """Fetch the latest version of a record within the bound tenant using M6's highest_version_for_record helper."""
        self._assert_tenant(tenant_id)
        row = await self._version_repo.highest_version_for_record(record_id)
        return to_pydantic_memory_version(row) if row is not None else None

    async def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        """Persist a provenance edge.

        Rejects self-loops (from_record_id == to_record_id).
        A duplicate edge (violating uq_provenance_edges_tenant_from_to_relation) returns the existing edge idempotently.
        """
        self._assert_tenant(edge.tenant_id)
        if edge.from_record_id == edge.to_record_id:
            raise ValueError(
                f"Self-loop provenance edge is prohibited (from_record_id '{edge.from_record_id}' "
                f"cannot equal to_record_id '{edge.to_record_id}')."
            )

        rel_type = edge.relation_type.value if hasattr(edge.relation_type, "value") else str(edge.relation_type)
        is_duplicate = False

        try:
            async with self.session.begin_nested():
                orm_edge = to_orm_provenance_edge(edge, self.tenant_id)
                self.session.add(orm_edge)
                await self.session.flush()
                return to_pydantic_provenance_edge(orm_edge)
        except IntegrityError as exc:
            err_str = str(exc.orig) if hasattr(exc, "orig") else str(exc)
            if "uq_provenance_edges_tenant_from_to_relation" in err_str or "provenance_edges" in err_str:
                is_duplicate = True
            else:
                raise sanitize_integrity_error(exc)

        if is_duplicate:
            # Query and return the existing edge idempotently
            stmt = (
                select(OrmProvenanceEdge)
                .where(
                    OrmProvenanceEdge.tenant_id == self.tenant_id,
                    OrmProvenanceEdge.from_record_id == edge.from_record_id,
                    OrmProvenanceEdge.to_record_id == edge.to_record_id,
                    OrmProvenanceEdge.relation_type == rel_type,
                )
                .limit(1)
            )
            res = (await self.session.execute(stmt)).scalar_one_or_none()
            if res is not None:
                return to_pydantic_provenance_edge(res)
            raise ValueError("Duplicate edge constraint triggered but existing edge not found.")

        # Fallback return (unreachable under normal control flow)
        return edge  # pragma: no cover

    async def get_edges_for_record(self, record_id: str, tenant_id: str) -> List[ProvenanceEdge]:
        """Fetch all provenance edges connecting from or to a record using M6's edges_for_record helper."""
        self._assert_tenant(tenant_id)
        edge_page = await self._edge_repo.edges_for_record(record_id, limit=MAX_PAGE_SIZE, offset=0)
        return [to_pydantic_provenance_edge(e) for e in edge_page.edges]

    async def get_agent(self, agent_id: str, tenant_id: str) -> Optional[AgentRecord]:
        """Fetch an agent entity by ID within tenant boundary."""
        self._assert_tenant(tenant_id)
        row = await self._agent_repo.get(agent_id)
        return to_pydantic_agent_record(row) if row is not None else None

    async def create_agent(self, agent: AgentRecord) -> AgentRecord:
        """Persist an agent entity."""
        self._assert_tenant(agent.tenant_id)
        try:
            async with self.session.begin_nested():
                orm_agent = to_orm_agent(agent, self.tenant_id)
                self.session.add(orm_agent)
                await self.session.flush()
                return to_pydantic_agent_record(orm_agent)
        except IntegrityError as exc:
            raise sanitize_integrity_error(exc)

    async def get_source(self, source_id: str, tenant_id: str) -> Optional[SourceRecord]:
        """Fetch a knowledge source by ID within tenant boundary."""
        self._assert_tenant(tenant_id)
        row = await self._source_repo.get(source_id)
        return to_pydantic_source_record(row) if row is not None else None

    async def create_source(self, source: SourceRecord) -> SourceRecord:
        """Persist a knowledge source entity."""
        self._assert_tenant(source.tenant_id)
        try:
            async with self.session.begin_nested():
                orm_source = to_orm_source(source, self.tenant_id)
                self.session.add(orm_source)
                await self.session.flush()
                return to_pydantic_source_record(orm_source)
        except IntegrityError as exc:
            raise sanitize_integrity_error(exc)


class DatabaseTransactionalMemoryRepository(MemoryRepository):
    """Transactional session-bound memory repository for multi-entity writes."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator["DatabaseTransactionalMemoryRepository"]:
        yield self

    async def create_record(self, record: MemoryRecord) -> MemoryRecord:
        adapter = SqlAlchemyMemoryRepository(self.session, record.tenant_id)
        return await adapter.create_record(record)

    async def get_record(self, record_id: str, tenant_id: str) -> Optional[MemoryRecord]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_record(record_id, tenant_id)

    async def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        only_trusted: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.list_records(
            tenant_id,
            agent_id=agent_id,
            trust_state=trust_state,
            only_trusted=only_trusted,
            limit=limit,
            offset=offset,
        )

    async def update_record(self, record: MemoryRecord) -> MemoryRecord:
        adapter = SqlAlchemyMemoryRepository(self.session, record.tenant_id)
        return await adapter.update_record(record)

    async def create_version(self, version: MemoryVersion) -> MemoryVersion:
        adapter = SqlAlchemyMemoryRepository(self.session, version.tenant_id)
        return await adapter.create_version(version)

    async def get_versions(self, record_id: str, tenant_id: str) -> List[MemoryVersion]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_versions(record_id, tenant_id)

    async def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_version(record_id, version, tenant_id)

    async def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_latest_version(record_id, tenant_id)

    async def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        adapter = SqlAlchemyMemoryRepository(self.session, edge.tenant_id)
        return await adapter.create_edge(edge)

    async def get_edges_for_record(self, record_id: str, tenant_id: str) -> List[ProvenanceEdge]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_edges_for_record(record_id, tenant_id)

    async def get_agent(self, agent_id: str, tenant_id: str) -> Optional[AgentRecord]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_agent(agent_id, tenant_id)

    async def create_agent(self, agent: AgentRecord) -> AgentRecord:
        adapter = SqlAlchemyMemoryRepository(self.session, agent.tenant_id)
        return await adapter.create_agent(agent)

    async def get_source(self, source_id: str, tenant_id: str) -> Optional[SourceRecord]:
        adapter = SqlAlchemyMemoryRepository(self.session, tenant_id)
        return await adapter.get_source(source_id, tenant_id)

    async def create_source(self, source: SourceRecord) -> SourceRecord:
        adapter = SqlAlchemyMemoryRepository(self.session, source.tenant_id)
        return await adapter.create_source(source)


class DatabaseMemoryRepository(MemoryRepository):
    """Production database memory repository backed by async sessionmaker."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[DatabaseTransactionalMemoryRepository]:
        async with self.session_factory() as session:
            async with session.begin():
                yield DatabaseTransactionalMemoryRepository(session)

    async def create_record(self, record: MemoryRecord) -> MemoryRecord:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).create_record(record)

    async def get_record(self, record_id: str, tenant_id: str) -> Optional[MemoryRecord]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_record(record_id, tenant_id)

    async def list_records(
        self,
        tenant_id: str,
        agent_id: Optional[str] = None,
        trust_state: Optional[str] = None,
        only_trusted: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MemoryRecord]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).list_records(
                tenant_id,
                agent_id=agent_id,
                trust_state=trust_state,
                only_trusted=only_trusted,
                limit=limit,
                offset=offset,
            )

    async def update_record(self, record: MemoryRecord) -> MemoryRecord:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).update_record(record)

    async def create_version(self, version: MemoryVersion) -> MemoryVersion:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).create_version(version)

    async def get_versions(self, record_id: str, tenant_id: str) -> List[MemoryVersion]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_versions(record_id, tenant_id)

    async def get_version(self, record_id: str, version: int, tenant_id: str) -> Optional[MemoryVersion]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_version(record_id, version, tenant_id)

    async def get_latest_version(self, record_id: str, tenant_id: str) -> Optional[MemoryVersion]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_latest_version(record_id, tenant_id)

    async def create_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).create_edge(edge)

    async def get_edges_for_record(self, record_id: str, tenant_id: str) -> List[ProvenanceEdge]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_edges_for_record(record_id, tenant_id)

    async def get_agent(self, agent_id: str, tenant_id: str) -> Optional[AgentRecord]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_agent(agent_id, tenant_id)

    async def create_agent(self, agent: AgentRecord) -> AgentRecord:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).create_agent(agent)

    async def get_source(self, source_id: str, tenant_id: str) -> Optional[SourceRecord]:
        async with self.session_factory() as session:
            return await DatabaseTransactionalMemoryRepository(session).get_source(source_id, tenant_id)

    async def create_source(self, source: SourceRecord) -> SourceRecord:
        async with self.session_factory() as session:
            async with session.begin():
                return await DatabaseTransactionalMemoryRepository(session).create_source(source)
