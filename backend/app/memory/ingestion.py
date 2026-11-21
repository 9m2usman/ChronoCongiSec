"""Memory ingestion and provenance lineage establishment.

Module: backend.app.memory.ingestion
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §13 & §15 and Document 05 §5.1 specifications.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from backend.app.core.exceptions import ValidationError
from .integrity import sha256_hex
from .models import (
    MemoryRecord,
    MemoryVersion,
    ProvenanceRelationType,
    TrustState,
)
from .provenance import (
    MAX_PROVENANCE_DEPTH,
    MAX_TRAVERSAL_BUDGET,
    InvalidProvenanceError,
    _check_dag_cycle,
    _get_lineage_depth,
    create_provenance_edge,
)
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError


import inspect



class AwaitableTuple(tuple):
    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


def ingest_memory(
    tenant_id: str,
    content: str,
    agent_id: Optional[str] = None,
    record_type: str = "KNOWLEDGE",
    source_id: Optional[str] = None,
    parent_record_id: Optional[str] = None,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Ingest a new memory chunk.

    Creates a MemoryRecord with trust_state UNVERIFIED (M4 owns trust state transitions)
    and a MemoryVersion with version 1 and cryptographic checksum from sha256_hex.
    Optionally records a DERIVED_FROM provenance edge if parent_record_id is supplied.
    Strictly verifies parent record existence, tenant boundary, and DAG depth/acyclicity.
    Enforces GAP-003: independently verifies agent_id, source_id, and parent ownership.
    Enforces GAP-008: wraps record, initial version, and provenance edge creation in atomic write transaction.
    """
    if content is None or not content.strip():
        raise ValidationError("Memory content must not be empty or whitespace only.")

    repo = repository or get_default_repository()
    now = datetime.now(timezone.utc)
    record_id = str(uuid.uuid4())
    version_id = str(uuid.uuid4())
    checksum = sha256_hex(content)

    def _create_entities():
        record = MemoryRecord(
            id=record_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            source_id=source_id,
            record_type=record_type,
            trust_state=TrustState.UNVERIFIED.value,
            current_version=1,
            created_at=now,
            updated_at=now,
        )
        version = MemoryVersion(
            id=version_id,
            tenant_id=tenant_id,
            record_id=record_id,
            version=1,
            content=content,
            checksum=checksum,
            created_at=now,
        )
        return record, version

    is_async = (
        inspect.iscoroutinefunction(getattr(repo, "create_record", None))
        or inspect.iscoroutinefunction(getattr(repo, "create_version", None))
        or inspect.iscoroutinefunction(getattr(repo, "create_edge", None))
        or inspect.iscoroutinefunction(getattr(repo, "get_record", None))
        or getattr(repo, "is_persistent", False)
    )

    if not is_async:
        if agent_id:
            agent = repo.get_agent(agent_id, tenant_id)
            if not agent or agent.tenant_id != tenant_id:
                raise ValidationError(
                    f"Agent '{agent_id}' does not exist or does not belong to company '{tenant_id}'."
                )
            if agent.status != "ACTIVE":
                raise ValidationError(
                    f"Agent '{agent_id}' is not ACTIVE (status: '{agent.status}'). Ingestion rejected."
                )

        if source_id:
            source = repo.get_source(source_id, tenant_id)
            if not source or source.tenant_id != tenant_id:
                raise ValidationError(
                    f"Source '{source_id}' does not exist or does not belong to company '{tenant_id}'."
                )
            if source.status != "ACTIVE":
                raise ValidationError(
                    f"Source '{source_id}' is not ACTIVE (status: '{source.status}'). Ingestion rejected."
                )

        if parent_record_id:
            parent = repo.get_record(parent_record_id, tenant_id)
            if not parent or parent.tenant_id != tenant_id:
                raise MemoryNotFoundError(
                    f"Parent memory record '{parent_record_id}' not found for tenant '{tenant_id}'. "
                    f"Cross-tenant and nonexistent parent references are strictly prohibited."
                )
            if parent.trust_state in ("QUARANTINED", "REJECTED"):
                raise ValidationError(
                    f"Cannot derive memory from parent record '{parent_record_id}' in '{parent.trust_state}' state."
                )
            _check_dag_cycle(repo, parent_record_id, record_id, tenant_id)
            _get_lineage_depth(repo, parent_record_id, tenant_id)

        record, version = _create_entities()
        with repo.transaction():
            repo.create_record(record)
            repo.create_version(version)
            if parent_record_id:
                create_provenance_edge(
                    tenant_id=tenant_id,
                    from_record_id=parent_record_id,
                    to_record_id=record_id,
                    relation_type=ProvenanceRelationType.DERIVED_FROM.value,
                    repository=repo,
                )
        return AwaitableTuple((record, version))

    async def async_impl():
        if agent_id:
            agent = repo.get_agent(agent_id, tenant_id)
            if inspect.isawaitable(agent):
                agent = await agent
            if not agent or agent.tenant_id != tenant_id:
                raise ValidationError(
                    f"Agent '{agent_id}' does not exist or does not belong to company '{tenant_id}'."
                )
            if agent.status != "ACTIVE":
                raise ValidationError(
                    f"Agent '{agent_id}' is not ACTIVE (status: '{agent.status}'). Ingestion rejected."
                )

        if source_id:
            source = repo.get_source(source_id, tenant_id)
            if inspect.isawaitable(source):
                source = await source
            if not source or source.tenant_id != tenant_id:
                raise ValidationError(
                    f"Source '{source_id}' does not exist or does not belong to company '{tenant_id}'."
                )
            if source.status != "ACTIVE":
                raise ValidationError(
                    f"Source '{source_id}' is not ACTIVE (status: '{source.status}'). Ingestion rejected."
                )

        if parent_record_id:
            parent = repo.get_record(parent_record_id, tenant_id)
            if inspect.isawaitable(parent):
                parent = await parent
            if not parent or parent.tenant_id != tenant_id:
                raise MemoryNotFoundError(
                    f"Parent memory record '{parent_record_id}' not found for tenant '{tenant_id}'. "
                    f"Cross-tenant and nonexistent parent references are strictly prohibited."
                )
            if parent.trust_state in ("QUARANTINED", "REJECTED"):
                raise ValidationError(
                    f"Cannot derive memory from parent record '{parent_record_id}' in '{parent.trust_state}' state."
                )
            res = _check_dag_cycle(repo, parent_record_id, record_id, tenant_id)
            if inspect.isawaitable(res):
                await res
            res = _get_lineage_depth(repo, parent_record_id, tenant_id)
            if inspect.isawaitable(res):
                await res

        record, version = _create_entities()
        async with repo.transaction():
            res = repo.create_record(record)
            if inspect.isawaitable(res):
                await res
            res = repo.create_version(version)
            if inspect.isawaitable(res):
                await res
            if parent_record_id:
                res = create_provenance_edge(
                    tenant_id=tenant_id,
                    from_record_id=parent_record_id,
                    to_record_id=record_id,
                    relation_type=ProvenanceRelationType.DERIVED_FROM.value,
                    repository=repo,
                )
                if inspect.isawaitable(res):
                    await res
        return (record, version)

    return async_impl()


__all__ = [
    "ingest_memory",
    "create_provenance_edge",
    "InvalidProvenanceError",
    "MAX_PROVENANCE_DEPTH",
    "MAX_TRAVERSAL_BUDGET",
    "_check_dag_cycle",
    "_get_lineage_depth",
]
