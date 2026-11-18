"""Tenant-scoped read helpers for memory versions and provenance edges (requested by M3).

Module: backend.app.database.repositories.memory
Owner: M6

Every query is filtered by the repository's tenant, so a record id from another
tenant simply returns nothing. Reads are bounded (GAP-005 "bound database reads";
TRD: default page size 50, maximum 100). These helpers only read and never commit.

What "current" and "highest" mean, and which version is eligible for retrieval,
is decided by M3 (versioning) and M4 (trust). This module only returns rows:
- ``current_version_for_record``: the version that ``memory_records.current_version`` points to;
- ``highest_version_for_record``: the version with the largest version number.
They can differ (for example after a rollback), which is why both exist.
"""

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import or_, select

from backend.app.database.models import MemoryRecord, MemoryVersion, ProvenanceEdge
from backend.app.database.repositories.base import (
    DEFAULT_PAGE_SIZE,
    TenantScopedRepository,
    check_page,
)


def _check_record_id(record_id: str) -> None:
    if not isinstance(record_id, str) or not record_id.strip():
        raise ValueError("record_id must be a non-empty string")


@dataclass(frozen=True)
class EdgePage:
    """One page of edges. ``has_more`` is True when at least one more edge exists after this page."""

    edges: list[ProvenanceEdge]
    has_more: bool
    limit: int
    offset: int


class ProvenanceEdgeRepository(TenantScopedRepository[ProvenanceEdge]):
    model = ProvenanceEdge

    async def edges_for_record(
        self, record_id: str, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0
    ) -> EdgePage:
        """Edges where the record is either end (``from_record_id`` OR ``to_record_id``).

        Ordered by ``id`` for stable paging. Fetches ``limit + 1`` rows to compute
        ``has_more`` without a COUNT query. Direction is returned as stored.
        """
        _check_record_id(record_id)
        check_page(limit, offset)
        stmt = (
            select(ProvenanceEdge)
            .where(
                ProvenanceEdge.tenant_id == self.tenant_id,
                or_(ProvenanceEdge.from_record_id == record_id, ProvenanceEdge.to_record_id == record_id),
            )
            .order_by(ProvenanceEdge.id)
            .limit(limit + 1)
            .offset(offset)
        )
        rows = list((await self.session.execute(stmt)).scalars().all())
        return EdgePage(edges=rows[:limit], has_more=len(rows) > limit, limit=limit, offset=offset)


class MemoryVersionRepository(TenantScopedRepository[MemoryVersion]):
    model = MemoryVersion

    async def current_version_for_record(self, record_id: str) -> Optional[MemoryVersion]:
        """The version ``memory_records.current_version`` points to, or None if the record or version is missing."""
        _check_record_id(record_id)
        stmt = (
            select(MemoryVersion)
            .join(
                MemoryRecord,
                (MemoryRecord.tenant_id == MemoryVersion.tenant_id)
                & (MemoryRecord.id == MemoryVersion.record_id)
                & (MemoryRecord.current_version == MemoryVersion.version),
            )
            .where(MemoryVersion.tenant_id == self.tenant_id, MemoryVersion.record_id == record_id)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def highest_version_for_record(self, record_id: str) -> Optional[MemoryVersion]:
        """The version with the largest version number, or None if the record has no versions."""
        _check_record_id(record_id)
        stmt = (
            select(MemoryVersion)
            .where(MemoryVersion.tenant_id == self.tenant_id, MemoryVersion.record_id == record_id)
            .order_by(MemoryVersion.version.desc())
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()
