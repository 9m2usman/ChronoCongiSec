"""FastAPI router for Memory & Provenance endpoints.

Module: backend.app.api.memory
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 05 Section 5.1 Route Catalog:
- GET  /api/v1/memory      (Query memory records with pagination & strict quarantine exclusion)
- POST /api/v1/memory      (Ingest knowledge chunk & hash)
- GET  /api/v1/memory/{id} (Get memory detail, versions & provenance)

Security & Governance:
- Authenticated Tenant Context: Verified via M1's `get_tenant_context` dependency.
- Mandatory Quarantine Exclusion: Standard agent retrieval strictly excludes QUARANTINED and REJECTED states.
- Bound Pagination: TRD §22 pagination limits enforced (default 50, maximum 100).
- Production Safety: Rejects in-memory repository fallbacks in production.
- Cryptographic Integrity: SHA-256 verified on retrieval and detail endpoints.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.core.config import get_settings
from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import ForbiddenError, NotFoundError, SecurityDependencyError, ValidationError
from backend.app.memory.models import (
    MemoryDetailResponse,
    MemoryIngestRequest,
    MemoryRecordResponse,
)
from backend.app.memory.repository import MemoryRepository, get_default_repository
from backend.app.memory.service import (
    MemoryIntegrityError,
    MemoryNotFoundError,
    get_memory_detail,
    ingest_memory,
    retrieve_memory,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.memory")


# --- Dependencies ---

async def get_memory_tenant_id(
    context: TenantContext = Depends(get_tenant_context),
) -> str:
    """Extract verified tenant_id from M1's authenticated TenantContext.

    Guarantees client-provided X-Tenant-ID headers are never trusted in isolation,
    and request body cannot spoof tenant ownership.
    """
    return context.tenant_id


async def get_repository(request: Request) -> MemoryRepository:
    """Dependency provider for MemoryRepository."""
    settings = getattr(request.app.state, "settings", None) or get_settings()
    repo = getattr(request.app.state, "memory_repo", None)

    if settings.APP_ENV == "production":
        if repo is None or getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
            raise SecurityDependencyError("Production database memory repository is not configured.")
        return repo

    if repo is not None:
        return repo
    return get_default_repository()


router = APIRouter(prefix="/memory", tags=["memory"])


@router.post(
    "",
    response_model=MemoryRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest knowledge chunk & hash",
)
async def api_ingest_memory(
    payload: MemoryIngestRequest,
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryRecordResponse:
    """Ingest a new knowledge chunk, assign version 1, and compute SHA-256 hash.

    Matches Document 05 Section 5.1 Route Catalog.
    Tenant ID is strictly derived from verified authentication context.
    """
    record, version = ingest_memory(
        tenant_id=tenant_id,
        content=payload.content,
        agent_id=payload.agent_id,
        record_type=payload.record_type,
        source_id=payload.source_id,
        parent_record_id=payload.parent_record_id,
        repository=repo,
    )
    return MemoryRecordResponse(
        id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        source_id=record.source_id,
        record_type=record.record_type,
        trust_state=record.trust_state,
        current_version=record.current_version,
        checksum=version.checksum,
        content=version.content,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=List[MemoryRecordResponse],
    status_code=status.HTTP_200_OK,
    summary="Query memory records",
)
async def api_query_memory(
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    trust_state: Optional[str] = Query(None, description="Filter by trust state"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return (1-100, default 50)"),
    offset: int = Query(0, ge=0, description="Number of records to skip (default 0)"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> List[MemoryRecordResponse]:
    """Query memory records with mandatory quarantine filtering and bounded pagination.

    Matches Document 05 Section 5.1 Route Catalog and TRD §22 pagination rules.
    Normal agent retrieval is strictly restricted to TRUSTED memory records.
    UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, and SUPERSEDED records are unconditionally excluded.
    """
    if trust_state and trust_state.upper() != "TRUSTED":
        raise ForbiddenError("Normal agent retrieval is strictly restricted to TRUSTED memory records.")

    records = retrieve_memory(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trust_state="TRUSTED",
        for_forensic=False,
        limit=limit,
        offset=offset,
        repository=repo,
    )

    responses: List[MemoryRecordResponse] = []
    for rec in records:
        latest_ver = repo.get_latest_version(rec.id, tenant_id)
        responses.append(
            MemoryRecordResponse(
                id=rec.id,
                tenant_id=rec.tenant_id,
                agent_id=rec.agent_id,
                source_id=rec.source_id,
                record_type=rec.record_type,
                trust_state=rec.trust_state,
                current_version=rec.current_version,
                checksum=latest_ver.checksum if latest_ver else None,
                content=latest_ver.content if latest_ver else None,
                created_at=rec.created_at,
                updated_at=rec.updated_at,
            )
        )
    return responses


@router.get(
    "/{id}",
    response_model=MemoryDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get memory detail, versions & provenance",
)
async def api_get_memory_detail(
    id: str,
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryDetailResponse:
    """Fetch complete memory detail including full revision history and provenance lineage.

    Normal agent access is strictly restricted to TRUSTED records (returns 404 for non-trusted).
    Forensic access is reserved for authorized M4 investigation workflows.
    """
    record, versions, provenance = get_memory_detail(
        tenant_id=tenant_id,
        record_id=id,
        for_forensic=False,
        allow_quarantined=False,
        repository=repo,
    )

    return MemoryDetailResponse(
        record=record,
        versions=versions,
        provenance=provenance,
    )
