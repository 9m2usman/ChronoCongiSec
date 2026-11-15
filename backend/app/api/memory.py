"""FastAPI router for Memory & Provenance endpoints.

Implements Document 05 Section 5.1 Route Catalog:
- GET  /memory      (Query memory records)
- POST /memory      (Ingest knowledge chunk & hash)
- GET  /memory/{id} (Get memory detail, versions & provenance)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from ..memory.models import (
    MemoryDetailResponse,
    MemoryIngestRequest,
    MemoryRecord,
    MemoryRecordResponse,
)
from ..memory.repository import MemoryRepository, get_default_repository
from ..memory.service import (
    MemoryIntegrityError,
    MemoryNotFoundError,
    get_memory_detail,
    ingest_memory,
    retrieve_memory,
)

# ============================================================================
# PLACEHOLDER: Auth & Tenancy Context Dependency (Member M1 Domain)
# ----------------------------------------------------------------------------
# TODO (Member M1): Per docs/02-TRD-SRS.md line 253 (Server-Side Tenant Resolution):
# "Client-provided headers (`X-Tenant-ID`) are never trusted in isolation.
# The server verifies that the authenticated user possesses an active `Membership`
# in the specified tenant before executing any request."
#
# Replace this temporary placeholder with M1's `get_tenant_context` once M1's
# `backend/app/tenancy/context.py` and `backend/app/api/auth.py` are landed.
# ============================================================================
def get_current_tenant_id(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> str:
    """Extract tenant_id from request header or reject with 403 Forbidden.

    To be replaced by M1's authenticated TenantContext verification.
    """
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Missing mandatory X-Tenant-ID header. Valid tenant context required.",
        )
    return x_tenant_id.strip()


def get_repository() -> MemoryRepository:
    """Dependency provider for MemoryRepository."""
    return get_default_repository()


router = APIRouter(prefix="/memory", tags=["memory"])


@router.post(
    "",
    response_model=MemoryRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest knowledge chunk & hash",
)
def api_ingest_memory(
    payload: MemoryIngestRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryRecordResponse:
    """Ingest a new knowledge chunk, assign version 1, and compute SHA-256 hash.

    Matches Document 05 Section 5.1 Route Catalog.
    Tenant ID is strictly sourced from auth/tenant context, never from request body.
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
def api_query_memory(
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    trust_state: Optional[str] = Query(None, description="Filter by trust state"),
    exclude_quarantined: bool = Query(
        True, description="Exclude QUARANTINED records from retrieval"
    ),
    tenant_id: str = Depends(get_current_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> List[MemoryRecordResponse]:
    """Query memory records with optional filters.

    Matches Document 05 Section 5.1 Route Catalog.
    Quarantined records are excluded by default for agent safety (Doc 02 §13).
    Stored checksums are cryptographically re-verified.
    """
    try:
        records = retrieve_memory(
            tenant_id=tenant_id,
            agent_id=agent_id,
            trust_state=trust_state,
            exclude_quarantined=exclude_quarantined,
            repository=repo,
        )
    except MemoryIntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security Alert: {str(e)}",
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
def api_get_memory_detail(
    id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryDetailResponse:
    """Fetch complete memory detail including full revision history and provenance lineage.

    Matches Document 05 Section 5.1 Route Catalog.
    """
    try:
        record, versions, provenance = get_memory_detail(
            tenant_id=tenant_id, record_id=id, repository=repo
        )
    except MemoryNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Memory record '{id}' not found in current tenant scope.",
        )
    except MemoryIntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security Alert: {str(e)}",
        )

    return MemoryDetailResponse(
        record=record,
        versions=versions,
        provenance=provenance,
    )
