"""FastAPI router for ChroniMem temporal version comparison and timeline endpoints.

Module: backend.app.api.chronimem
Owner: M3 — Knowledge & Memory Systems Lead

Not yet registered in main.py: M1 to add app.include_router(...)

Implements Document 05 Section 5.1 Route Catalog:
- GET /chronimem/timeline (Get temporal version timeline)
- GET /chronimem/records/{id}/compare (Compute diff between two versions)
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status

from backend.app.api.memory import get_memory_tenant_id, get_repository
from backend.app.memory.models import TimelineEvent, VersionCompareResponse
from backend.app.memory.repository import MemoryRepository
from backend.app.memory.versioning import compare_versions, get_timeline

logger = logging.getLogger("amsc.api.chronimem")

router = APIRouter(prefix="/chronimem", tags=["chronimem"])


@router.get(
    "/timeline",
    response_model=List[TimelineEvent],
    status_code=status.HTTP_200_OK,
    summary="Get temporal version timeline",
)
async def api_get_timeline(
    agent_id: Optional[str] = Query(None, description="Filter timeline events by agent ID"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of timeline events to return (1-100, default 50)"),
    offset: int = Query(0, ge=0, description="Number of events to skip (default 0)"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> List[TimelineEvent]:
    """Retrieve temporal version events ordered by created_at then version."""
    return get_timeline(
        tenant_id=tenant_id,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
        repository=repo,
    )


@router.get(
    "/records/{id}/compare",
    response_model=VersionCompareResponse,
    status_code=status.HTTP_200_OK,
    summary="Compute diff between two versions",
)
async def api_compare_versions(
    id: str,
    v_from: int = Query(..., ge=1, description="Source baseline version number"),
    v_to: int = Query(..., ge=1, description="Target updated version number"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> VersionCompareResponse:
    """Compute unified diff and added/removed line annotations between two memory versions."""
    return compare_versions(
        tenant_id=tenant_id,
        record_id=id,
        v_from=v_from,
        v_to=v_to,
        repository=repo,
    )
