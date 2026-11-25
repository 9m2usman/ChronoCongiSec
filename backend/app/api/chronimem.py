"""FastAPI router for ChroniMem temporal version comparison and timeline endpoints.

Module: backend.app.api.chronimem
Owner: M3 — Knowledge & Memory Systems Lead

Registered in main.py via api_router.include_router()

Implements Document 05 Section 5.1 Route Catalog:
- GET /chronimem/timeline (Get temporal version timeline)
- GET /chronimem/records/{id}/compare (Compute diff between two versions)
"""

from datetime import datetime, timezone
import logging
from typing import Any, List, Optional, Union
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel

from backend.app.api.memory import get_memory_tenant_id, get_repository
from backend.app.core.exceptions import NotFoundError
from backend.app.memory.models import TimelineEvent, VersionCompareResponse
from backend.app.memory.repository import MemoryRepository
from backend.app.memory.versioning import compare_versions, get_timeline

logger = logging.getLogger("amsc.api.chronimem")

router = APIRouter(prefix="/chronimem", tags=["chronimem"])


class ChroniMemVersion(BaseModel):
    version: int
    time_display: str
    checksum: str
    author: str
    trust_state: str
    content: str
    created_at: str


class ChroniMemRecordTimelineResponse(BaseModel):
    record_id: str
    tenant_id: str
    current_version: int
    versions: List[ChroniMemVersion]


@router.get(
    "/timeline",
    response_model=Union[ChroniMemRecordTimelineResponse, List[TimelineEvent]],
    status_code=status.HTTP_200_OK,
    summary="Get temporal version timeline",
    description="Fetch temporal version timeline. When record_id is supplied, returns record version history; otherwise returns chronological events.",
)
async def api_get_timeline(
    record_id: Optional[str] = Query(None, description="Fetch version timeline for specific memory record (frontend contract)"),
    agent_id: Optional[str] = Query(None, description="Filter timeline events by agent ID"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of timeline events to return (1-100, default 50)"),
    offset: int = Query(0, ge=0, description="Number of events to skip (default 0)"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> Any:
    """Retrieve temporal version events or record timeline."""
    if record_id:
        record = await repo.get_record(record_id, tenant_id)
        if record is None:
            raise NotFoundError(f"Memory record '{record_id}' not found.")
        trust_val = record.trust_state.value if hasattr(record.trust_state, "value") else str(record.trust_state)
        if trust_val in {"QUARANTINED", "REJECTED"}:
            raise NotFoundError(f"Memory record '{record_id}' not found.")

        versions = await repo.get_versions(record_id, tenant_id)
        formatted_versions: List[ChroniMemVersion] = []
        for v in versions:
            created_str = (
                v.created_at.isoformat()
                if hasattr(v, "created_at") and v.created_at
                else datetime.now(timezone.utc).isoformat()
            )
            time_disp = (
                v.created_at.strftime("%H:%M:%S UTC")
                if hasattr(v, "created_at") and v.created_at
                else "00:00:00 UTC"
            )
            formatted_versions.append(
                ChroniMemVersion(
                    version=v.version,
                    time_display=time_disp,
                    checksum=v.checksum,
                    author=record.agent_id or "system",
                    trust_state=record.trust_state,
                    content=v.content,
                    created_at=created_str,
                )
            )

        return ChroniMemRecordTimelineResponse(
            record_id=record.id,
            tenant_id=record.tenant_id,
            current_version=record.current_version,
            versions=formatted_versions,
        )

    return await get_timeline(
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
    return await compare_versions(
        tenant_id=tenant_id,
        record_id=id,
        v_from=v_from,
        v_to=v_to,
        repository=repo,
    )
