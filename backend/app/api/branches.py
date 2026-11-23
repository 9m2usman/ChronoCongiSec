"""Branch Management & Scoping API.

Module: backend.app.api.branches
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- PRD FR-001, FR-003: Multi-tenant and branch authorization
- AMSC Phase 1: Canonical Enterprise Branches (HO, LHR, KHI, ISB)
"""

from typing import List, Optional
from fastapi import APIRouter, Request, status
from pydantic import BaseModel, Field

from backend.app.core.dependencies import AuthRepoDep, SettingsDep

router = APIRouter(prefix="/branches", tags=["Branches"])


class BranchResponse(BaseModel):
    id: str = Field(description="Unique branch identifier")
    tenant_id: str = Field(description="Tenant company identifier")
    name: str = Field(description="Branch office name")
    code: str = Field(description="Short code (e.g., HO, LHR, KHI, ISB)")
    status: str = Field(description="Branch status")


@router.get(
    "",
    response_model=List[BranchResponse],
    status_code=status.HTTP_200_OK,
    summary="List Active Branches",
    description="Returns active branches for the enterprise company workspace.",
)
async def list_branches(
    request: Request,
    repo: AuthRepoDep,
    settings: SettingsDep,
    tenant_slug: Optional[str] = None,
) -> List[BranchResponse]:
    target_slug = tenant_slug or request.headers.get("X-Tenant-Slug") or "alphacorp"
    tenant = await repo.get_tenant_by_slug(target_slug)
    if not tenant or tenant.status != "ACTIVE":
        return []

    branches = await repo.list_branches(tenant.id)
    return [
        BranchResponse(
            id=b.id,
            tenant_id=b.tenant_id,
            name=b.name,
            code=b.code,
            status=b.status,
        )
        for b in branches
    ]
