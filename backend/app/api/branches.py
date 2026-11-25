"""Branch Management & Scoping API.

Branch visibility is derived from the authenticated membership. A caller-supplied
tenant slug or header is never used to select another tenant's branches.
"""

from typing import List

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from backend.app.core.dependencies import AuthRepoDep, TenantContextDep

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
    summary="List Authorized Branches",
    description=(
        "Returns active branches in the authenticated tenant. Tenant administrators "
        "can view all branches; other employees can view only their assigned branch."
    ),
)
async def list_branches(
    repo: AuthRepoDep,
    context: TenantContextDep,
) -> List[BranchResponse]:
    """List branches without trusting caller-controlled tenant selectors."""
    if context.role != "TENANT_ADMIN":
        if not context.branch_id:
            return []
        branch = await repo.get_branch_by_id(context.tenant_id, context.branch_id)
        branches = [branch] if branch and branch.status == "ACTIVE" else []
    else:
        branches = await repo.list_branches(context.tenant_id)

    return [
        BranchResponse(
            id=branch.id,
            tenant_id=branch.tenant_id,
            name=branch.name,
            code=branch.code,
            status=branch.status,
        )
        for branch in branches
    ]
