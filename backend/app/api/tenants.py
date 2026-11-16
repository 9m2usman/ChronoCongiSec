"""Tenant Workspace API Endpoints.

Module: backend.app.api.tenants
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-005 Section 5.1: Route Catalog (GET /tenants, GET /tenants/{id})
- Master Implementation Specification: M1 Day 2 Multi-Tenancy
"""

from typing import List
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from backend.app.core.dependencies import (
    AuthRepoDep,
    CurrentUserDep,
    TenantContextDep,
)
from backend.app.core.exceptions import (
    NotFoundError,
    SecurityDependencyError,
    TenantAccessForbiddenError,
)

router = APIRouter(prefix="/tenants", tags=["Tenants"])


class TenantWorkspaceSummary(BaseModel):
    """Summary representation of an authorized tenant organization."""
    id: str = Field(description="Tenant UUIDv4 identifier")
    name: str = Field(description="Organization name")
    slug: str = Field(description="Organization URL slug")
    status: str = Field(description="Tenant operational status")


@router.get(
    "",
    response_model=List[TenantWorkspaceSummary],
    status_code=status.HTTP_200_OK,
    summary="List Authorized Tenant Workspaces",
    description="Returns all active tenant workspaces where the authenticated user holds valid membership.",
)
async def list_user_tenants(
    current_user: CurrentUserDep,
    repo: AuthRepoDep,
) -> List[TenantWorkspaceSummary]:
    """Retrieve tenants accessible to current user."""
    try:
        tenants = await repo.list_user_tenants(current_user.id)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc
    return [
        TenantWorkspaceSummary(
            id=t.id,
            name=t.name,
            slug=t.slug,
            status=t.status,
        )
        for t in tenants
    ]


@router.get(
    "/{tenant_id}",
    response_model=TenantWorkspaceSummary,
    status_code=status.HTTP_200_OK,
    summary="Get Tenant Workspace Details",
    description="Retrieve details of an authorized tenant workspace.",
)
async def get_tenant_details(
    tenant_id: str,
    tenant_context: TenantContextDep,
    repo: AuthRepoDep,
) -> TenantWorkspaceSummary:
    """Retrieve details for a specific tenant, asserting tenant isolation."""
    # Strict multi-tenant isolation: caller cannot query details of another tenant
    if tenant_id != tenant_context.tenant_id:
        raise TenantAccessForbiddenError("Access to other tenant workspaces is prohibited.")

    try:
        tenant = await repo.get_tenant_by_id(tenant_id)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc
    if not tenant:
        raise NotFoundError("Tenant workspace not found.")

    return TenantWorkspaceSummary(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        status=tenant.status,
    )
