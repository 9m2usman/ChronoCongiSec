"""Tenant Administration and IAM Governance Endpoints.

Module: backend.app.api.admin
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC PRD FR-001, FR-002, FR-003
- AMSC Phase 1: Identity & Access Management Governance
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field

from backend.app.api.audit import record_audit_event

from backend.app.core.dependencies import (
    AuthRepoDep,
    CurrentUserDep,
)
from backend.app.core.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
)
from backend.app.database.models.identity import MEMBERSHIP_STATUSES
from backend.app.security.authorization import Role, require_role_access
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/admin", tags=["Tenant Administration"])


# ============================================================================
# 1. Schemas
# ============================================================================

class RegistrationRequestDetailResponse(BaseModel):
    id: str
    tenant_id: str
    full_name: str
    email: str
    requested_branch_code: str
    status: str
    created_at: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by_user_id: Optional[str] = None
    review_reason: Optional[str] = None
    assigned_role: Optional[str] = None
    assigned_branch_id: Optional[str] = None


class ApproveRegistrationRequest(BaseModel):
    role: Role = Field(description="Assigned role: TENANT_ADMIN, SECURITY_ANALYST, AI_DEVELOPER, AUDITOR")
    branch_id: Optional[str] = Field(default=None, description="Assigned branch identifier (None for company-wide)")
    reason: Optional[str] = Field(default=None, max_length=500, description="Administrative rationale")

    model_config = {"extra": "forbid"}


class ApproveRegistrationResponse(BaseModel):
    message: str = "Employee registration request approved successfully."
    user_id: str
    membership_id: str
    role: str
    branch_id: Optional[str] = None


class RejectRegistrationRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500, description="Rejection reason")

    model_config = {"extra": "forbid"}


class RejectRegistrationResponse(BaseModel):
    message: str = "Employee registration request rejected."
    request_id: str


class TenantMemberResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: str
    branch_id: Optional[str] = None
    branch_name: Optional[str] = None
    branch_code: Optional[str] = None
    status: str


class UpdateMemberRequest(BaseModel):
    role: Optional[Role] = None
    branch_id: Optional[str] = None
    status: Optional[str] = None

    model_config = {"extra": "forbid"}


class UpdateMemberResponse(BaseModel):
    message: str = "Member settings updated successfully."
    user_id: str
    role: str
    branch_id: Optional[str] = None
    status: str


# ============================================================================
# 2. Audit Helper
# ============================================================================

async def _audit_admin_action(
    request: Request,
    tenant_id: str,
    actor_id: str,
    action: str,
    resource_id: str,
    details: Dict[str, Any],
) -> None:
    """Audit recording for administrative IAM actions."""
    await record_audit_event(
        request=request,
        tenant_id=tenant_id,
        actor_id=actor_id,
        event_type="IAM_ADMIN_ACTION",
        action=action,
        resource_id=resource_id,
        outcome="SUCCESS",
        details=details,
    )


# ============================================================================
# 3. Route Handlers (Protected: TENANT_ADMIN only)
# ============================================================================

@router.get(
    "/registrations",
    response_model=List[RegistrationRequestDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="List Employee Registration Requests",
    description="Returns registration requests for the admin's tenant organization.",
)
async def list_registration_requests(
    request: Request,
    repo: AuthRepoDep,
    tenant_context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN)),
    status_filter: Optional[str] = None,
) -> List[RegistrationRequestDetailResponse]:
    try:
        reqs = await repo.list_registration_requests(tenant_context.tenant_id, status=status_filter)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    return [
        RegistrationRequestDetailResponse(
            id=r.id,
            tenant_id=r.tenant_id,
            full_name=r.full_name,
            email=r.email,
            requested_branch_code=r.requested_branch_code,
            status=r.status,
            created_at=r.created_at,
            reviewed_at=r.reviewed_at,
            reviewed_by_user_id=r.reviewed_by_user_id,
            review_reason=r.review_reason,
            assigned_role=r.assigned_role,
            assigned_branch_id=r.assigned_branch_id,
        )
        for r in reqs
    ]


@router.post(
    "/registrations/{request_id}/approve",
    response_model=ApproveRegistrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve Employee Registration Request",
    description="Approves a pending registration request and assigns role and branch.",
)
async def approve_registration(
    request_id: str,
    body: ApproveRegistrationRequest,
    request: Request,
    current_user: CurrentUserDep,
    repo: AuthRepoDep,
    tenant_context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN)),
) -> ApproveRegistrationResponse:
    # 1. Fetch request
    reg_req = await repo.get_registration_request_by_id(request_id)
    if not reg_req or reg_req.tenant_id != tenant_context.tenant_id:
        raise NotFoundError("Registration request not found.")

    if reg_req.status != "PENDING":
        raise BadRequestError(f"Cannot approve request with status '{reg_req.status}'. Must be PENDING.")

    # 2. Prevent self-approval (if email matches current admin)
    if reg_req.email.strip().lower() == current_user.email.strip().lower():
        raise ForbiddenError("Administrators cannot approve their own registration requests.")

    # 3. Validate branch if supplied
    if body.branch_id:
        branch = await repo.get_branch_by_id(tenant_context.tenant_id, body.branch_id)
        if not branch:
            raise BadRequestError(f"Branch '{body.branch_id}' not found in current company workspace.")

    # 4. Transactional approval
    try:
        user, mem = await repo.approve_registration_request(
            request_id=request_id,
            admin_user_id=current_user.id,
            assigned_role=body.role.value,
            assigned_branch_id=body.branch_id,
            reason=body.reason,
        )
    except ValueError as exc:
        raise BadRequestError(str(exc))
    except Exception as exc:
        raise SecurityDependencyError("Failed to persist registration approval.") from exc

    # 5. Audit
    await _audit_admin_action(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=f"user:{current_user.id}",
        action="REGISTRATION_APPROVED",
        resource_id=user.id,
        details={
            "request_id": request_id,
            "approved_user_email": user.email,
            "assigned_role": body.role.value,
            "assigned_branch_id": body.branch_id,
            "reason": body.reason,
        },
    )

    return ApproveRegistrationResponse(
        user_id=user.id,
        membership_id=mem.id,
        role=mem.role,
        branch_id=mem.branch_id,
    )


@router.post(
    "/registrations/{request_id}/reject",
    response_model=RejectRegistrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject Employee Registration Request",
    description="Rejects a pending registration request with mandatory administrative reason.",
)
async def reject_registration(
    request_id: str,
    body: RejectRegistrationRequest,
    request: Request,
    current_user: CurrentUserDep,
    repo: AuthRepoDep,
    tenant_context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN)),
) -> RejectRegistrationResponse:
    reg_req = await repo.get_registration_request_by_id(request_id)
    if not reg_req or reg_req.tenant_id != tenant_context.tenant_id:
        raise NotFoundError("Registration request not found.")

    if reg_req.status != "PENDING":
        raise BadRequestError(f"Cannot reject request with status '{reg_req.status}'. Must be PENDING.")

    try:
        updated = await repo.reject_registration_request(
            request_id=request_id,
            admin_user_id=current_user.id,
            reason=body.reason,
        )
    except ValueError as exc:
        raise BadRequestError(str(exc))
    except Exception as exc:
        raise SecurityDependencyError("Failed to persist registration rejection.") from exc

    await _audit_admin_action(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=f"user:{current_user.id}",
        action="REGISTRATION_REJECTED",
        resource_id=request_id,
        details={
            "rejected_email": reg_req.email,
            "reason": body.reason,
        },
    )

    return RejectRegistrationResponse(request_id=updated.id)


@router.get(
    "/users",
    response_model=List[TenantMemberResponse],
    status_code=status.HTTP_200_OK,
    summary="List Organization Members",
    description="Returns all users and memberships in the active company workspace.",
)
async def list_tenant_members(
    repo: AuthRepoDep,
    tenant_context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN)),
) -> List[TenantMemberResponse]:
    try:
        members = await repo.list_tenant_members(tenant_context.tenant_id)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    return [
        TenantMemberResponse(
            user_id=m["user_id"],
            email=m["email"],
            full_name=m["full_name"],
            role=m["role"],
            branch_id=m.get("branch_id"),
            branch_name=m.get("branch_name"),
            branch_code=m.get("branch_code"),
            status=m["status"],
        )
        for m in members
    ]


@router.patch(
    "/users/{user_id}/membership",
    response_model=UpdateMemberResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Member Role, Branch or Status",
    description="Updates role, branch, or status for a tenant membership (e.g. SUSPEND or REVOKE).",
)
async def update_member_membership(
    user_id: str,
    body: UpdateMemberRequest,
    request: Request,
    current_user: CurrentUserDep,
    repo: AuthRepoDep,
    tenant_context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN)),
) -> UpdateMemberResponse:
    if body.status and body.status not in MEMBERSHIP_STATUSES:
        raise BadRequestError(f"Invalid status '{body.status}'. Must be one of {MEMBERSHIP_STATUSES}.")

    if body.branch_id:
        branch = await repo.get_branch_by_id(tenant_context.tenant_id, body.branch_id)
        if not branch:
            raise BadRequestError(f"Branch '{body.branch_id}' not found in current company workspace.")

    try:
        mem = await repo.update_member(
            tenant_id=tenant_context.tenant_id,
            user_id=user_id,
            role=body.role.value if body.role else None,
            branch_id=body.branch_id,
            status=body.status,
        )
    except ValueError as exc:
        raise NotFoundError(str(exc))
    except Exception as exc:
        raise SecurityDependencyError("Failed to update member.") from exc

    # If suspended or revoked, revoke all active sessions for this user in this tenant immediately
    if body.status in ("SUSPENDED", "REVOKED"):
        revocation_store = getattr(request.app.state, "revocation_store", None)
        if revocation_store is not None:
            await revocation_store.revoke_user_sessions(
                user_id=user_id,
                tenant_id=tenant_context.tenant_id,
                reason=f"Membership status changed to {body.status}",
            )

    await _audit_admin_action(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=f"user:{current_user.id}",
        action="MEMBERSHIP_MODIFIED",
        resource_id=user_id,
        details={
            "role": body.role.value if body.role else None,
            "branch_id": body.branch_id,
            "status": body.status,
        },
    )

    return UpdateMemberResponse(
        user_id=user_id,
        role=mem.role,
        branch_id=mem.branch_id,
        status=mem.status,
    )
