"""Authentication API Endpoints & Request/Response Contracts.

Module: backend.app.api.auth
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 5: Security Architecture
- AMSC-DOC-005 Section 5.1: Route Catalog (POST /auth/login, GET /auth/me)
- Master Implementation Specification: M1 Day 2 Authentication
"""

import re
from typing import Annotated
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field, field_validator

from backend.app.core.config import Settings
from backend.app.core.dependencies import (
    AuthRepoDep,
    CurrentUserDep,
    SettingsDep,
    TenantContextDep,
)
from backend.app.core.exceptions import AuthenticationError, SecurityDependencyError
from backend.app.core.security import (
    create_access_token,
    dummy_verify_password,
    verify_password,
)
from backend.app.tenancy.context import TenantContext, UserRecord

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ============================================================================
# 1. Request and Response Schemas
# ============================================================================

class TenantInfo(BaseModel):
    """Active tenant workspace details in authentication responses."""
    id: str = Field(description="Unique tenant identifier (UUIDv4)")
    name: str = Field(description="Human-readable organization name")
    slug: str = Field(description="URL-safe unique organization slug")


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class LoginRequest(BaseModel):
    """Contract for user login requests matching AMSC-DOC-005 Section 5.1."""
    email: str = Field(
        min_length=3,
        max_length=255,
        description="User email address (normalized case-insensitively)",
    )
    password: str = Field(
        min_length=1,
        max_length=128,
        description="Plaintext password to be verified against Argon2id hash",
    )
    tenant_slug: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Target tenant organization slug",
    )

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Email must be a string.")
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean

    @field_validator("tenant_slug", mode="before")
    @classmethod
    def validate_tenant_slug(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Tenant slug must be a string.")
        clean = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean):
            raise ValueError("Tenant slug must contain only alphanumeric characters, dashes, or underscores.")
        return clean


class LoginResponse(BaseModel):
    """Contract for successful login response matching AMSC-DOC-005 Section 5.1."""
    access_token: str = Field(description="Signed HMAC-SHA256 JWT access token")
    token_type: str = Field(default="bearer", description="OAuth2 token type")
    user_id: str = Field(description="Authenticated user identifier")
    active_tenant: TenantInfo = Field(description="Authorized active tenant workspace")
    role: str = Field(description="User membership role in the active tenant")
    expires_in: int = Field(description="Token validity lifetime in seconds")


class UserProfileResponse(BaseModel):
    """Contract for GET /auth/me profile inspection."""
    user_id: str = Field(description="Authenticated user identifier")
    email: str = Field(description="User email address")
    full_name: str = Field(description="User full name")
    active_tenant: TenantInfo = Field(description="Currently authorized active tenant")
    role: str = Field(description="Membership role in current tenant")


# ============================================================================
# 2. Authentication Route Handlers
# ============================================================================

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate User & Issue Tenant-Scoped JWT",
    description="Authenticates user credentials, validates tenant membership, and returns a signed JWT.",
)
async def login(
    body: LoginRequest,
    repo: AuthRepoDep,
    settings: SettingsDep,
) -> LoginResponse:
    """Execute Day 2 secure authentication flow.

    1. Normalizes email and tenant slug.
    2. Retrieves user from repository.
    3. Verifies password against stored Argon2id hash.
    4. Validates user is ACTIVE.
    5. Retrieves target tenant and verifies status is ACTIVE.
    6. Verifies user holds valid membership in target tenant.
    7. Employs constant-time dummy verification on missing entities to thwart enumeration.
    8. Issues signed JWT with sub, tenant_id, role, and standard claims.
    """
    normalized_email = body.email.strip().lower()
    normalized_slug = body.tenant_slug.strip().lower()

    # Step 1: User retrieval
    try:
        user = await repo.get_user_by_email(normalized_email)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not user:
        dummy_verify_password()
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 2: Password verification
    is_valid_pw = verify_password(body.password, user.hashed_password)
    if not is_valid_pw:
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 3: User status check
    if user.status != "ACTIVE":
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 4: Target tenant retrieval & status check
    try:
        tenant = await repo.get_tenant_by_slug(normalized_slug)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not tenant or tenant.status != "ACTIVE":
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 5: Membership & Role verification
    try:
        membership = await repo.get_membership(user.id, tenant.id)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not membership:
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 6: Issue signed JWT scoped to authorized tenant
    access_token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        role=membership.role,
        settings=settings,
    )

    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=user.id,
        active_tenant=TenantInfo(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
        ),
        role=membership.role,
        expires_in=expires_in_seconds,
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Return Active User & Tenant Profile",
    description="Inspect current authenticated identity, active tenant scope, and assigned role.",
)
async def get_me(
    current_user: CurrentUserDep,
    tenant_context: TenantContextDep,
) -> UserProfileResponse:
    """Return verified user and active tenant context."""
    return UserProfileResponse(
        user_id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        active_tenant=TenantInfo(
            id=tenant_context.tenant_id,
            name=tenant_context.tenant_name,
            slug=tenant_context.tenant_slug,
        ),
        role=tenant_context.role,
    )
