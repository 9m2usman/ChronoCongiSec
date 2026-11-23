"""Authentication API Endpoints & Request/Response Contracts.

Module: backend.app.api.auth
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 5: Security Architecture
- AMSC-DOC-005 Section 5.1: Route Catalog (POST /auth/login, GET /auth/me)
- Master Implementation Specification: M1 Day 2 Authentication
"""

import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Request, status
from pydantic import BaseModel, Field, field_validator

from backend.app.api.audit import record_audit_event
from backend.app.core.config import Settings
from backend.app.core.dependencies import (
    AuthRepoDep,
    CurrentUserDep,
    RateLimiterDep,
    SettingsDep,
    TenantContextDep,
)
from backend.app.core.exceptions import (
    AuthenticationError,
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitExceededError,
    SecurityDependencyError,
)
from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    dummy_verify_password_async,
    hash_password,
    verify_password_async,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def is_trusted_proxy(ip_str: str, trusted_proxies: list[str]) -> bool:
    """Determine whether an IP address matches any trusted proxy definition (IP or CIDR)."""
    import ipaddress
    try:
        client_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    for trusted in trusted_proxies:
        trusted_clean = trusted.strip()
        if not trusted_clean:
            continue
        try:
            if "/" in trusted_clean:
                if client_obj in ipaddress.ip_network(trusted_clean, strict=False):
                    return True
            else:
                if client_obj == ipaddress.ip_address(trusted_clean):
                    return True
        except ValueError:
            if ip_str.strip() == trusted_clean:
                return True
    return False


def get_client_ip(request: Request, settings: Settings) -> str:
    """Extract client IP address with strict trusted proxy validation.

    CRITICAL SECURITY REQUIREMENT:
    Do NOT blindly trust X-Forwarded-For or other forwarded headers from arbitrary clients.
    Forwarded headers are only evaluated when the direct connection originates from an
    explicitly configured trusted proxy in settings.TRUSTED_PROXIES.

    When requests pass through trusted proxies, traverse X-Forwarded-For from right to left,
    skipping trusted intermediaries, to find the true client IP (RFC 7239 / standard reverse proxy handling).
    """
    direct_ip = request.client.host if request.client else "127.0.0.1"
    if settings.TRUSTED_PROXIES and is_trusted_proxy(direct_ip, settings.TRUSTED_PROXIES):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ips = [p.strip() for p in forwarded.split(",") if p.strip()]
            # Walk right-to-left: the first IP that is NOT a trusted proxy is the real client
            for ip in reversed(ips):
                if not is_trusted_proxy(ip, settings.TRUSTED_PROXIES):
                    return ip
            # If all forwarded IPs are trusted proxies, fall back to the first hop
            if ips:
                return ips[0]
    return direct_ip


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
    branch_id: Optional[str] = Field(default=None, description="Authorized branch context (None for company-wide)")
    expires_in: int = Field(description="Token validity lifetime in seconds")


class UserProfileResponse(BaseModel):
    """Contract for GET /auth/me profile inspection."""
    user_id: str = Field(description="Authenticated user identifier")
    email: str = Field(description="User email address")
    full_name: str = Field(description="User full name")
    active_tenant: TenantInfo = Field(description="Currently authorized active tenant")
    role: str = Field(description="Membership role in current tenant")
    branch_id: Optional[str] = Field(default=None, description="Authorized branch context (None for company-wide)")


class LogoutResponse(BaseModel):
    """Contract for POST /auth/logout session revocation (GAP-007)."""
    message: str = Field(
        default="Successfully logged out. Session has been revoked.",
        description="Confirmation message",
    )


class RegisterRequest(BaseModel):
    """Contract for employee self-registration request (Phase 1 IAM)."""
    full_name: str = Field(min_length=2, max_length=255, description="Full name of employee")
    email: str = Field(min_length=3, max_length=255, description="Work email address")
    password: str = Field(min_length=8, max_length=128, description="Password (at least 8 characters)")
    requested_branch_code: str = Field(min_length=2, max_length=32, description="Target branch code (e.g., HO, LHR, KHI, ISB)")
    tenant_slug: str = Field(default="alphacorp", min_length=1, max_length=64, description="Target company slug")

    model_config = {"extra": "forbid"}

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Email must be a string.")
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean

    @field_validator("requested_branch_code", mode="before")
    @classmethod
    def validate_branch_code(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Branch code must be a string.")
        clean = v.strip().upper()
        if not clean:
            raise ValueError("Branch code cannot be empty.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v


class RegisterResponse(BaseModel):
    """Response returned upon submitting an employee registration request."""
    request_id: str = Field(description="Unique tracking ID for the registration request")
    email: str = Field(description="Submitted email address")
    status: str = Field(default="PENDING", description="Registration request status")
    requested_branch_code: str = Field(description="Requested branch code")
    created_at: str = Field(description="Timestamp of request submission")
    message: str = Field(
        default="Employee registration request submitted. A Tenant Administrator must review and approve your account before you can log in.",
        description="Status instructions for employee",
    )


class RegistrationStatusResponse(BaseModel):
    """Safe status response for checking registration progress without leaking sensitive data."""
    request_id: str = Field(description="Registration request identifier")
    email_masked: str = Field(description="Masked employee email address")
    status: str = Field(description="Current registration status (PENDING, APPROVED, REJECTED)")
    requested_branch_code: str = Field(description="Requested branch code")
    created_at: Optional[str] = Field(default=None, description="Request creation timestamp")
    reviewed_at: Optional[str] = Field(default=None, description="Review decision timestamp")
    reason: Optional[str] = Field(default=None, description="Administrative decision rationale if rejected")


class BootstrapAdminRequest(BaseModel):
    """Payload for provisioning the initial Tenant Administrator."""
    tenant_slug: str = Field(default="alphacorp", min_length=1, max_length=64, description="Target company slug")
    admin_email: str = Field(min_length=3, max_length=255, description="Administrator email address")
    admin_full_name: str = Field(min_length=2, max_length=255, description="Administrator full name")
    password: str = Field(min_length=8, max_length=128, description="Initial administrator password")

    model_config = {"extra": "forbid"}

    @field_validator("admin_email", mode="before")
    @classmethod
    def validate_admin_email(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Email must be a string.")
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean


class BootstrapAdminResponse(BaseModel):
    message: str = "Tenant administrator account successfully bootstrapped."
    tenant_slug: str
    admin_email: str
    role: str = "TENANT_ADMIN"


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
    request: Request,
    repo: AuthRepoDep,
    rate_limiter: RateLimiterDep,
    settings: SettingsDep,
) -> LoginResponse:
    """Execute Day 2 secure authentication flow with rate limiting.

    1. Applies source-IP and account-based rate limiting via M7 protocol.
    2. Normalizes email and tenant slug.
    3. Retrieves user from repository.
    4. Verifies password against stored Argon2id hash.
    5. Validates user is ACTIVE.
    6. Retrieves target tenant and verifies status is ACTIVE.
    7. Verifies user holds valid membership in target tenant.
    8. Employs constant-time dummy verification on missing entities to thwart enumeration.
    9. Issues signed JWT with sub, tenant_id, role, and standard claims.
    """
    normalized_email = body.email.strip().lower()
    normalized_slug = body.tenant_slug.strip().lower()

    # Rate Limiting: 1. Source IP throttling with trusted proxy validation
    client_ip = get_client_ip(request, settings)
    try:
        ip_check = await rate_limiter.check_rate_limit(
            key=f"login:ip:{client_ip}",
            max_requests=settings.LOGIN_RATE_LIMIT_IP_MAX_REQUESTS,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
    except SecurityDependencyError:
        if settings.RATE_LIMIT_REDIS_FAILURE_POLICY == "fail_closed":
            raise
        ip_check = None

    if ip_check is not None and not ip_check.allowed:
        raise RateLimitExceededError(
            message="Too many login attempts from this network address. Please try again later.",
            retry_after=ip_check.retry_after,
        )

    # Rate Limiting: 2. Target account throttling using keyed HMAC (GAP-009 / Finding C)
    # Uses keyed HMAC-SHA256 to prevent rainbow tables and offline guessing if keys are exposed,
    # and combines account-plus-IP throttling with a tiered global account limit to protect against
    # distributed brute-force attacks without allowing attackers to deny service to legitimate users.
    hmac_key = getattr(settings, "RATE_LIMIT_HMAC_SECRET", None) or settings.JWT_SECRET
    account_raw = f"{normalized_email}:{normalized_slug}".encode("utf-8")
    account_hmac = hmac.new(hmac_key.encode("utf-8"), account_raw, hashlib.sha256).hexdigest()

    # 2a. Global account-wide rate limit across all source IPs (DoS mitigation tier)
    global_account_max = getattr(settings, "LOGIN_RATE_LIMIT_GLOBAL_ACCOUNT_MAX_REQUESTS", None)
    if global_account_max is None:
        global_account_max = max(settings.LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS * 3, 10)

    global_account_key = f"login:account:global:{account_hmac}"
    try:
        global_check = await rate_limiter.check_rate_limit(
            key=global_account_key,
            max_requests=global_account_max,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
    except SecurityDependencyError:
        if settings.RATE_LIMIT_REDIS_FAILURE_POLICY == "fail_closed":
            raise
        global_check = None

    if global_check is not None and not global_check.allowed:
        raise RateLimitExceededError(
            message="Too many login attempts for this account. Please try again later.",
            retry_after=global_check.retry_after,
        )

    # 2b. Account-plus-IP throttling: enforces per-account limit for this client IP
    acct_ip_key = f"login:account:{client_ip}:{account_hmac}"
    try:
        acct_ip_check = await rate_limiter.check_rate_limit(
            key=acct_ip_key,
            max_requests=settings.LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
    except SecurityDependencyError:
        if settings.RATE_LIMIT_REDIS_FAILURE_POLICY == "fail_closed":
            raise
        acct_ip_check = None

    if acct_ip_check is not None and not acct_ip_check.allowed:
        raise RateLimitExceededError(
            message="Too many login attempts for this account. Please try again later.",
            retry_after=acct_ip_check.retry_after,
        )

    async def _fail_auth(target_tenant: Optional[Any] = None) -> None:
        t_id = getattr(target_tenant, "id", None) or "unknown"
        await record_audit_event(
            request=request,
            tenant_id=t_id,
            actor_id=f"anonymous:{client_ip}",
            event_type="IAM_AUTHENTICATION",
            action="LOGIN_FAILED",
            resource_id=normalized_email,
            outcome="FAILURE",
            details={"email": normalized_email, "tenant_slug": normalized_slug},
        )
        raise AuthenticationError("Invalid email, password, or tenant access.")

    # Step 1: User retrieval
    try:
        user = await repo.get_user_by_email(normalized_email)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not user:
        await dummy_verify_password_async(
            max_concurrency=settings.AUTH_MAX_CONCURRENT_VERIFICATIONS
        )
        await _fail_auth()

    # Step 2: Password verification (bounded async thread pool to keep event loop responsive)
    is_valid_pw = await verify_password_async(
        body.password,
        user.hashed_password,
        max_concurrency=settings.AUTH_MAX_CONCURRENT_VERIFICATIONS,
    )
    if not is_valid_pw:
        await _fail_auth()

    # Step 3: User status check
    if user.status != "ACTIVE":
        await _fail_auth()

    # Step 4: Target tenant retrieval & status check
    try:
        tenant = await repo.get_tenant_by_slug(normalized_slug)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not tenant or tenant.status != "ACTIVE":
        await _fail_auth(tenant)

    # Step 5: Membership & Role verification (guarantee membership is ACTIVE and not revoked/suspended)
    try:
        membership = await repo.get_membership(user.id, tenant.id)
    except Exception as exc:
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not membership:
        await _fail_auth(tenant)

    mem_status = getattr(membership, "status", None)
    if mem_status is None or str(mem_status).strip().upper() != "ACTIVE":
        await _fail_auth(tenant)

    branch_id = getattr(membership, "branch_id", None)
    additional_claims = {"branch_id": branch_id} if branch_id else None

    # Step 6: Issue signed JWT scoped to authorized tenant
    access_token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        role=membership.role,
        settings=settings,
        additional_claims=additional_claims,
    )

    # Step 7: Audit login success
    await record_audit_event(
        request=request,
        tenant_id=tenant.id,
        actor_id=f"user:{user.id}",
        event_type="IAM_AUTHENTICATION",
        action="LOGIN_SUCCESS",
        resource_id=user.id,
        outcome="SUCCESS",
        details={"email": user.email, "role": membership.role, "branch_id": branch_id},
    )

    # Step 7: Reset account-plus-IP counter on successful login so legitimate users are not penalized
    try:
        if hasattr(rate_limiter, "reset"):
            await rate_limiter.reset(acct_ip_key)
    except Exception:
        pass

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
        branch_id=branch_id,
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
        branch_id=tenant_context.branch_id,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke Current User Session & Invalidate Token",
    description="Revokes the authenticated JWT jti in the persistent revocation store (GAP-007 / Finding B).",
)
async def logout(
    request: Request,
    tenant_context: TenantContextDep,
    settings: SettingsDep,
) -> LogoutResponse:
    """Revoke authenticated session token (GAP-007)."""
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.strip().split(" ", 1)
    token = parts[1].strip() if len(parts) == 2 else ""
    if token:
        payload = decode_access_token(token, settings=settings)
        jti = payload.get("jti")
        exp = payload.get("exp", int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp()))
        revocation_store = getattr(request.app.state, "revocation_store", None)
        if revocation_store is not None and jti:
            await revocation_store.revoke_token(jti=jti, expires_at=exp, reason="User logout")

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=f"user:{tenant_context.user_id}",
        event_type="IAM_AUTHENTICATION",
        action="LOGOUT",
        resource_id=tenant_context.user_id,
        outcome="SUCCESS",
        details={"tenant_id": tenant_context.tenant_id},
    )
    return LogoutResponse()


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Employee Registration Request",
    description="Allows prospective employees to submit registration requests. Requires Tenant Admin approval before login.",
)
async def register_employee(
    body: RegisterRequest,
    request: Request,
    repo: AuthRepoDep,
    rate_limiter: RateLimiterDep,
    settings: SettingsDep,
) -> RegisterResponse:
    """Submit an employee self-registration request (Phase 1 IAM)."""
    client_ip = get_client_ip(request, settings)

    # Rate Limiting on public registration
    try:
        ip_check = await rate_limiter.check_rate_limit(
            key=f"register:ip:{client_ip}",
            max_requests=settings.LOGIN_RATE_LIMIT_IP_MAX_REQUESTS,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
    except SecurityDependencyError:
        if settings.RATE_LIMIT_REDIS_FAILURE_POLICY == "fail_closed":
            raise
        ip_check = None

    if ip_check is not None and not ip_check.allowed:
        raise RateLimitExceededError(
            message="Too many registration attempts from this address. Please try again later.",
            retry_after=ip_check.retry_after,
        )

    # 1. Tenant validation
    tenant = await repo.get_tenant_by_slug(body.tenant_slug)
    if not tenant or tenant.status != "ACTIVE":
        raise BadRequestError("Target company workspace not found or is inactive.")

    # 2. Branch code validation
    branch = await repo.get_branch_by_code(tenant.id, body.requested_branch_code)
    if not branch:
        raise BadRequestError(
            f"Branch code '{body.requested_branch_code}' does not exist for this company. "
            "Please select a valid branch (e.g. HO, LHR, KHI, ISB)."
        )

    # 3. Check for existing active account
    existing_user = await repo.get_user_by_email(body.email)
    if existing_user:
        raise BadRequestError("An account with this email address already exists. Please log in.")

    # 4. Check for existing pending request
    pending = await repo.list_registration_requests(tenant.id, status="PENDING")
    if any(r.email.lower() == body.email.lower() for r in pending):
        raise BadRequestError(
            "A pending registration request for this email address already exists. "
            "Please wait for an administrator to review it."
        )

    # 5. Hash password and persist request
    pw_hash = hash_password(body.password)
    req_record = await repo.create_registration_request(
        tenant_id=tenant.id,
        full_name=body.full_name.strip(),
        email=body.email.strip().lower(),
        hashed_password=pw_hash,
        requested_branch_code=body.requested_branch_code.strip().upper(),
    )

    created_iso = req_record.created_at or datetime.now(timezone.utc).isoformat()

    # 6. Audit registration request submission
    await record_audit_event(
        request=request,
        tenant_id=tenant.id,
        actor_id=f"anonymous:{client_ip}",
        event_type="IAM_REGISTRATION",
        action="REGISTRATION_REQUEST_SUBMITTED",
        resource_id=req_record.id,
        outcome="SUCCESS",
        details={"email": req_record.email, "requested_branch_code": req_record.requested_branch_code},
    )

    return RegisterResponse(
        request_id=req_record.id,
        email=req_record.email,
        status="PENDING",
        requested_branch_code=req_record.requested_branch_code,
        created_at=created_iso,
    )


def mask_email(email: str) -> str:
    """Mask email for privacy in public status responses: j***e@example.com."""
    parts = email.split("@")
    if len(parts) != 2:
        return "***"
    local, domain = parts
    if not local:
        return f"***@{domain}"
    if len(local) <= 2:
        masked_local = local[0] + "***"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"


@router.get(
    "/registration-status/{request_id}",
    response_model=RegistrationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Check Employee Registration Request Status",
    description="Public status check for a pending or reviewed registration request without exposing private data.",
)
async def check_registration_status(
    request_id: str,
    request: Request,
    repo: AuthRepoDep,
    rate_limiter: RateLimiterDep,
    settings: SettingsDep,
) -> RegistrationStatusResponse:
    client_ip = get_client_ip(request, settings)
    try:
        ip_check = await rate_limiter.check_rate_limit(
            key=f"reg_status:ip:{client_ip}",
            max_requests=settings.LOGIN_RATE_LIMIT_IP_MAX_REQUESTS * 2,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
    except SecurityDependencyError:
        if settings.RATE_LIMIT_REDIS_FAILURE_POLICY == "fail_closed":
            raise
        ip_check = None

    if ip_check is not None and not ip_check.allowed:
        raise RateLimitExceededError(
            message="Too many status requests. Please try again later.",
            retry_after=ip_check.retry_after,
        )

    req = await repo.get_registration_request_by_id(request_id)
    if not req:
        raise NotFoundError("Registration request not found.")

    return RegistrationStatusResponse(
        request_id=req.id,
        email_masked=mask_email(req.email),
        status=req.status,
        requested_branch_code=req.requested_branch_code,
        created_at=req.created_at,
        reviewed_at=req.reviewed_at,
        reason=req.review_reason,
    )


@router.post(
    "/bootstrap-admin",
    response_model=BootstrapAdminResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bootstrap Initial Tenant Administrator",
    description="Provision the initial Tenant Administrator through a secure, non-public bootstrap procedure.",
)
async def bootstrap_admin(
    body: BootstrapAdminRequest,
    request: Request,
    repo: AuthRepoDep,
    settings: SettingsDep,
) -> BootstrapAdminResponse:
    """Secure First Administrator Bootstrap Procedure (AMSC Phase 1 Section 5)."""
    # 1. Require X-Bootstrap-Secret header
    bootstrap_secret = request.headers.get("X-Bootstrap-Secret", "").strip()

    expected_secret = getattr(settings, "BOOTSTRAP_SECRET", "").strip()
    if not expected_secret or len(expected_secret) < 16:
        raise ForbiddenError("Administrator bootstrap is disabled: BOOTSTRAP_SECRET is not configured or insufficient.")

    if not hmac.compare_digest(bootstrap_secret, expected_secret):
        raise ForbiddenError("Invalid bootstrap authorization secret.")

    # 2. Hash password and bootstrap
    pw_hash = hash_password(body.password)
    try:
        tenant, user, mem = await repo.bootstrap_tenant_admin(
            tenant_slug=body.tenant_slug,
            admin_email=body.admin_email,
            admin_full_name=body.admin_full_name,
            password_hash=pw_hash,
        )
    except RuntimeError as exc:
        raise ConflictError(str(exc))
    except ValueError as exc:
        raise BadRequestError(str(exc))
    except Exception as exc:
        raise SecurityDependencyError("Failed to bootstrap administrator.") from exc

    # 3. Audit administrator bootstrap
    await record_audit_event(
        request=request,
        tenant_id=tenant.id,
        actor_id="system:bootstrap",
        event_type="IAM_BOOTSTRAP",
        action="ADMINISTRATOR_BOOTSTRAPPED",
        resource_id=user.id,
        outcome="SUCCESS",
        details={"admin_email": user.email, "role": mem.role, "tenant_slug": tenant.slug},
    )

    return BootstrapAdminResponse(
        tenant_slug=tenant.slug,
        admin_email=user.email,
        role=mem.role,
    )
