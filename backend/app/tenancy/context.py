"""Request-Scoped Multi-Tenant Context & Identity Resolution.

Module: backend.app.tenancy.context
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Multi-Tenant Isolation
- AMSC-DOC-005 (Database & API Schema) Section 3.1: Tenancy & Identity Subsystem
- Master Implementation Specification: M1 Day 2 Authentication Baseline
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import (
    AuthenticationError,
    SecurityDependencyError,
    TenantAccessForbiddenError,
)
from backend.app.core.security import decode_access_token


# ============================================================================
# 1. Domain Entities & Immutable Tenant Context
# ============================================================================

@dataclass(frozen=True)
class TenantContext:
    """Immutable, request-scoped tenant execution context.

    Bound per-request to prevent context leakage across concurrent requests.
    """
    tenant_id: str
    tenant_slug: str
    tenant_name: str
    user_id: str
    role: str
    is_active: bool = True


@dataclass(frozen=True)
class UserRecord:
    """Read-only user entity contract for M6 database integration."""
    id: str
    email: str
    hashed_password: str
    full_name: str
    status: str = "ACTIVE"


@dataclass(frozen=True)
class TenantRecord:
    """Read-only tenant entity contract for M6 database integration."""
    id: str
    name: str
    slug: str
    status: str = "ACTIVE"


@dataclass(frozen=True)
class MembershipRecord:
    """Read-only membership mapping contract for M6 database integration."""
    id: str
    tenant_id: str
    user_id: str
    role: str
    status: str = "ACTIVE"


# ============================================================================
# 2. Repository Protocol & Default Seeded Store (M6 Boundary)
# ============================================================================

@runtime_checkable
class AuthRepositoryProtocol(Protocol):
    """Protocol defining the repository contract between M1 (Platform) and M6 (Database)."""

    async def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        ...

    async def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        ...

    async def get_tenant_by_slug(self, slug: str) -> Optional[TenantRecord]:
        ...

    async def get_tenant_by_id(self, tenant_id: str) -> Optional[TenantRecord]:
        ...

    async def get_membership(self, user_id: str, tenant_id: str) -> Optional[MembershipRecord]:
        ...

    async def list_user_tenants(self, user_id: str) -> List[TenantRecord]:
        ...


class InMemoryAuthRepository:
    """Thread-safe, synchronous/asynchronous test and fallback repository.

    Provides Company A, Company B, and Company C fixtures per AMSC-DOC-006 Section 3.
    Serves as the documented interface boundary until M6 completes PostgreSQL models.
    """

    is_demo: bool = True

    def __init__(self) -> None:
        self.users: Dict[str, UserRecord] = {}
        self.users_by_email: Dict[str, UserRecord] = {}
        self.tenants: Dict[str, TenantRecord] = {}
        self.tenants_by_slug: Dict[str, TenantRecord] = {}
        # key: (user_id, tenant_id) -> MembershipRecord
        self.memberships: Dict[tuple[str, str], MembershipRecord] = {}

    def add_user(self, user: UserRecord) -> None:
        self.users[user.id] = user
        self.users_by_email[user.email.lower()] = user

    def add_tenant(self, tenant: TenantRecord) -> None:
        self.tenants[tenant.id] = tenant
        self.tenants_by_slug[tenant.slug.lower()] = tenant

    def add_membership(self, membership: MembershipRecord) -> None:
        self.memberships[(membership.user_id, membership.tenant_id)] = membership

    async def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        return self.users_by_email.get(email.strip().lower())

    async def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        return self.users.get(user_id)

    async def get_tenant_by_slug(self, slug: str) -> Optional[TenantRecord]:
        return self.tenants_by_slug.get(slug.strip().lower())

    async def get_tenant_by_id(self, tenant_id: str) -> Optional[TenantRecord]:
        return self.tenants.get(tenant_id)

    async def get_membership(self, user_id: str, tenant_id: str) -> Optional[MembershipRecord]:
        return self.memberships.get((user_id, tenant_id))

    async def list_user_tenants(self, user_id: str) -> List[TenantRecord]:
        user_active_tenant_ids = [
            t_id
            for (u_id, t_id), m in self.memberships.items()
            if u_id == user_id
            and getattr(m, "status", None) is not None
            and str(getattr(m, "status", "")).strip().upper() == "ACTIVE"
        ]
        return [
            self.tenants[t_id]
            for t_id in user_active_tenant_ids
            if t_id in self.tenants and self.tenants[t_id].status == "ACTIVE"
        ]


# Singleton default repository instance for dev/test runtime baseline
_default_auth_repo: Optional[AuthRepositoryProtocol] = None


def seed_demo_accounts(repo: InMemoryAuthRepository) -> InMemoryAuthRepository:
    """Pre-seed canonical Company A, B, and C tenant and user records.

    MVP ARCHITECTURAL NOTE:
    The approved ChronoCogniSec MVP scope operates in a single company organization
    with multiple geographically distributed branches (e.g., HQ, Regional Branches).
    The synthetic multi-company fixtures below (Company A, Company B, Company C)
    are retained strictly as multi-tenant isolation and security test fixtures to verify
    tenant boundaries, header spoofing rejection, and cross-organization isolation.
    They must not be confused with the single-company MVP demonstration topology.

    SECURITY REQUIREMENT:
    Allowed ONLY in development and testing environments.
    Strictly forbidden in staging and production.
    """
    from backend.app.core.security import hash_password

    # Pre-seed canonical Company A, B, and C tenant records
    t_a = TenantRecord(
        id="tenant-a-uuid-001",
        name="Company A (Attack Lab)",
        slug="company-a",
        status="ACTIVE",
    )
    t_b = TenantRecord(
        id="tenant-b-uuid-002",
        name="Company B (External Partner)",
        slug="company-b",
        status="ACTIVE",
    )
    t_c = TenantRecord(
        id="tenant-c-uuid-003",
        name="Company C (Strict Isolation)",
        slug="company-c",
        status="ACTIVE",
    )
    t_suspended = TenantRecord(
        id="tenant-suspended-uuid-999",
        name="Suspended Corp",
        slug="suspended-corp",
        status="SUSPENDED",
    )
    for t in [t_a, t_b, t_c, t_suspended]:
        repo.add_tenant(t)

    # Standard password for demo/seed: "SecurePassword123!"
    seed_hash = hash_password("SecurePassword123!")

    # Pre-seed canonical users
    u_analyst_a = UserRecord(
        id="user-a-analyst-001",
        email="analyst@company-a.com",
        hashed_password=seed_hash,
        full_name="Alice Analyst",
        status="ACTIVE",
    )
    u_admin_a = UserRecord(
        id="user-a-admin-002",
        email="admin@company-a.com",
        hashed_password=seed_hash,
        full_name="Adam Admin",
        status="ACTIVE",
    )
    u_analyst_b = UserRecord(
        id="user-b-analyst-003",
        email="analyst@company-b.com",
        hashed_password=seed_hash,
        full_name="Bob Analyst",
        status="ACTIVE",
    )
    u_analyst_c = UserRecord(
        id="user-c-analyst-004",
        email="analyst@company-c.com",
        hashed_password=seed_hash,
        full_name="Charlie Analyst",
        status="ACTIVE",
    )
    u_inactive = UserRecord(
        id="user-inactive-005",
        email="inactive@company-a.com",
        hashed_password=seed_hash,
        full_name="Ian Inactive",
        status="INACTIVE",
    )
    # Users for membership status testing (Active user, but varied membership status)
    u_revoked_mem = UserRecord(
        id="user-revoked-mem-006",
        email="revoked-mem@company-a.com",
        hashed_password=seed_hash,
        full_name="Rachel Revoked",
        status="ACTIVE",
    )
    u_suspended_mem = UserRecord(
        id="user-suspended-mem-007",
        email="suspended-mem@company-a.com",
        hashed_password=seed_hash,
        full_name="Sam Suspended",
        status="ACTIVE",
    )
    u_inactive_mem = UserRecord(
        id="user-inactive-mem-008",
        email="inactive-mem@company-a.com",
        hashed_password=seed_hash,
        full_name="Iris InactiveMembership",
        status="ACTIVE",
    )

    for u in [
        u_analyst_a, u_admin_a, u_analyst_b, u_analyst_c, u_inactive,
        u_revoked_mem, u_suspended_mem, u_inactive_mem,
    ]:
        repo.add_user(u)

    # Pre-seed memberships
    repo.add_membership(
        MembershipRecord(
            id="mem-001",
            tenant_id=t_a.id,
            user_id=u_analyst_a.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-002",
            tenant_id=t_a.id,
            user_id=u_admin_a.id,
            role="TENANT_ADMIN",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-003",
            tenant_id=t_b.id,
            user_id=u_analyst_b.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-004",
            tenant_id=t_c.id,
            user_id=u_analyst_c.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-005",
            tenant_id=t_a.id,
            user_id=u_inactive.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-006",
            tenant_id=t_a.id,
            user_id=u_revoked_mem.id,
            role="SECURITY_ANALYST",
            status="REVOKED",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-007",
            tenant_id=t_a.id,
            user_id=u_suspended_mem.id,
            role="SECURITY_ANALYST",
            status="SUSPENDED",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-008",
            tenant_id=t_a.id,
            user_id=u_inactive_mem.id,
            role="SECURITY_ANALYST",
            status="INACTIVE",
        )
    )
    return repo


def create_demo_auth_repository(settings: Optional[Settings] = None) -> InMemoryAuthRepository:
    """Factory creating and seeding an in-memory auth repository for dev/test only."""
    cfg = settings or get_settings()
    if cfg.APP_ENV == "production":
        raise RuntimeError(
            "Security violation: In-memory demo authentication repository cannot be created in production."
        )
    if not cfg.ALLOW_IN_MEMORY_AUTH:
        raise RuntimeError(
            "Security violation: In-memory demo authentication is disabled by configuration."
        )
    repo = InMemoryAuthRepository()
    return seed_demo_accounts(repo)


def get_default_auth_repository(settings: Optional[Settings] = None) -> AuthRepositoryProtocol:
    """Factory returning the configured Auth repository for local dev or tests."""
    global _default_auth_repo
    cfg = settings or get_settings()
    if cfg.APP_ENV == "production":
        raise RuntimeError(
            "Security violation: In-memory demo authentication repository cannot be accessed in production."
        )
    if not cfg.ALLOW_IN_MEMORY_AUTH:
        raise RuntimeError(
            "Security violation: In-memory demo authentication is disabled by configuration."
        )
    if _default_auth_repo is None:
        _default_auth_repo = create_demo_auth_repository(cfg)
    return _default_auth_repo


def set_default_auth_repository(repo: Optional[AuthRepositoryProtocol]) -> None:
    """Override repository implementation (used in integration tests or M6 injection)."""
    global _default_auth_repo
    _default_auth_repo = repo


# ============================================================================
# 3. Tenant Context Extraction & Verification Helper
# ============================================================================

async def resolve_tenant_context_from_request(
    request: Request,
    repo: Optional[AuthRepositoryProtocol] = None,
) -> TenantContext:
    """Extract, validate, and authorize tenant context from request headers and JWT.

    Security Invariants:
    1. Authorization Bearer header must be present and valid.
    2. JWT signature, expiration, and issuer must be verified.
    3. User and Tenant must exist and have ACTIVE status.
    4. User must have an active membership in the token's tenant.
    5. Role is obtained directly from trusted repository, not from untrusted inputs.
    6. If X-Tenant-ID header is present, it MUST match the token's tenant_id.
       Cross-tenant mismatches are rejected immediately with HTTP 403 Forbidden.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise AuthenticationError("Missing Authorization header.")

    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthenticationError("Invalid Authorization scheme. Bearer token required.")

    token = parts[1].strip()
    if not token:
        raise AuthenticationError("Empty Bearer token provided.")

    # Validate JWT cryptographic signature and claims using request app settings if available
    app_settings = getattr(request.app.state, "settings", None) or get_settings()
    payload = decode_access_token(token, settings=app_settings)

    user_id = payload.get("sub")
    token_tenant_id = payload.get("tenant_id")
    if not user_id or not token_tenant_id:
        raise AuthenticationError("Token missing required user or tenant claims.")

    # Validate optional X-Tenant-ID header
    requested_tenant_header = request.headers.get("X-Tenant-ID")
    if requested_tenant_header:
        requested_tenant_header = requested_tenant_header.strip()
        if requested_tenant_header != token_tenant_id:
            raise TenantAccessForbiddenError(
                "Cross-tenant access forbidden: X-Tenant-ID does not match authorized token tenant."
            )

    # Re-verify against database repository
    repository = repo or getattr(request.app.state, "auth_repo", None)
    if repository is None:
        if app_settings.APP_ENV == "production" or not app_settings.ALLOW_IN_MEMORY_AUTH:
            raise SecurityDependencyError("Authentication database repository is not configured.")
        repository = get_default_auth_repository(app_settings)

    try:
        user = await repository.get_user_by_id(user_id)
    except Exception as exc:
        if isinstance(exc, (AuthenticationError, TenantAccessForbiddenError)):
            raise
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not user:
        raise AuthenticationError("Authenticated user account not found.")
    if user.status != "ACTIVE":
        raise AuthenticationError("Authenticated user account is inactive or disabled.")

    try:
        tenant = await repository.get_tenant_by_id(token_tenant_id)
    except Exception as exc:
        if isinstance(exc, (AuthenticationError, TenantAccessForbiddenError)):
            raise
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not tenant:
        raise TenantAccessForbiddenError("Authorized tenant workspace not found.")
    if tenant.status != "ACTIVE":
        raise TenantAccessForbiddenError("Authorized tenant workspace is inactive or suspended.")

    try:
        membership = await repository.get_membership(user_id, token_tenant_id)
    except Exception as exc:
        if isinstance(exc, (AuthenticationError, TenantAccessForbiddenError)):
            raise
        raise SecurityDependencyError("Security verification database is unavailable.") from exc

    if not membership:
        raise TenantAccessForbiddenError("User is not an active member of the requested tenant.")

    # Membership status enforcement: active membership required (reject INACTIVE, REVOKED, SUSPENDED, and missing status)
    mem_status = getattr(membership, "status", None)
    if mem_status is None or str(mem_status).strip().upper() != "ACTIVE":
        raise TenantAccessForbiddenError("User is not an active member of the requested tenant.")

    # Return immutable request-scoped context
    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        user_id=user.id,
        role=membership.role,
        is_active=True,
    )
