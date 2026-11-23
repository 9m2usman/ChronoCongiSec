"""Request-Scoped Multi-Tenant Context & Identity Resolution.

Module: backend.app.tenancy.context
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Multi-Tenant Isolation
- AMSC-DOC-005 (Database & API Schema) Section 3.1: Tenancy & Identity Subsystem
- Master Implementation Specification: M1 Day 2 Authentication Baseline
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, runtime_checkable
from fastapi import Request

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
    Includes trusted branch_id resolved from persistent membership (GAP-028).
    """
    tenant_id: str
    tenant_slug: str
    tenant_name: str
    user_id: str
    role: str
    is_active: bool = True
    branch_id: Optional[str] = None


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
class BranchRecord:
    """Read-only branch entity contract for M6 database integration."""
    id: str
    tenant_id: str
    name: str
    code: str
    status: str = "ACTIVE"


@dataclass(frozen=True)
class RegistrationRequestRecord:
    """Read-only registration request contract for M6 database integration."""
    id: str
    tenant_id: str
    full_name: str
    email: str
    hashed_password: str
    requested_branch_code: str
    status: str = "PENDING"
    created_at: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by_user_id: Optional[str] = None
    review_reason: Optional[str] = None
    assigned_role: Optional[str] = None
    assigned_branch_id: Optional[str] = None


@dataclass(frozen=True)
class MembershipRecord:
    """Read-only membership mapping contract for M6 database integration."""
    id: str
    tenant_id: str
    user_id: str
    role: str
    status: str = "ACTIVE"
    branch_id: Optional[str] = None


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

    async def list_branches(self, tenant_id: str) -> List[BranchRecord]:
        ...

    async def get_branch_by_code(self, tenant_id: str, code: str) -> Optional[BranchRecord]:
        ...

    async def get_branch_by_id(self, tenant_id: str, branch_id: str) -> Optional[BranchRecord]:
        ...

    async def create_registration_request(
        self,
        tenant_id: str,
        full_name: str,
        email: str,
        hashed_password: str,
        requested_branch_code: str,
    ) -> RegistrationRequestRecord:
        ...

    async def get_registration_request_by_id(
        self, request_id: str
    ) -> Optional[RegistrationRequestRecord]:
        ...

    async def list_registration_requests(
        self, tenant_id: str, status: Optional[str] = None
    ) -> List[RegistrationRequestRecord]:
        ...

    async def approve_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        assigned_role: str,
        assigned_branch_id: Optional[str],
        reason: Optional[str] = None,
    ) -> tuple[UserRecord, MembershipRecord]:
        ...

    async def reject_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        reason: str,
    ) -> RegistrationRequestRecord:
        ...

    async def list_tenant_members(self, tenant_id: str) -> List[dict]:
        ...

    async def update_member(
        self,
        tenant_id: str,
        user_id: str,
        role: Optional[str] = None,
        branch_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> MembershipRecord:
        ...

    async def bootstrap_tenant_admin(
        self,
        tenant_slug: str,
        admin_email: str,
        admin_full_name: str,
        password_hash: str,
    ) -> tuple[TenantRecord, UserRecord, MembershipRecord]:
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
        # key: (tenant_id, branch_id) -> BranchRecord
        self.branches: Dict[tuple[str, str], BranchRecord] = {}
        # key: (tenant_id, branch_code_upper) -> BranchRecord
        self.branches_by_code: Dict[tuple[str, str], BranchRecord] = {}
        # key: request_id -> RegistrationRequestRecord
        self.registration_requests: Dict[str, RegistrationRequestRecord] = {}

    def add_user(self, user: UserRecord) -> None:
        self.users[user.id] = user
        self.users_by_email[user.email.lower()] = user

    def add_tenant(self, tenant: TenantRecord) -> None:
        self.tenants[tenant.id] = tenant
        self.tenants_by_slug[tenant.slug.lower()] = tenant

    def add_membership(self, membership: MembershipRecord) -> None:
        self.memberships[(membership.user_id, membership.tenant_id)] = membership

    def add_branch(self, branch: BranchRecord) -> None:
        self.branches[(branch.tenant_id, branch.id)] = branch
        self.branches_by_code[(branch.tenant_id, branch.code.upper())] = branch

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

    async def list_branches(self, tenant_id: str) -> List[BranchRecord]:
        return [
            b for (t_id, _), b in self.branches.items()
            if t_id == tenant_id and b.status == "ACTIVE"
        ]

    async def get_branch_by_code(self, tenant_id: str, code: str) -> Optional[BranchRecord]:
        return self.branches_by_code.get((tenant_id, code.strip().upper()))

    async def get_branch_by_id(self, tenant_id: str, branch_id: str) -> Optional[BranchRecord]:
        return self.branches.get((tenant_id, branch_id))

    async def create_registration_request(
        self,
        tenant_id: str,
        full_name: str,
        email: str,
        hashed_password: str,
        requested_branch_code: str,
    ) -> RegistrationRequestRecord:
        import uuid
        from datetime import datetime, timezone
        req_id = f"reg-{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()
        rec = RegistrationRequestRecord(
            id=req_id,
            tenant_id=tenant_id,
            full_name=full_name,
            email=email.strip().lower(),
            hashed_password=hashed_password,
            requested_branch_code=requested_branch_code.strip().upper(),
            status="PENDING",
            created_at=now_str,
        )
        self.registration_requests[req_id] = rec
        return rec

    async def get_registration_request_by_id(
        self, request_id: str
    ) -> Optional[RegistrationRequestRecord]:
        return self.registration_requests.get(request_id)

    async def list_registration_requests(
        self, tenant_id: str, status: Optional[str] = None
    ) -> List[RegistrationRequestRecord]:
        requests = [r for r in self.registration_requests.values() if r.tenant_id == tenant_id]
        if status:
            requests = [r for r in requests if r.status.upper() == status.upper()]
        return requests

    async def approve_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        assigned_role: str,
        assigned_branch_id: Optional[str],
        reason: Optional[str] = None,
    ) -> tuple[UserRecord, MembershipRecord]:
        import uuid
        from datetime import datetime, timezone
        req = self.registration_requests.get(request_id)
        if not req:
            raise ValueError(f"Registration request {request_id} not found.")
        if req.status != "PENDING":
            raise ValueError(f"Cannot approve request in status {req.status}.")

        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        user = UserRecord(
            id=user_id,
            email=req.email,
            hashed_password=req.hashed_password,
            full_name=req.full_name,
            status="ACTIVE",
        )
        self.add_user(user)

        mem_id = f"mem-{uuid.uuid4().hex[:12]}"
        membership = MembershipRecord(
            id=mem_id,
            tenant_id=req.tenant_id,
            user_id=user_id,
            role=assigned_role,
            status="ACTIVE",
            branch_id=assigned_branch_id,
        )
        self.add_membership(membership)

        now_str = datetime.now(timezone.utc).isoformat()
        updated_req = RegistrationRequestRecord(
            id=req.id,
            tenant_id=req.tenant_id,
            full_name=req.full_name,
            email=req.email,
            hashed_password=req.hashed_password,
            requested_branch_code=req.requested_branch_code,
            status="APPROVED",
            created_at=req.created_at,
            reviewed_at=now_str,
            reviewed_by_user_id=admin_user_id,
            review_reason=reason,
            assigned_role=assigned_role,
            assigned_branch_id=assigned_branch_id,
        )
        self.registration_requests[request_id] = updated_req
        return user, membership

    async def reject_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        reason: str,
    ) -> RegistrationRequestRecord:
        from datetime import datetime, timezone
        req = self.registration_requests.get(request_id)
        if not req:
            raise ValueError(f"Registration request {request_id} not found.")
        if req.status != "PENDING":
            raise ValueError(f"Cannot reject request in status {req.status}.")

        now_str = datetime.now(timezone.utc).isoformat()
        updated_req = RegistrationRequestRecord(
            id=req.id,
            tenant_id=req.tenant_id,
            full_name=req.full_name,
            email=req.email,
            hashed_password=req.hashed_password,
            requested_branch_code=req.requested_branch_code,
            status="REJECTED",
            created_at=req.created_at,
            reviewed_at=now_str,
            reviewed_by_user_id=admin_user_id,
            review_reason=reason,
        )
        self.registration_requests[request_id] = updated_req
        return updated_req

    async def list_tenant_members(self, tenant_id: str) -> List[dict]:
        members = []
        for (u_id, t_id), m in self.memberships.items():
            if t_id == tenant_id:
                user = self.users.get(u_id)
                branch = self.branches.get((t_id, m.branch_id)) if m.branch_id else None
                members.append({
                    "user_id": u_id,
                    "email": user.email if user else "",
                    "full_name": user.full_name if user else "",
                    "role": m.role,
                    "branch_id": m.branch_id,
                    "branch_name": branch.name if branch else None,
                    "branch_code": branch.code if branch else None,
                    "status": m.status,
                })
        return members

    async def update_member(
        self,
        tenant_id: str,
        user_id: str,
        role: Optional[str] = None,
        branch_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> MembershipRecord:
        key = (user_id, tenant_id)
        existing = self.memberships.get(key)
        if not existing:
            raise ValueError(f"Membership for user {user_id} in tenant {tenant_id} not found.")

        updated = MembershipRecord(
            id=existing.id,
            tenant_id=tenant_id,
            user_id=user_id,
            role=role if role is not None else existing.role,
            status=status if status is not None else existing.status,
            branch_id=branch_id if branch_id is not None else existing.branch_id,
        )
        self.memberships[key] = updated
        return updated

    async def bootstrap_tenant_admin(
        self,
        tenant_slug: str,
        admin_email: str,
        admin_full_name: str,
        password_hash: str,
    ) -> tuple[TenantRecord, UserRecord, MembershipRecord]:
        import uuid
        tenant = await self.get_tenant_by_slug(tenant_slug)
        if not tenant:
            raise ValueError(f"Tenant slug {tenant_slug} not found.")

        # Check if an active TENANT_ADMIN already exists in this tenant
        for (u_id, t_id), m in self.memberships.items():
            if t_id == tenant.id and m.role == "TENANT_ADMIN" and m.status == "ACTIVE":
                raise RuntimeError("Tenant admin already exists for this tenant.")

        user = await self.get_user_by_email(admin_email)
        if not user:
            user = UserRecord(
                id=f"usr-{uuid.uuid4().hex[:12]}",
                email=admin_email.strip().lower(),
                hashed_password=password_hash,
                full_name=admin_full_name,
                status="ACTIVE",
            )
            self.add_user(user)

        mem = MembershipRecord(
            id=f"mem-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant.id,
            user_id=user.id,
            role="TENANT_ADMIN",
            status="ACTIVE",
            branch_id=None,
        )
        self.add_membership(mem)
        return tenant, user, mem


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
    u_dev_a = UserRecord(
        id="user-a-dev-009",
        email="developer@company-a.com",
        hashed_password=seed_hash,
        full_name="Dave Developer",
        status="ACTIVE",
    )
    u_dev_b = UserRecord(
        id="user-b-dev-010",
        email="developer@company-b.com",
        hashed_password=seed_hash,
        full_name="Diana Developer",
        status="ACTIVE",
    )
    # Branch-specific users for trusted branch authorization testing (GAP-028)
    u_branch_karachi = UserRecord(
        id="user-a-branch-karachi-011",
        email="karachi-dev@company-a.com",
        hashed_password=seed_hash,
        full_name="Khalid Karachi",
        status="ACTIVE",
    )
    u_branch_lahore = UserRecord(
        id="user-a-branch-lahore-012",
        email="lahore-dev@company-a.com",
        hashed_password=seed_hash,
        full_name="Laila Lahore",
        status="ACTIVE",
    )

    for u in [
        u_analyst_a, u_admin_a, u_analyst_b, u_analyst_c, u_inactive,
        u_revoked_mem, u_suspended_mem, u_inactive_mem,
        u_dev_a, u_dev_b,
        u_branch_karachi, u_branch_lahore,
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
    repo.add_membership(
        MembershipRecord(
            id="mem-009",
            tenant_id=t_a.id,
            user_id=u_dev_a.id,
            role="AI_DEVELOPER",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-010",
            tenant_id=t_b.id,
            user_id=u_dev_b.id,
            role="AI_DEVELOPER",
            status="ACTIVE",
        )
    )
    # Branch-scoped memberships for branch authorization testing (GAP-028)
    repo.add_membership(
        MembershipRecord(
            id="mem-011",
            tenant_id=t_a.id,
            user_id=u_branch_karachi.id,
            role="AI_DEVELOPER",
            status="ACTIVE",
            branch_id="branch-karachi-99",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-012",
            tenant_id=t_a.id,
            user_id=u_branch_lahore.id,
            role="AI_DEVELOPER",
            status="ACTIVE",
            branch_id="branch-lahore-88",
        )
    )

    # Canonical Single-Company Enterprise Branches (AMSC Phase 1)
    b_ho = BranchRecord(
        id="branch-ho-001",
        tenant_id=t_a.id,
        name="Head Office - Core Security",
        code="HO",
        status="ACTIVE",
    )
    b_lhr = BranchRecord(
        id="branch-lhr-002",
        tenant_id=t_a.id,
        name="Finance & Regional Operations Branch (Lahore)",
        code="LHR",
        status="ACTIVE",
    )
    b_khi = BranchRecord(
        id="branch-khi-003",
        tenant_id=t_a.id,
        name="Maritime & Logistics Operations Branch (Karachi)",
        code="KHI",
        status="ACTIVE",
    )
    b_isb = BranchRecord(
        id="branch-isb-004",
        tenant_id=t_a.id,
        name="Corporate Affairs & HR Branch (Islamabad)",
        code="ISB",
        status="ACTIVE",
    )
    for b in [b_ho, b_lhr, b_khi, b_isb]:
        repo.add_branch(b)

    # Alias alphacorp to canonical tenant-a-uuid-001 so frontend and seed match identically
    repo.tenants_by_slug["alphacorp"] = t_a

    # Canonical Enterprise Users (Sarah Admin, Alex Analyst, Dave Developer)
    u_sarah = UserRecord(
        id="usr-admin-sarah-01",
        email="sarah.admin@alphacorp.com",
        hashed_password=seed_hash,
        full_name="Sarah Chen",
        status="ACTIVE",
    )
    u_alex = UserRecord(
        id="usr-analyst-alex-02",
        email="alex.analyst@alphacorp.com",
        hashed_password=seed_hash,
        full_name="Alex Mercer",
        status="ACTIVE",
    )
    u_dave = UserRecord(
        id="usr-dev-dave-03",
        email="dave.developer@alphacorp.com",
        hashed_password=seed_hash,
        full_name="Dave Miller",
        status="ACTIVE",
    )
    u_auditor = UserRecord(
        id="usr-auditor-amara-04",
        email="amara.auditor@alphacorp.com",
        hashed_password=seed_hash,
        full_name="Amara Auditor",
        status="ACTIVE",
    )
    for u in [u_sarah, u_alex, u_dave, u_auditor]:
        repo.add_user(u)

    repo.add_membership(
        MembershipRecord(
            id="mem-sarah-admin-01",
            tenant_id=t_a.id,
            user_id=u_sarah.id,
            role="TENANT_ADMIN",
            status="ACTIVE",
            branch_id=None,
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-alex-analyst-02",
            tenant_id=t_a.id,
            user_id=u_alex.id,
            role="SECURITY_ANALYST",
            status="ACTIVE",
            branch_id="branch-lhr-002",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-dave-dev-03",
            tenant_id=t_a.id,
            user_id=u_dave.id,
            role="AI_DEVELOPER",
            status="ACTIVE",
            branch_id="branch-ho-001",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-amara-auditor-04",
            tenant_id=t_a.id,
            user_id=u_auditor.id,
            role="AUDITOR",
            status="ACTIVE",
            branch_id="branch-ho-001",
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

    # Token and session revocation check (GAP-007 / Finding B)
    revocation_store = getattr(request.app.state, "revocation_store", None)
    if revocation_store is not None:
        jti = payload.get("jti")
        iat = payload.get("iat", 0)
        try:
            if jti and await revocation_store.is_token_revoked(jti):
                raise AuthenticationError("Authentication token has been revoked.")
            if user_id and token_tenant_id and await revocation_store.is_user_revoked(user_id, token_tenant_id, iat):
                raise AuthenticationError("User session has been revoked.")
        except AuthenticationError:
            raise
        except Exception as exc:
            raise SecurityDependencyError("Revocation verification service is unavailable.") from exc

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

    # Resolve trusted branch membership (GAP-028 / Finding E)
    branch_id = getattr(membership, "branch_id", None)
    if branch_id is not None:
        branch_id = str(branch_id).strip() or None

    # Return immutable request-scoped context
    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        user_id=user.id,
        role=membership.role,
        is_active=True,
        branch_id=branch_id,
    )
