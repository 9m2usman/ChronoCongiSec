"""Database-backed Authentication and Identity Repository (M6 / M1 integration).

Module: backend.app.database.repositories.auth
Owner: M6 (Database Schema) & M1 (Platform Auth)

Follows:
- AMSC-DOC-005 Section 3.1: Tenancy & Identity Subsystem
- AMSC Phase 1 Specification: Persistent IAM and Employee Registration
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Union

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models import (
    Branch,
    Membership,
    RegistrationRequest,
    Tenant,
    User,
)
from backend.app.tenancy.context import (
    AuthRepositoryProtocol,
    BranchRecord,
    MembershipRecord,
    RegistrationRequestRecord,
    TenantRecord,
    UserRecord,
)


class DatabaseAuthRepository(AuthRepositoryProtocol):
    """Production and persistent database repository for users, tenants, memberships, and registration requests."""

    is_demo: bool = False
    is_persistent: bool = True

    def __init__(self, session_or_factory: Union[AsyncSession, async_sessionmaker[AsyncSession]]) -> None:
        if isinstance(session_or_factory, async_sessionmaker):
            self._session_factory = session_or_factory
            self._direct_session: Optional[AsyncSession] = None
        else:
            self._session_factory = None
            self._direct_session = session_or_factory

    async def _get_session(self) -> AsyncSession:
        if self._direct_session is not None:
            return self._direct_session
        return self._session_factory()

    async def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        clean_email = email.strip().lower()
        if self._direct_session is not None:
            stmt = select(User).where(func.lower(User.email) == clean_email)
            user = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(User).where(func.lower(User.email) == clean_email)
                user = (await session.execute(stmt)).scalar_one_or_none()

        if user is None:
            return None
        return UserRecord(
            id=user.id,
            email=user.email,
            hashed_password=user.hashed_password,
            full_name=user.full_name,
            status=user.status,
        )

    async def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        if self._direct_session is not None:
            stmt = select(User).where(User.id == user_id)
            user = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(User).where(User.id == user_id)
                user = (await session.execute(stmt)).scalar_one_or_none()

        if user is None:
            return None
        return UserRecord(
            id=user.id,
            email=user.email,
            hashed_password=user.hashed_password,
            full_name=user.full_name,
            status=user.status,
        )

    async def get_tenant_by_slug(self, slug: str) -> Optional[TenantRecord]:
        clean_slug = slug.strip().lower()
        target_slugs = [clean_slug]
        if clean_slug in ("company-a", "alphacorp", "chronocognisec"):
            target_slugs = ["alphacorp", "company-a", "chronocognisec"]
        if self._direct_session is not None:
            stmt = select(Tenant).where(func.lower(Tenant.slug).in_(target_slugs))
            tenant = (await self._direct_session.execute(stmt)).scalars().first()
        else:
            async with self._session_factory() as session:
                stmt = select(Tenant).where(func.lower(Tenant.slug).in_(target_slugs))
                tenant = (await session.execute(stmt)).scalars().first()

        if tenant is None:
            return None
        return TenantRecord(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            status=tenant.status,
        )

    async def get_tenant_by_id(self, tenant_id: str) -> Optional[TenantRecord]:
        if self._direct_session is not None:
            stmt = select(Tenant).where(Tenant.id == tenant_id)
            tenant = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(Tenant).where(Tenant.id == tenant_id)
                tenant = (await session.execute(stmt)).scalar_one_or_none()

        if tenant is None:
            return None
        return TenantRecord(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            status=tenant.status,
        )

    async def get_membership(self, user_id: str, tenant_id: str) -> Optional[MembershipRecord]:
        if self._direct_session is not None:
            stmt = select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == tenant_id
            )
            membership = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(Membership).where(
                    Membership.user_id == user_id, Membership.tenant_id == tenant_id
                )
                membership = (await session.execute(stmt)).scalar_one_or_none()

        if membership is None:
            return None
        return MembershipRecord(
            id=membership.id,
            tenant_id=membership.tenant_id,
            user_id=membership.user_id,
            role=membership.role,
            status=membership.status,
            branch_id=getattr(membership, "branch_id", None),
        )

    async def list_user_tenants(self, user_id: str) -> List[TenantRecord]:
        if self._direct_session is not None:
            stmt = (
                select(Tenant)
                .join(Membership, Membership.tenant_id == Tenant.id)
                .where(
                    Membership.user_id == user_id,
                    Membership.status == "ACTIVE",
                    Tenant.status == "ACTIVE",
                )
            )
            tenants = (await self._direct_session.execute(stmt)).scalars().all()
        else:
            async with self._session_factory() as session:
                stmt = (
                    select(Tenant)
                    .join(Membership, Membership.tenant_id == Tenant.id)
                    .where(
                        Membership.user_id == user_id,
                        Membership.status == "ACTIVE",
                        Tenant.status == "ACTIVE",
                    )
                )
                tenants = (await session.execute(stmt)).scalars().all()

        return [
            TenantRecord(
                id=t.id,
                name=t.name,
                slug=t.slug,
                status=t.status,
            )
            for t in tenants
        ]

    async def list_branches(self, tenant_id: str) -> List[BranchRecord]:
        if self._direct_session is not None:
            stmt = select(Branch).where(
                Branch.tenant_id == tenant_id, Branch.status == "ACTIVE"
            ).order_by(Branch.name)
            branches = (await self._direct_session.execute(stmt)).scalars().all()
        else:
            async with self._session_factory() as session:
                stmt = select(Branch).where(
                    Branch.tenant_id == tenant_id, Branch.status == "ACTIVE"
                ).order_by(Branch.name)
                branches = (await session.execute(stmt)).scalars().all()

        return [
            BranchRecord(
                id=b.id,
                tenant_id=b.tenant_id,
                name=b.name,
                code=b.code,
                status=b.status,
            )
            for b in branches
        ]

    async def get_branch_by_code(self, tenant_id: str, code: str) -> Optional[BranchRecord]:
        clean_code = code.strip().upper()
        if self._direct_session is not None:
            stmt = select(Branch).where(
                Branch.tenant_id == tenant_id, func.upper(Branch.code) == clean_code
            )
            branch = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(Branch).where(
                    Branch.tenant_id == tenant_id, func.upper(Branch.code) == clean_code
                )
                branch = (await session.execute(stmt)).scalar_one_or_none()

        if branch is None:
            return None
        return BranchRecord(
            id=branch.id,
            tenant_id=branch.tenant_id,
            name=branch.name,
            code=branch.code,
            status=branch.status,
        )

    async def get_branch_by_id(self, tenant_id: str, branch_id: str) -> Optional[BranchRecord]:
        if self._direct_session is not None:
            stmt = select(Branch).where(
                Branch.tenant_id == tenant_id, Branch.id == branch_id
            )
            branch = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(Branch).where(
                    Branch.tenant_id == tenant_id, Branch.id == branch_id
                )
                branch = (await session.execute(stmt)).scalar_one_or_none()

        if branch is None:
            return None
        return BranchRecord(
            id=branch.id,
            tenant_id=branch.tenant_id,
            name=branch.name,
            code=branch.code,
            status=branch.status,
        )

    async def create_registration_request(
        self,
        tenant_id: str,
        full_name: str,
        email: str,
        hashed_password: str,
        requested_branch_code: str,
    ) -> RegistrationRequestRecord:
        req_id = f"reg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        req = RegistrationRequest(
            id=req_id,
            tenant_id=tenant_id,
            full_name=full_name,
            email=email.strip().lower(),
            hashed_password=hashed_password,
            requested_branch_code=requested_branch_code.strip().upper(),
            status="PENDING",
            created_at=now,
        )
        if self._direct_session is not None:
            self._direct_session.add(req)
            await self._direct_session.flush()
        else:
            async with self._session_factory() as session:
                session.add(req)
                await session.commit()

        return RegistrationRequestRecord(
            id=req.id,
            tenant_id=req.tenant_id,
            full_name=req.full_name,
            email=req.email,
            hashed_password=req.hashed_password,
            requested_branch_code=req.requested_branch_code,
            status="PENDING",
            created_at=req.created_at.isoformat(),
        )

    async def get_registration_request_by_id(
        self, request_id: str
    ) -> Optional[RegistrationRequestRecord]:
        if self._direct_session is not None:
            stmt = select(RegistrationRequest).where(RegistrationRequest.id == request_id)
            req = (await self._direct_session.execute(stmt)).scalar_one_or_none()
        else:
            async with self._session_factory() as session:
                stmt = select(RegistrationRequest).where(RegistrationRequest.id == request_id)
                req = (await session.execute(stmt)).scalar_one_or_none()

        if req is None:
            return None
        return RegistrationRequestRecord(
            id=req.id,
            tenant_id=req.tenant_id,
            full_name=req.full_name,
            email=req.email,
            hashed_password=req.hashed_password,
            requested_branch_code=req.requested_branch_code,
            status=req.status,
            created_at=req.created_at.isoformat() if req.created_at else None,
            reviewed_at=req.reviewed_at.isoformat() if req.reviewed_at else None,
            reviewed_by_user_id=req.reviewed_by_user_id,
            review_reason=req.review_reason,
            assigned_role=req.assigned_role,
            assigned_branch_id=req.assigned_branch_id,
        )

    async def list_registration_requests(
        self, tenant_id: str, status: Optional[str] = None
    ) -> List[RegistrationRequestRecord]:
        stmt = select(RegistrationRequest).where(RegistrationRequest.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(RegistrationRequest.status == status.upper())
        stmt = stmt.order_by(RegistrationRequest.created_at.desc())

        if self._direct_session is not None:
            items = (await self._direct_session.execute(stmt)).scalars().all()
        else:
            async with self._session_factory() as session:
                items = (await session.execute(stmt)).scalars().all()

        return [
            RegistrationRequestRecord(
                id=r.id,
                tenant_id=r.tenant_id,
                full_name=r.full_name,
                email=r.email,
                hashed_password=r.hashed_password,
                requested_branch_code=r.requested_branch_code,
                status=r.status,
                created_at=r.created_at.isoformat() if r.created_at else None,
                reviewed_at=r.reviewed_at.isoformat() if r.reviewed_at else None,
                reviewed_by_user_id=r.reviewed_by_user_id,
                review_reason=r.review_reason,
                assigned_role=r.assigned_role,
                assigned_branch_id=r.assigned_branch_id,
            )
            for r in items
        ]

    async def approve_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        assigned_role: str,
        assigned_branch_id: Optional[str],
        reason: Optional[str] = None,
    ) -> tuple[UserRecord, MembershipRecord]:
        now = datetime.now(timezone.utc)

        async def _execute_approval(session: AsyncSession):
            stmt = select(RegistrationRequest).where(RegistrationRequest.id == request_id).with_for_update()
            req = (await session.execute(stmt)).scalar_one_or_none()
            if not req:
                raise ValueError(f"Registration request {request_id} not found.")
            if req.status != "PENDING":
                raise ValueError(f"Cannot approve request in status {req.status}.")

            # 1. Create User
            user_stmt = select(User).where(func.lower(User.email) == req.email.lower())
            user = (await session.execute(user_stmt)).scalar_one_or_none()
            if not user:
                user = User(
                    id=f"usr-{uuid.uuid4().hex[:12]}",
                    email=req.email,
                    hashed_password=req.hashed_password,
                    full_name=req.full_name,
                    status="ACTIVE",
                    created_at=now,
                )
                session.add(user)
                await session.flush()

            # 2. Create Membership
            mem_stmt = select(Membership).where(
                Membership.user_id == user.id, Membership.tenant_id == req.tenant_id
            )
            mem = (await session.execute(mem_stmt)).scalar_one_or_none()
            if not mem:
                mem = Membership(
                    id=f"mem-{uuid.uuid4().hex[:12]}",
                    tenant_id=req.tenant_id,
                    user_id=user.id,
                    role=assigned_role,
                    branch_id=assigned_branch_id,
                    status="ACTIVE",
                    created_at=now,
                )
                session.add(mem)
                await session.flush()
            else:
                mem.role = assigned_role
                mem.branch_id = assigned_branch_id
                mem.status = "ACTIVE"
                await session.flush()

            # 3. Update Registration Request
            req.status = "APPROVED"
            req.reviewed_at = now
            req.reviewed_by_user_id = admin_user_id
            req.review_reason = reason
            req.assigned_role = assigned_role
            req.assigned_branch_id = assigned_branch_id
            await session.flush()

            return (
                UserRecord(
                    id=user.id,
                    email=user.email,
                    hashed_password=user.hashed_password,
                    full_name=user.full_name,
                    status=user.status,
                ),
                MembershipRecord(
                    id=mem.id,
                    tenant_id=mem.tenant_id,
                    user_id=mem.user_id,
                    role=mem.role,
                    status=mem.status,
                    branch_id=mem.branch_id,
                ),
            )

        if self._direct_session is not None:
            return await _execute_approval(self._direct_session)
        else:
            async with self._session_factory() as session:
                async with session.begin():
                    return await _execute_approval(session)

    async def reject_registration_request(
        self,
        request_id: str,
        admin_user_id: str,
        reason: str,
    ) -> RegistrationRequestRecord:
        now = datetime.now(timezone.utc)

        async def _execute_rejection(session: AsyncSession):
            stmt = select(RegistrationRequest).where(RegistrationRequest.id == request_id).with_for_update()
            req = (await session.execute(stmt)).scalar_one_or_none()
            if not req:
                raise ValueError(f"Registration request {request_id} not found.")
            if req.status != "PENDING":
                raise ValueError(f"Cannot reject request in status {req.status}.")

            req.status = "REJECTED"
            req.reviewed_at = now
            req.reviewed_by_user_id = admin_user_id
            req.review_reason = reason
            await session.flush()

            return RegistrationRequestRecord(
                id=req.id,
                tenant_id=req.tenant_id,
                full_name=req.full_name,
                email=req.email,
                hashed_password=req.hashed_password,
                requested_branch_code=req.requested_branch_code,
                status="REJECTED",
                created_at=req.created_at.isoformat() if req.created_at else None,
                reviewed_at=req.reviewed_at.isoformat() if req.reviewed_at else None,
                reviewed_by_user_id=req.reviewed_by_user_id,
                review_reason=req.review_reason,
            )

        if self._direct_session is not None:
            return await _execute_rejection(self._direct_session)
        else:
            async with self._session_factory() as session:
                async with session.begin():
                    return await _execute_rejection(session)

    async def list_tenant_members(self, tenant_id: str) -> List[dict]:
        stmt = (
            select(Membership, User, Branch)
            .join(User, User.id == Membership.user_id)
            .outerjoin(
                Branch,
                (Branch.id == Membership.branch_id) & (Branch.tenant_id == tenant_id),
            )
            .where(Membership.tenant_id == tenant_id)
            .order_by(Membership.created_at.desc())
        )
        if self._direct_session is not None:
            rows = (await self._direct_session.execute(stmt)).all()
        else:
            async with self._session_factory() as session:
                rows = (await session.execute(stmt)).all()

        return [
            {
                "user_id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": mem.role,
                "branch_id": mem.branch_id,
                "branch_name": branch.name if branch else None,
                "branch_code": branch.code if branch else None,
                "status": mem.status,
            }
            for mem, user, branch in rows
        ]

    async def update_member(
        self,
        tenant_id: str,
        user_id: str,
        role: Optional[str] = None,
        branch_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> MembershipRecord:
        async def _execute_update(session: AsyncSession):
            stmt = select(Membership).where(
                Membership.tenant_id == tenant_id, Membership.user_id == user_id
            ).with_for_update()
            mem = (await session.execute(stmt)).scalar_one_or_none()
            if not mem:
                raise ValueError(f"Membership for user {user_id} in tenant {tenant_id} not found.")

            if role is not None:
                mem.role = role
            if branch_id is not None:
                mem.branch_id = branch_id
            if status is not None:
                mem.status = status

            await session.flush()
            return MembershipRecord(
                id=mem.id,
                tenant_id=mem.tenant_id,
                user_id=mem.user_id,
                role=mem.role,
                status=mem.status,
                branch_id=mem.branch_id,
            )

        if self._direct_session is not None:
            return await _execute_update(self._direct_session)
        else:
            async with self._session_factory() as session:
                async with session.begin():
                    return await _execute_update(session)

    async def bootstrap_tenant_admin(
        self,
        tenant_slug: str,
        admin_email: str,
        admin_full_name: str,
        password_hash: str,
    ) -> tuple[TenantRecord, UserRecord, MembershipRecord]:
        now = datetime.now(timezone.utc)

        async def _execute_bootstrap(session: AsyncSession):
            t_stmt = select(Tenant).where(func.lower(Tenant.slug) == tenant_slug.strip().lower())
            tenant = (await session.execute(t_stmt)).scalar_one_or_none()
            if not tenant:
                raise ValueError(f"Tenant slug {tenant_slug} not found.")

            # Check if an active TENANT_ADMIN already exists
            check_admin_stmt = select(Membership).where(
                Membership.tenant_id == tenant.id,
                Membership.role == "TENANT_ADMIN",
                Membership.status == "ACTIVE",
            )
            existing_admin = (await session.execute(check_admin_stmt)).scalar_one_or_none()
            if existing_admin:
                raise RuntimeError("Tenant admin already exists for this tenant.")

            u_stmt = select(User).where(func.lower(User.email) == admin_email.strip().lower())
            user = (await session.execute(u_stmt)).scalar_one_or_none()
            if not user:
                user = User(
                    id=f"usr-{uuid.uuid4().hex[:12]}",
                    email=admin_email.strip().lower(),
                    hashed_password=password_hash,
                    full_name=admin_full_name,
                    status="ACTIVE",
                    created_at=now,
                )
                session.add(user)
                await session.flush()

            mem_stmt = select(Membership).where(
                Membership.user_id == user.id, Membership.tenant_id == tenant.id
            )
            mem = (await session.execute(mem_stmt)).scalar_one_or_none()
            if not mem:
                mem = Membership(
                    id=f"mem-{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant.id,
                    user_id=user.id,
                    role="TENANT_ADMIN",
                    status="ACTIVE",
                    branch_id=None,
                    created_at=now,
                )
                session.add(mem)
                await session.flush()
            else:
                mem.role = "TENANT_ADMIN"
                mem.status = "ACTIVE"
                await session.flush()

            return (
                TenantRecord(id=tenant.id, name=tenant.name, slug=tenant.slug, status=tenant.status),
                UserRecord(id=user.id, email=user.email, hashed_password=user.hashed_password, full_name=user.full_name, status=user.status),
                MembershipRecord(id=mem.id, tenant_id=mem.tenant_id, user_id=mem.user_id, role=mem.role, status=mem.status, branch_id=mem.branch_id),
            )

        if self._direct_session is not None:
            return await _execute_bootstrap(self._direct_session)
        else:
            async with self._session_factory() as session:
                async with session.begin():
                    return await _execute_bootstrap(session)
