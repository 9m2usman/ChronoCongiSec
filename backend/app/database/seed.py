"""M6 / M7 Database Seed: Reproducible Multi-Tenant Canonical Seed Data.

Module: backend.app.database.seed
Owner: M6 (Data Schema) + M7 (Test/Dev Fixtures)

Implements Canonical Architecture:
- AMSC-DOC-005 Section 3: Identity, Tenancy, Agents, Sources, and Memories
- Seeds Company A (Financial), Company B (Cyber), Company C (Autonomous)
"""

from datetime import datetime, timezone
import logging
from typing import Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.security import hash_password
from backend.app.database.models.identity import (
    Branch,
    Membership,
    Tenant,
    User,
)

logger = logging.getLogger("amsc.database.seed")


# Canonical tenants
TENANTS = [
    {
        "id": "tenant-a-uuid-001",
        "name": "ChronoCongiSec Enterprise",
        "slug": "alphacorp",
        "status": "ACTIVE",
    },
    {
        "id": "tenant-b-uuid-002",
        "name": "BetaShield Defense AI",
        "slug": "betashield",
        "status": "ACTIVE",
    },
    {
        "id": "tenant-c-uuid-003",
        "name": "GammaAI Autonomous Ops",
        "slug": "gammaai",
        "status": "ACTIVE",
    },
]

# Canonical users with argon2id hashed passwords
USERS = [
    {
        "id": "usr-admin-sarah-01",
        "email": "sarah.admin@alphacorp.com",
        "full_name": "Sarah Chen",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
    {
        "id": "usr-analyst-alex-02",
        "email": "alex.analyst@alphacorp.com",
        "full_name": "Alex Mercer",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
    {
        "id": "usr-dev-dave-03",
        "email": "dave.developer@alphacorp.com",
        "full_name": "Dave Miller",
        "status": "ACTIVE",
        "is_superadmin": False,
    },
]

# Memberships
MEMBERSHIPS = [
    {
        "id": "mem-sarah-admin-01",
        "user_id": "usr-admin-sarah-01",
        "tenant_id": "tenant-a-uuid-001",
        "role": "TENANT_ADMIN",
        "status": "ACTIVE",
    },
    {
        "id": "mem-alex-analyst-02",
        "user_id": "usr-analyst-alex-02",
        "tenant_id": "tenant-a-uuid-001",
        "role": "SECURITY_ANALYST",
        "status": "ACTIVE",
    },
    {
        "id": "mem-dave-dev-03",
        "user_id": "usr-dev-dave-03",
        "tenant_id": "tenant-a-uuid-001",
        "role": "AI_DEVELOPER",
        "status": "ACTIVE",
    },
]

# Branches
BRANCHES = [
    {
        "id": "branch-ho-001",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Head Office - Core Security",
        "status": "ACTIVE",
    },
    {
        "id": "branch-lhr-002",
        "tenant_id": "tenant-a-uuid-001",
        "name": "Finance Operations Branch",
        "status": "ACTIVE",
    },
]


async def seed_database(session: AsyncSession) -> Dict[str, int]:
    """Execute reproducible seed script against active database session."""
    stats = {"tenants": 0, "users": 0, "memberships": 0, "branches": 0}
    now = datetime.now(timezone.utc)

    # 1. Seed Tenants
    for t_data in TENANTS:
        res = await session.execute(select(Tenant).where(Tenant.id == t_data["id"]))
        if res.scalar_one_or_none() is None:
            tenant = Tenant(
                id=t_data["id"],
                name=t_data["name"],
                slug=t_data["slug"],
                status=t_data["status"],
                created_at=now,
                updated_at=now,
            )
            session.add(tenant)
            stats["tenants"] += 1

    # 2. Seed Users
    default_pw_hash = hash_password("CorrectHorseBatteryStaple2026!")
    for u_data in USERS:
        res = await session.execute(select(User).where(User.id == u_data["id"]))
        if res.scalar_one_or_none() is None:
            user = User(
                id=u_data["id"],
                email=u_data["email"],
                full_name=u_data["full_name"],
                hashed_password=default_pw_hash,
                status=u_data["status"],
                is_superadmin=u_data["is_superadmin"],
                created_at=now,
                updated_at=now,
            )
            session.add(user)
            stats["users"] += 1

    # 3. Seed Branches
    for b_data in BRANCHES:
        res = await session.execute(select(Branch).where(Branch.id == b_data["id"]))
        if res.scalar_one_or_none() is None:
            branch = Branch(
                id=b_data["id"],
                tenant_id=b_data["tenant_id"],
                name=b_data["name"],
                status=b_data["status"],
                created_at=now,
            )
            session.add(branch)
            stats["branches"] += 1

    # 4. Seed Memberships
    for m_data in MEMBERSHIPS:
        res = await session.execute(select(Membership).where(Membership.id == m_data["id"]))
        if res.scalar_one_or_none() is None:
            mem = Membership(
                id=m_data["id"],
                user_id=m_data["user_id"],
                tenant_id=m_data["tenant_id"],
                role=m_data["role"],
                status=m_data["status"],
                created_at=now,
            )
            session.add(mem)
            stats["memberships"] += 1

    await session.commit()
    logger.info(f"Database seed complete: {stats}")
    return stats
