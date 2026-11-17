"""Tenancy & Identity subsystem (AMSC-DOC-005 Section 3.1).

Tables: tenants, branches, users, memberships, roles, permissions, role_permissions.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    id_column,
    tenant_id_column,
)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (Index("idx_tenants_slug", "slug"),)


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_tenant_branch_code"),
        Index("idx_branches_tenant", "tenant_id"),
    )


class User(Base):
    """Global identity. Tenant access is granted only through ``memberships``."""

    __tablename__ = "users"

    id: Mapped[str] = id_column()
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (Index("idx_users_email", "email"),)


# Membership lifecycle (M6 migration 0003). Only ACTIVE grants tenant access;
# M1 enforces that at login, the database only guarantees a known value.
MEMBERSHIP_STATUSES = ("ACTIVE", "INACTIVE", "SUSPENDED", "REVOKED")


class Membership(Base):
    """A user's access grant to one tenant.

    ``status`` defaults to ACTIVE for new rows. Rows that existed before
    migration 0003 were backfilled to INACTIVE (their status was unknown).
    Revoke access by setting ``status``, not by deleting the row: approvals
    reference the membership with ON DELETE RESTRICT.
    """

    __tablename__ = "memberships"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    user_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'SECURITY_ANALYST'")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user"),
        Index("idx_memberships_tenant_user", "tenant_id", "user_id"),
        CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in MEMBERSHIP_STATUSES) + ")",
            name="status",
        ),
    )


class Role(Base):
    """Role catalog. ``tenant_id`` NULL means a platform-global role (the only nullable tenant_id)."""

    __tablename__ = "roles"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_column()


class Permission(Base):
    """Global permission catalog (e.g. 'memory:quarantine')."""

    __tablename__ = "permissions"

    id: Mapped[str] = id_column()
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )
