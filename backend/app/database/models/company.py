"""Persistent employee-facing company application records.

All records are tenant scoped and reference branch/membership identities using
composite foreign keys. File content is versioned in PostgreSQL for the MVP;
no filesystem paths are exposed by this domain.
"""
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint, DateTime, ForeignKeyConstraint, Index, Integer,
    String, Text, UniqueConstraint, text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH, NOW, Base, created_at_column, id_column,
    jsonb_object_column, tenant_id_column, tenant_parent_key,
)


class CompanyWorkspace(Base):
    __tablename__ = "company_workspaces"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    branch_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    owner_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'PRIVATE'"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)
    __table_args__ = (
        tenant_parent_key(),
        UniqueConstraint("tenant_id", "branch_id", "owner_user_id", "name", name="uq_company_workspace_owner_name"),
        CheckConstraint("visibility IN ('PRIVATE', 'BRANCH')", name="visibility"),
        ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_workspaces_branch_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "owner_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_workspaces_owner_membership", ondelete="RESTRICT"),
        Index("idx_company_workspaces_tenant_branch", "tenant_id", "branch_id"),
        Index("idx_company_workspaces_owner", "tenant_id", "owner_user_id"),
    )


class CompanyFile(Base):
    __tablename__ = "company_files"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    workspace_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    owner_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False, server_default=text("'text/plain'"))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'ACTIVE'"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        tenant_parent_key(),
        CheckConstraint("current_version >= 1", name="current_version_positive"),
        CheckConstraint("status IN ('ACTIVE', 'DELETED')", name="status"),
        ForeignKeyConstraint(["tenant_id", "workspace_id"], ["company_workspaces.tenant_id", "company_workspaces.id"], name="fk_company_files_workspace_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "owner_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_files_owner_membership", ondelete="RESTRICT"),
        Index("idx_company_files_tenant_workspace", "tenant_id", "workspace_id"),
        Index("idx_company_files_owner", "tenant_id", "owner_user_id"),
    )


class CompanyFileVersion(Base):
    __tablename__ = "company_file_versions"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    file_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    created_at: Mapped[datetime] = created_at_column()
    __table_args__ = (
        UniqueConstraint("tenant_id", "file_id", "version_number", name="uq_company_file_version_number"),
        ForeignKeyConstraint(["tenant_id", "file_id"], ["company_files.tenant_id", "company_files.id"], name="fk_company_file_versions_file_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "created_by_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_versions_creator_membership", ondelete="RESTRICT"),
        Index("idx_company_file_versions_file", "tenant_id", "file_id", "version_number"),
        Index("idx_company_file_versions_creator", "tenant_id", "created_by_user_id"),
    )


class CompanyFileTransfer(Base):
    __tablename__ = "company_file_transfers"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    file_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    sender_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    recipient_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'PENDING'"))
    message: Mapped[Optional[str]] = mapped_column(String(500))
    created_at: Mapped[datetime] = created_at_column()
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED')", name="status"),
        CheckConstraint("sender_user_id <> recipient_user_id", name="different_participants"),
        ForeignKeyConstraint(["tenant_id", "file_id"], ["company_files.tenant_id", "company_files.id"], name="fk_company_file_transfers_file_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "sender_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_transfers_sender_membership", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "recipient_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_transfers_recipient_membership", ondelete="RESTRICT"),
        Index("idx_company_file_transfers_file", "tenant_id", "file_id"),
        Index("idx_company_file_transfers_sender", "tenant_id", "sender_user_id"),
        Index("idx_company_file_transfers_recipient", "tenant_id", "recipient_user_id", "status"),
    )


class CompanyTask(Base):
    __tablename__ = "company_tasks"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    workspace_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    branch_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default=text("'OPEN'"))
    priority: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'NORMAL'"))
    created_by_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    assigned_to_user_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)
    __table_args__ = (
        tenant_parent_key(),
        CheckConstraint("status IN ('OPEN', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'CANCELLED')", name="status"),
        CheckConstraint("priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')", name="priority"),
        ForeignKeyConstraint(["tenant_id", "workspace_id"], ["company_workspaces.tenant_id", "company_workspaces.id"], name="fk_company_tasks_workspace_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_tasks_branch_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "created_by_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_tasks_creator_membership", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "assigned_to_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_tasks_assignee_membership", ondelete="RESTRICT"),
        Index("idx_company_tasks_workspace", "tenant_id", "workspace_id"),
        Index("idx_company_tasks_branch_status", "tenant_id", "branch_id", "status"),
        Index("idx_company_tasks_creator", "tenant_id", "created_by_user_id"),
        Index("idx_company_tasks_assignee", "tenant_id", "assigned_to_user_id", "status"),
    )


class CompanyTaskEvent(Base):
    __tablename__ = "company_task_events"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    task_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "task_id"], ["company_tasks.tenant_id", "company_tasks.id"], name="fk_company_task_events_task_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "actor_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_task_events_actor_membership", ondelete="RESTRICT"),
        Index("idx_company_task_events_task", "tenant_id", "task_id", "created_at"),
        Index("idx_company_task_events_actor", "tenant_id", "actor_user_id"),
    )


class CompanyMessage(Base):
    __tablename__ = "company_messages"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    sender_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    recipient_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, server_default=text("''"))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'SENT'"))
    sent_at: Mapped[datetime] = created_at_column()
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        CheckConstraint("status IN ('SENT', 'READ')", name="status"),
        CheckConstraint("sender_user_id <> recipient_user_id", name="different_participants"),
        ForeignKeyConstraint(["tenant_id", "sender_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_messages_sender_membership", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "recipient_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_messages_recipient_membership", ondelete="RESTRICT"),
        Index("idx_company_messages_sender", "tenant_id", "sender_user_id"),
        Index("idx_company_messages_inbox", "tenant_id", "recipient_user_id", "sent_at"),
    )


class CompanyNotification(Base):
    __tablename__ = "company_notifications"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(String(1000), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64))
    resource_id: Mapped[Optional[str]] = mapped_column(String(128))
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_notifications_user_membership", ondelete="RESTRICT"),
        Index("idx_company_notifications_user", "tenant_id", "user_id", "read_at", "created_at"),
    )


class CompanyActivity(Base):
    __tablename__ = "company_activity"
    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    actor_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_activity_branch_tenant", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "actor_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_activity_actor_membership", ondelete="RESTRICT"),
        Index("idx_company_activity_timeline", "tenant_id", "branch_id", "created_at"),
        Index("idx_company_activity_actor", "tenant_id", "actor_user_id"),
    )
