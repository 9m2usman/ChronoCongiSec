"""Create the persisted employee company application schema.

Revision ID: 0017
Revises: 0016
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: Union[str, Sequence[str], None] = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "company_workspaces",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("branch_id", sa.String(36), nullable=False),
        sa.Column("owner_user_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("visibility", sa.String(16), nullable=False, server_default=sa.text("'PRIVATE'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_company_workspaces_tenant_id"),
        sa.UniqueConstraint("tenant_id", "branch_id", "owner_user_id", "name", name="uq_company_workspace_owner_name"),
        sa.CheckConstraint("visibility IN ('PRIVATE', 'BRANCH')", name="ck_company_workspaces_visibility"),
        sa.ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_workspaces_branch_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "owner_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_workspaces_owner_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_workspaces_tenant_branch", "company_workspaces", ["tenant_id", "branch_id"])
    op.create_index("idx_company_workspaces_owner", "company_workspaces", ["tenant_id", "owner_user_id"])

    op.create_table(
        "company_files",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("owner_user_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(128), nullable=False, server_default=sa.text("'text/plain'")),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "id", name="uq_company_files_tenant_id"),
        sa.CheckConstraint("current_version >= 1", name="ck_company_files_current_version_positive"),
        sa.CheckConstraint("status IN ('ACTIVE', 'DELETED')", name="ck_company_files_status"),
        sa.ForeignKeyConstraint(["tenant_id", "workspace_id"], ["company_workspaces.tenant_id", "company_workspaces.id"], name="fk_company_files_workspace_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "owner_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_files_owner_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_files_tenant_workspace", "company_files", ["tenant_id", "workspace_id"])

    op.create_table(
        "company_file_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("file_id", sa.String(36), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "file_id", "version_number", name="uq_company_file_version_number"),
        sa.ForeignKeyConstraint(["tenant_id", "file_id"], ["company_files.tenant_id", "company_files.id"], name="fk_company_file_versions_file_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "created_by_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_versions_creator_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_file_versions_file", "company_file_versions", ["tenant_id", "file_id", "version_number"])

    op.create_table(
        "company_file_transfers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("file_id", sa.String(36), nullable=False),
        sa.Column("sender_user_id", sa.String(36), nullable=False),
        sa.Column("recipient_user_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'PENDING'")),
        sa.Column("message", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("responded_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED')", name="ck_company_file_transfers_status"),
        sa.CheckConstraint("sender_user_id <> recipient_user_id", name="ck_company_file_transfers_different_participants"),
        sa.ForeignKeyConstraint(["tenant_id", "file_id"], ["company_files.tenant_id", "company_files.id"], name="fk_company_file_transfers_file_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "sender_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_transfers_sender_membership", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "recipient_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_file_transfers_recipient_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_file_transfers_recipient", "company_file_transfers", ["tenant_id", "recipient_user_id", "status"])

    op.create_table(
        "company_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("branch_id", sa.String(36), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(24), nullable=False, server_default=sa.text("'OPEN'")),
        sa.Column("priority", sa.String(16), nullable=False, server_default=sa.text("'NORMAL'")),
        sa.Column("created_by_user_id", sa.String(36), nullable=False),
        sa.Column("assigned_to_user_id", sa.String(36)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_company_tasks_tenant_id"),
        sa.CheckConstraint("status IN ('OPEN', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'CANCELLED')", name="ck_company_tasks_status"),
        sa.CheckConstraint("priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')", name="ck_company_tasks_priority"),
        sa.ForeignKeyConstraint(["tenant_id", "workspace_id"], ["company_workspaces.tenant_id", "company_workspaces.id"], name="fk_company_tasks_workspace_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_tasks_branch_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "created_by_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_tasks_creator_membership", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "assigned_to_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_tasks_assignee_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_tasks_branch_status", "company_tasks", ["tenant_id", "branch_id", "status"])
    op.create_index("idx_company_tasks_assignee", "company_tasks", ["tenant_id", "assigned_to_user_id", "status"])

    op.create_table(
        "company_task_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("task_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "task_id"], ["company_tasks.tenant_id", "company_tasks.id"], name="fk_company_task_events_task_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "actor_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_task_events_actor_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_task_events_task", "company_task_events", ["tenant_id", "task_id", "created_at"])

    op.create_table(
        "company_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("sender_user_id", sa.String(36), nullable=False),
        sa.Column("recipient_user_id", sa.String(36), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False, server_default=sa.text("''")),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'SENT'")),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('SENT', 'READ')", name="ck_company_messages_status"),
        sa.CheckConstraint("sender_user_id <> recipient_user_id", name="ck_company_messages_different_participants"),
        sa.ForeignKeyConstraint(["tenant_id", "sender_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_messages_sender_membership", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "recipient_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_messages_recipient_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_messages_inbox", "company_messages", ["tenant_id", "recipient_user_id", "sent_at"])

    op.create_table(
        "company_notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("body", sa.String(1000), nullable=False),
        sa.Column("resource_type", sa.String(64)),
        sa.Column("resource_id", sa.String(128)),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_notifications_user_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_notifications_user", "company_notifications", ["tenant_id", "user_id", "read_at", "created_at"])

    op.create_table(
        "company_activity",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("branch_id", sa.String(36)),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "branch_id"], ["branches.tenant_id", "branches.id"], name="fk_company_activity_branch_tenant", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "actor_user_id"], ["memberships.tenant_id", "memberships.user_id"], name="fk_company_activity_actor_membership", ondelete="RESTRICT"),
    )
    op.create_index("idx_company_activity_timeline", "company_activity", ["tenant_id", "branch_id", "created_at"])


def downgrade() -> None:
    for table in (
        "company_activity", "company_notifications", "company_messages",
        "company_task_events", "company_tasks", "company_file_transfers",
        "company_file_versions", "company_files", "company_workspaces",
    ):
        op.drop_table(table)
