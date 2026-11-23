"""Employee registration requests and branch-scoped memberships (Phase 1 IAM).

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-22

Owner: M6 & M1. AMSC Phase 1 Identity and Access Management Specification:
1. Adds ``memberships.branch_id`` VARCHAR(36) referencing ``branches.id`` with ON DELETE SET NULL.
2. Creates ``registration_requests`` table with:
   - ``id`` VARCHAR(36) PRIMARY KEY
   - ``tenant_id`` VARCHAR(36) NOT NULL referencing ``tenants.id`` ON DELETE RESTRICT
   - ``full_name`` VARCHAR(255) NOT NULL
   - ``email`` VARCHAR(255) NOT NULL
   - ``hashed_password`` VARCHAR(255) NOT NULL
   - ``requested_branch_code`` VARCHAR(32) NOT NULL
   - ``status`` VARCHAR(32) NOT NULL DEFAULT 'PENDING'
   - ``created_at`` TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
   - ``reviewed_at`` TIMESTAMP WITH TIME ZONE NULL
   - ``reviewed_by_user_id`` VARCHAR(36) NULL referencing ``users.id`` ON DELETE SET NULL
   - ``review_reason`` TEXT NULL
   - ``assigned_role`` VARCHAR(64) NULL
   - ``assigned_branch_id`` VARCHAR(36) NULL referencing ``branches.id`` ON DELETE SET NULL
   - Constraint: ``ck_reg_requests_status`` enforcing ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')
   - Indices on ``(tenant_id, status)`` and ``(email)``
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, Sequence[str], None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

REG_STATUS_CHECK = "ck_reg_requests_status"
REG_STATUSES = ("PENDING", "APPROVED", "REJECTED", "EXPIRED")


def upgrade() -> None:
    # 1. Add branch_id to memberships table
    op.add_column(
        "memberships",
        sa.Column("branch_id", sa.String(36), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_memberships_branch_id_branches"),
        "memberships",
        "branches",
        ["branch_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        op.f("ix_memberships_branch_id"),
        "memberships",
        ["branch_id"],
        unique=False,
    )

    # 2. Create registration_requests table
    op.create_table(
        "registration_requests",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("requested_branch_code", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'PENDING'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_user_id", sa.String(36), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("assigned_role", sa.String(64), nullable=True),
        sa.Column("assigned_branch_id", sa.String(36), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_registration_requests_tenant_id_tenants"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"],
            ["users.id"],
            name=op.f("fk_registration_requests_reviewed_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_branch_id"],
            ["branches.id"],
            name=op.f("fk_registration_requests_assigned_branch_id_branches"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_registration_requests")),
    )
    op.create_index(
        "idx_reg_requests_tenant_status",
        "registration_requests",
        ["tenant_id", "status"],
        unique=False,
    )
    op.create_index(
        "idx_reg_requests_email",
        "registration_requests",
        ["email"],
        unique=False,
    )
    allowed = ", ".join(f"'{s}'" for s in REG_STATUSES)
    op.create_check_constraint(
        op.f(REG_STATUS_CHECK),
        "registration_requests",
        f"status IN ({allowed})",
    )


def downgrade() -> None:
    op.drop_constraint(op.f(REG_STATUS_CHECK), "registration_requests", type_="check")
    op.drop_index("idx_reg_requests_email", table_name="registration_requests")
    op.drop_index("idx_reg_requests_tenant_status", table_name="registration_requests")
    op.drop_table("registration_requests")

    op.drop_index(op.f("ix_memberships_branch_id"), table_name="memberships")
    op.drop_constraint(op.f("fk_memberships_branch_id_branches"), "memberships", type_="foreignkey")
    op.drop_column("memberships", "branch_id")
