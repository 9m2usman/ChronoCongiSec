"""Enforce tenant-consistent branch and reviewer references for Phase 1 IAM.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-23

Migration 0011 introduced branch-scoped memberships and registration requests.
This migration closes the tenant-isolation gap left by its single-column branch
and reviewer foreign keys, adds tenant_id immutability for registration requests,
and aligns the membership branch index with SQLAlchemy metadata.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, Sequence[str], None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TRIGGER_NAME = "trg_forbid_tenant_id_change"


def upgrade() -> None:
    # Branch IDs are globally unique, but PostgreSQL still requires the exact
    # composite parent key for tenant-consistent foreign keys.
    op.create_unique_constraint(
        "uq_branches_tenant_id_id",
        "branches",
        ["tenant_id", "id"],
    )

    # Membership branch scope must match the membership's tenant.
    op.drop_constraint(
        "fk_memberships_branch_id_branches",
        "memberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_memberships_branch_tenant",
        "memberships",
        "branches",
        ["tenant_id", "branch_id"],
        ["tenant_id", "id"],
        ondelete="SET NULL (branch_id)",
    )
    op.drop_index("ix_memberships_branch_id", table_name="memberships")
    op.create_index(
        "idx_memberships_branch",
        "memberships",
        ["tenant_id", "branch_id"],
        unique=False,
    )

    # Registration reviewers must be members of the request's tenant.
    # The original users FK remains as the global identity existence check.
    op.create_foreign_key(
        "fk_registration_requests_reviewed_by_membership",
        "registration_requests",
        "memberships",
        ["tenant_id", "reviewed_by_user_id"],
        ["tenant_id", "user_id"],
        ondelete="RESTRICT",
    )

    # An assigned branch must belong to the same tenant as the request.
    op.drop_constraint(
        "fk_registration_requests_assigned_branch_id_branches",
        "registration_requests",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_registration_requests_assigned_branch_tenant",
        "registration_requests",
        "branches",
        ["tenant_id", "assigned_branch_id"],
        ["tenant_id", "id"],
        ondelete="SET NULL (assigned_branch_id)",
    )

    op.create_index(
        "ix_registration_requests_tenant_id_reviewed_by_user_id",
        "registration_requests",
        ["tenant_id", "reviewed_by_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_registration_requests_tenant_id_assigned_branch_id",
        "registration_requests",
        ["tenant_id", "assigned_branch_id"],
        unique=False,
    )

    # Migration 0002's trigger predates this tenant-owned table.
    op.execute(
        f"CREATE TRIGGER {TRIGGER_NAME} "
        "BEFORE UPDATE OF tenant_id ON registration_requests "
        "FOR EACH ROW EXECUTE FUNCTION amsc_forbid_tenant_id_change()"
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER {TRIGGER_NAME} ON registration_requests")

    op.drop_index(
        "ix_registration_requests_tenant_id_assigned_branch_id",
        table_name="registration_requests",
    )
    op.drop_index(
        "ix_registration_requests_tenant_id_reviewed_by_user_id",
        table_name="registration_requests",
    )

    op.drop_constraint(
        "fk_registration_requests_assigned_branch_tenant",
        "registration_requests",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_registration_requests_assigned_branch_id_branches",
        "registration_requests",
        "branches",
        ["assigned_branch_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint(
        "fk_registration_requests_reviewed_by_membership",
        "registration_requests",
        type_="foreignkey",
    )

    op.drop_index("idx_memberships_branch", table_name="memberships")
    op.drop_constraint(
        "fk_memberships_branch_tenant",
        "memberships",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_memberships_branch_id_branches",
        "memberships",
        "branches",
        ["branch_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_memberships_branch_id",
        "memberships",
        ["branch_id"],
        unique=False,
    )

    op.drop_constraint(
        "uq_branches_tenant_id_id",
        "branches",
        type_="unique",
    )
