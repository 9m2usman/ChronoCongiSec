"""Membership status, tenant-consistent approver and forensic delete protection.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-17

Owner: M6. Security hardening of the Day 1-2 schema (review of PR #5).

1. ``memberships.status`` VARCHAR(32) NOT NULL with
   ``CHECK (status IN ('ACTIVE','INACTIVE','SUSPENDED','REVOKED'))``.
   Rows that already exist are backfilled to INACTIVE (their status is unknown, so
   they must never be silently activated). New rows default to ACTIVE.
2. ``approvals.approver_user_id``: the plain FK to global ``users`` is replaced by
   ``(tenant_id, approver_user_id) -> memberships (tenant_id, user_id) ON DELETE
   RESTRICT``. The approver must belong to the approval's tenant, and a membership
   that approved something cannot be deleted (revoke it via ``status``). NULL
   (unassigned approval) stays allowed.
3. Forensic evidence can no longer be erased by a cascade:
   - ``tenant_id -> tenants.id`` becomes ON DELETE RESTRICT on audit_events,
     incidents, incident_evidence, tool_proposals, policy_decisions, approvals and
     tool_executions;
   - ``tool_proposals.agent_id`` becomes ON DELETE RESTRICT (agents are isolated,
     not deleted).

Upgrade stops with a clear error, and changes nothing, if an existing approval
names an approver who is not a member of the approval's tenant.
Downgrade restores the exact 0002 schema (the status column and its values are dropped).
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

MEMBERSHIP_STATUSES = ("ACTIVE", "INACTIVE", "SUSPENDED", "REVOKED")
STATUS_CHECK = "ck_memberships_status"

# Tables whose tenant_id FK changes CASCADE -> RESTRICT.
FORENSIC_TENANT_TABLES = (
    "audit_events",
    "incidents",
    "incident_evidence",
    "tool_proposals",
    "policy_decisions",
    "approvals",
    "tool_executions",
)

APPROVER_PLAIN_FK = "fk_approvals_approver_user_id_users"
APPROVER_TENANT_FK = "fk_approvals_approver_user_id_tenant"
APPROVER_INDEX = "ix_approvals_tenant_id_approver_user_id"
PROPOSAL_AGENT_FK = "fk_tool_proposals_agent_id_tenant"


def _tenant_fk(table: str) -> str:
    return f"fk_{table}_tenant_id_tenants"


def _set_tenant_delete_rule(table: str, rule: str) -> None:
    op.drop_constraint(_tenant_fk(table), table, type_="foreignkey")
    op.create_foreign_key(_tenant_fk(table), table, "tenants", ["tenant_id"], ["id"], ondelete=rule)


def _set_proposal_agent_rule(rule: str) -> None:
    op.drop_constraint(PROPOSAL_AGENT_FK, "tool_proposals", type_="foreignkey")
    op.create_foreign_key(
        PROPOSAL_AGENT_FK, "tool_proposals", "agents",
        ["tenant_id", "agent_id"], ["tenant_id", "id"], ondelete=rule,
    )


def _check_approvers_are_members() -> None:
    if context.is_offline_mode():
        return
    orphans = op.get_bind().execute(sa.text(
        """
        SELECT a.id FROM approvals a
        WHERE a.approver_user_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM memberships m
                          WHERE m.tenant_id = a.tenant_id AND m.user_id = a.approver_user_id)
        ORDER BY a.id LIMIT 20
        """
    )).scalars().all()
    if orphans:
        raise RuntimeError(
            "Migration 0003 stopped: these approvals name an approver who is not a member of "
            f"the approval's tenant: {orphans}. Fix or confirm them manually; nothing was changed."
        )


def upgrade() -> None:
    _check_approvers_are_members()

    # 1. Membership status: existing rows -> INACTIVE, then new rows default to ACTIVE.
    op.add_column(
        "memberships",
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'INACTIVE'")),
    )
    op.alter_column("memberships", "status", server_default=sa.text("'ACTIVE'"))
    allowed = ", ".join(f"'{s}'" for s in MEMBERSHIP_STATUSES)
    op.create_check_constraint(op.f(STATUS_CHECK), "memberships", f"status IN ({allowed})")

    # 2. Approver must be a member of the same tenant.
    op.drop_constraint(APPROVER_PLAIN_FK, "approvals", type_="foreignkey")
    op.create_foreign_key(
        APPROVER_TENANT_FK, "approvals", "memberships",
        ["tenant_id", "approver_user_id"], ["tenant_id", "user_id"], ondelete="RESTRICT",
    )
    op.create_index(APPROVER_INDEX, "approvals", ["tenant_id", "approver_user_id"])

    # 3. Forensic evidence is never removed by a cascade.
    for table in FORENSIC_TENANT_TABLES:
        _set_tenant_delete_rule(table, "RESTRICT")
    _set_proposal_agent_rule("RESTRICT")


def downgrade() -> None:
    _set_proposal_agent_rule("CASCADE")
    for table in reversed(FORENSIC_TENANT_TABLES):
        _set_tenant_delete_rule(table, "CASCADE")

    op.drop_index(APPROVER_INDEX, table_name="approvals")
    op.drop_constraint(APPROVER_TENANT_FK, "approvals", type_="foreignkey")
    op.create_foreign_key(
        APPROVER_PLAIN_FK, "approvals", "users", ["approver_user_id"], ["id"], ondelete="SET NULL"
    )

    op.drop_constraint(op.f(STATUS_CHECK), "memberships", type_="check")
    op.drop_column("memberships", "status")
