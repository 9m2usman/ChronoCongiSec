"""Gateway chain integrity: execution decision belongs to its proposal; RESTRICT deletes.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-18

Owner: M6. DOC-006 Day 4 M6 row ("No tool execution recorded without decision") and
GAP-008 (uniqueness/integrity constraints for the proposal -> decision -> execution chain).

1. ``policy_decisions`` gets the parent key ``UNIQUE (tenant_id, proposal_id, id)``, and
   ``tool_executions (tenant_id, proposal_id, decision_id)`` references it
   (``fk_tool_executions_decision_matches_proposal``, ON DELETE RESTRICT). Before, the
   two-column FKs only proved "same tenant": an execution could cite the decision of a
   DIFFERENT proposal.
2. The gateway chain becomes ON DELETE RESTRICT (it was CASCADE), so deleting a proposal
   or a decision can no longer erase decisions, approvals or executions (forensic evidence):
   - policy_decisions.proposal_id -> tool_proposals
   - approvals.decision_id        -> policy_decisions
   - tool_executions.proposal_id  -> tool_proposals
   - tool_executions.decision_id  -> policy_decisions

Deliberately NOT included: CHECK constraints on decision / execution_status / status
values and any "execution only if ALLOW" rule. Those depend on M1/M2/M4 decisions and are
tracked in OPEN-DEPENDENCIES (M6 progress log) for the final integration migration.

Pre-check: if an existing execution cites a decision of another proposal, the upgrade
stops with the execution ids and changes nothing. Offline (``--sql``) mode skips the
pre-check; PostgreSQL would still refuse the FK.

Downgrade restores the exact 0006 state (CASCADE rules, no 3-column FK, no parent key).
No rows are deleted in either direction.
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DECISION_PARENT_KEY = "uq_policy_decisions_tenant_id_proposal_id_id"
EXECUTION_DECISION_FK = "fk_tool_executions_decision_matches_proposal"

# (child_table, column, parent_table): two-column tenant FKs that change CASCADE -> RESTRICT.
GATEWAY_CHAIN = (
    ("policy_decisions", "proposal_id", "tool_proposals"),
    ("approvals", "decision_id", "policy_decisions"),
    ("tool_executions", "proposal_id", "tool_proposals"),
    ("tool_executions", "decision_id", "policy_decisions"),
)

MAX_REPORTED_IDS = 20


def _set_chain_rule(table: str, column: str, parent: str, rule: str) -> None:
    name = f"fk_{table}_{column}_tenant"
    op.drop_constraint(name, table, type_="foreignkey")
    op.create_foreign_key(name, table, parent, ["tenant_id", column], ["tenant_id", "id"], ondelete=rule)


def _check_executions_match_their_proposal() -> None:
    if context.is_offline_mode():
        return
    mismatched = op.get_bind().execute(sa.text(
        f"""
        SELECT e.id FROM tool_executions e
        JOIN policy_decisions d ON d.tenant_id = e.tenant_id AND d.id = e.decision_id
        WHERE d.proposal_id <> e.proposal_id
        ORDER BY e.id LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if mismatched:
        raise RuntimeError(
            "Migration 0007 stopped: these tool_executions cite a decision that belongs to a "
            f"different proposal: {mismatched}. Nothing was changed; fix them manually."
        )


def upgrade() -> None:
    _check_executions_match_their_proposal()

    op.create_unique_constraint(op.f(DECISION_PARENT_KEY), "policy_decisions", ["tenant_id", "proposal_id", "id"])
    op.create_foreign_key(
        op.f(EXECUTION_DECISION_FK),
        "tool_executions",
        "policy_decisions",
        ["tenant_id", "proposal_id", "decision_id"],
        ["tenant_id", "proposal_id", "id"],
        ondelete="RESTRICT",
    )
    for table, column, parent in GATEWAY_CHAIN:
        _set_chain_rule(table, column, parent, "RESTRICT")


def downgrade() -> None:
    for table, column, parent in reversed(GATEWAY_CHAIN):
        _set_chain_rule(table, column, parent, "CASCADE")
    op.drop_constraint(op.f(EXECUTION_DECISION_FK), "tool_executions", type_="foreignkey")
    op.drop_constraint(op.f(DECISION_PARENT_KEY), "policy_decisions", type_="unique")
