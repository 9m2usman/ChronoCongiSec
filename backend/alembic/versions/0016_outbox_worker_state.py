"""Add persistent outbox worker claiming, retry, dead-letter, and idempotency columns.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-25
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0016"
down_revision: Union[str, Sequence[str], None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "outbox_events",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "outbox_events",
        sa.Column("max_attempts", sa.Integer(), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("locked_by", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "idx_outbox_poll",
        "outbox_events",
        ["status", "next_attempt_at", "created_at"],
        unique=False,
    )
    op.create_index(
        "idx_outbox_locked_until",
        "outbox_events",
        ["status", "locked_until"],
        unique=False,
    )
    op.create_unique_constraint(
        "uq_outbox_tenant_idempotency",
        "outbox_events",
        ["tenant_id", "idempotency_key"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_outbox_tenant_idempotency", "outbox_events", type_="unique")
    op.drop_index("idx_outbox_locked_until", table_name="outbox_events")
    op.drop_index("idx_outbox_poll", table_name="outbox_events")
    op.drop_column("outbox_events", "idempotency_key")
    op.drop_column("outbox_events", "dead_lettered_at")
    op.drop_column("outbox_events", "locked_until")
    op.drop_column("outbox_events", "locked_at")
    op.drop_column("outbox_events", "locked_by")
    op.drop_column("outbox_events", "last_error")
    op.drop_column("outbox_events", "next_attempt_at")
    op.drop_column("outbox_events", "max_attempts")
    op.drop_column("outbox_events", "attempts")
