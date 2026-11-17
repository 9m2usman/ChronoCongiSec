"""Require each checkpoint item to reference a version of its own memory record.

Revision ID: 0005
Revises: 0004
Owner: M6 — Database Architect & Governance.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0005"
down_revision: Union[str, Sequence[str], None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The three-column FK below needs a matching unique parent key. The id
    # column is already globally unique, but PostgreSQL requires an explicit
    # unique key over the exact referenced column set.
    op.create_unique_constraint(
        "uq_memory_versions_tenant_record_id",
        "memory_versions",
        ["tenant_id", "record_id", "id"],
    )
    op.create_foreign_key(
        "fk_checkpoint_items_version_matches_record",
        "checkpoint_items",
        "memory_versions",
        ["tenant_id", "record_id", "version_id"],
        ["tenant_id", "record_id", "id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_checkpoint_items_tenant_record_version",
        "checkpoint_items",
        ["tenant_id", "record_id", "version_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_checkpoint_items_tenant_record_version",
        table_name="checkpoint_items",
    )
    op.drop_constraint(
        "fk_checkpoint_items_version_matches_record",
        "checkpoint_items",
        type_="foreignkey",
    )
    op.drop_constraint(
        "uq_memory_versions_tenant_record_id",
        "memory_versions",
        type_="unique",
    )
