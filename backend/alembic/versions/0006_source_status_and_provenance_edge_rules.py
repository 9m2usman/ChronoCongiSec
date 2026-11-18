"""Source lifecycle status and provenance edge integrity rules (requested by M3).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-18

Owner: M6.

1. ``sources.status`` VARCHAR(32) NOT NULL with ``CHECK (status IN ('ACTIVE', 'INACTIVE'))``
   (``ck_sources_status``). GAP-003 requires ingestion to accept only ACTIVE sources;
   DOC-005 has no such column, so M3 requested it. Rows that already exist become
   INACTIVE (their status is unknown and must never be silently activated); new
   rows default to ACTIVE. ``trust_state`` is unchanged and remains separate.
2. ``provenance_edges``:
   - ``CHECK (relation_type IN ('DERIVED_FROM', 'TRANSFORMED_INTO', 'SUPERSEDES'))``
     (DOC-005 Table 14, TRD section 15.2);
   - ``UNIQUE (tenant_id, from_record_id, to_record_id, relation_type)``: the same
     directed edge cannot be stored twice. Direction is not normalised: A->B and
     B->A are different edges;
   - ``CHECK (from_record_id <> to_record_id)``: no self-loops.

Pre-check: before any change, the upgrade looks for existing rows that would break
rule 2 (duplicates, self-loops, unknown relation types). If it finds any, it stops
with the offending ids and changes nothing. It never deletes or rewrites data.
In offline mode (``alembic upgrade --sql``) the pre-check cannot query data and is
skipped; PostgreSQL still refuses the constraints if violating rows exist.

Downgrade: drops the three provenance constraints and the ``sources.status`` column.
The stored status values are lost; a later upgrade sets every existing source to
INACTIVE again, so sources must be re-activated explicitly. No rows are deleted.
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0006"
down_revision: Union[str, Sequence[str], None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SOURCE_STATUSES = ("ACTIVE", "INACTIVE")
RELATION_TYPES = ("DERIVED_FROM", "TRANSFORMED_INTO", "SUPERSEDES")

SOURCE_STATUS_CHECK = "ck_sources_status"
RELATION_TYPE_CHECK = "ck_provenance_edges_relation_type"
SELF_LOOP_CHECK = "ck_provenance_edges_no_self_loop"
EDGE_UNIQUE = "uq_provenance_edges_tenant_from_to_relation"

MAX_REPORTED_IDS = 20


def _in_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _check_existing_edges() -> None:
    """Stop (without changing anything) if existing provenance edges violate the new rules."""
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    problems = []

    duplicates = bind.execute(sa.text(
        f"""
        SELECT array_agg(id ORDER BY id) AS ids
        FROM provenance_edges
        GROUP BY tenant_id, from_record_id, to_record_id, relation_type
        HAVING count(*) > 1
        ORDER BY min(id)
        LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if duplicates:
        problems.append(f"duplicate edges (same tenant, from, to, relation_type): {duplicates}")

    self_loops = bind.execute(sa.text(
        f"SELECT id FROM provenance_edges WHERE from_record_id = to_record_id ORDER BY id LIMIT {MAX_REPORTED_IDS}"
    )).scalars().all()
    if self_loops:
        problems.append(f"self-loop edges (from_record_id = to_record_id): {self_loops}")

    bad_types = bind.execute(sa.text(
        f"""
        SELECT id FROM provenance_edges
        WHERE relation_type NOT IN ({_in_list(RELATION_TYPES)})
        ORDER BY id LIMIT {MAX_REPORTED_IDS}
        """
    )).scalars().all()
    if bad_types:
        problems.append(f"unknown relation_type: {bad_types}")

    if problems:
        raise RuntimeError(
            "Migration 0006 stopped: existing provenance_edges rows violate the new rules. "
            "Nothing was changed; review these rows with M3 and fix them manually. "
            + " | ".join(problems)
        )


def upgrade() -> None:
    _check_existing_edges()

    # 1. Source lifecycle status: existing rows -> INACTIVE, then new rows default to ACTIVE.
    op.add_column(
        "sources",
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'INACTIVE'")),
    )
    op.alter_column("sources", "status", server_default=sa.text("'ACTIVE'"))
    op.create_check_constraint(op.f(SOURCE_STATUS_CHECK), "sources", f"status IN ({_in_list(SOURCE_STATUSES)})")

    # 2. Provenance edge rules.
    op.create_check_constraint(
        op.f(RELATION_TYPE_CHECK), "provenance_edges", f"relation_type IN ({_in_list(RELATION_TYPES)})"
    )
    op.create_check_constraint(op.f(SELF_LOOP_CHECK), "provenance_edges", "from_record_id <> to_record_id")
    op.create_unique_constraint(
        op.f(EDGE_UNIQUE), "provenance_edges", ["tenant_id", "from_record_id", "to_record_id", "relation_type"]
    )


def downgrade() -> None:
    op.drop_constraint(op.f(EDGE_UNIQUE), "provenance_edges", type_="unique")
    op.drop_constraint(op.f(SELF_LOOP_CHECK), "provenance_edges", type_="check")
    op.drop_constraint(op.f(RELATION_TYPE_CHECK), "provenance_edges", type_="check")

    op.drop_constraint(op.f(SOURCE_STATUS_CHECK), "sources", type_="check")
    op.drop_column("sources", "status")
