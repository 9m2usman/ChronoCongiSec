"""Composite tenant-consistent foreign keys, tenant parent keys, FK indexes and tenant_id immutability.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-17

Owner: M6. Implements AMSC-DOC-005 §1 ("Tenant-safe relational references") and
the DOC-006 Day 2 M6 exit gate ("Cross-tenant foreign key inserts fail in DB").

1. Every tenant-owned table that is referenced by another tenant-owned table gets
   ``UNIQUE (tenant_id, id)``.
2. Every single-column FK between tenant-owned tables is replaced by a composite
   ``(tenant_id, <col>) REFERENCES parent (tenant_id, id)``. SET NULL references use
   ``ON DELETE SET NULL (<col>)`` (PostgreSQL 15+) so tenant_id is never cleared.
3. ``policy_decisions.incident_id`` (unconstrained in DOC-005) gets a composite FK.
4. ``(tenant_id, <col>)`` indexes back each composite FK unless one already exists.
5. A trigger on every tenant-owned table rejects any UPDATE that changes tenant_id.

Hand-written (not autogenerate order) because every parent key must exist before
any composite FK that references it, and must be dropped after them on downgrade.
The data below is frozen on purpose; do not import application models here.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that receive UNIQUE (tenant_id, id).
TENANT_PARENTS = (
    "agents",
    "tool_registrations",
    "sources",
    "memory_records",
    "memory_versions",
    "tool_proposals",
    "policy_decisions",
    "incidents",
    "checkpoints",
    "recovery_plans",
    "knowledge_entities",
    "traces",
)

# (child_table, column, parent_table, on_delete, add_index, had_plain_fk_in_0001)
TENANT_FKS = (
    ("agent_versions", "agent_id", "agents", "CASCADE", True, True),
    ("agent_tool_permissions", "agent_id", "agents", "CASCADE", True, True),
    ("agent_tool_permissions", "tool_id", "tool_registrations", "CASCADE", True, True),
    ("documents", "source_id", "sources", "CASCADE", True, True),
    ("memory_records", "agent_id", "agents", "SET NULL", True, True),
    ("memory_records", "source_id", "sources", "SET NULL", True, True),
    ("memory_versions", "record_id", "memory_records", "CASCADE", True, True),
    ("transformations", "input_record_id", "memory_records", "CASCADE", True, True),
    ("transformations", "output_record_id", "memory_records", "CASCADE", True, True),
    ("provenance_edges", "from_record_id", "memory_records", "CASCADE", False, True),
    ("provenance_edges", "to_record_id", "memory_records", "CASCADE", False, True),
    ("retrieval_events", "agent_id", "agents", "CASCADE", True, True),
    ("retrieval_events", "record_id", "memory_records", "CASCADE", True, True),
    ("tool_proposals", "agent_id", "agents", "CASCADE", True, True),
    ("policy_decisions", "proposal_id", "tool_proposals", "CASCADE", False, True),
    ("policy_decisions", "incident_id", "incidents", "SET NULL", True, False),
    ("approvals", "decision_id", "policy_decisions", "CASCADE", True, True),
    ("tool_executions", "proposal_id", "tool_proposals", "CASCADE", False, True),
    ("tool_executions", "decision_id", "policy_decisions", "CASCADE", True, True),
    ("incidents", "affected_record_id", "memory_records", "SET NULL", True, True),
    ("incidents", "agent_id", "agents", "SET NULL", True, True),
    ("incident_evidence", "incident_id", "incidents", "CASCADE", True, True),
    ("quarantines", "record_id", "memory_records", "CASCADE", True, True),
    ("quarantines", "incident_id", "incidents", "SET NULL", True, True),
    ("checkpoints", "agent_id", "agents", "SET NULL", True, True),
    ("checkpoint_items", "checkpoint_id", "checkpoints", "CASCADE", True, True),
    ("checkpoint_items", "record_id", "memory_records", "CASCADE", True, True),
    ("checkpoint_items", "version_id", "memory_versions", "CASCADE", True, True),
    ("recovery_plans", "incident_id", "incidents", "SET NULL", True, True),
    ("recovery_plans", "checkpoint_id", "checkpoints", "CASCADE", True, True),
    ("recovery_plans", "target_record_id", "memory_records", "SET NULL", True, True),
    ("recovery_actions", "plan_id", "recovery_plans", "CASCADE", True, True),
    ("knowledge_relations", "source_entity_id", "knowledge_entities", "CASCADE", True, True),
    ("knowledge_relations", "target_entity_id", "knowledge_entities", "CASCADE", True, True),
    ("drift_observations", "record_id", "memory_records", "CASCADE", True, True),
    ("traces", "agent_id", "agents", "SET NULL", True, True),
    ("trace_spans", "trace_id", "traces", "CASCADE", True, True),
)

# Every table with a tenant_id column (tenant-owned tables plus roles).
TENANT_ID_TABLES = (
    "agent_tool_permissions", "agent_versions", "agents", "approvals", "audit_events",
    "branches", "checkpoint_items", "checkpoints", "documents", "drift_observations",
    "incident_evidence", "incidents", "knowledge_entities", "knowledge_relations",
    "memberships", "memory_records", "memory_versions", "outbox_events",
    "policy_decisions", "provenance_edges", "quarantines", "recovery_actions",
    "recovery_plans", "retrieval_events", "roles", "sources", "tool_executions",
    "tool_proposals", "tool_registrations", "trace_spans", "traces", "transformations",
)

TRIGGER_FUNCTION = "amsc_forbid_tenant_id_change"
TRIGGER_NAME = "trg_forbid_tenant_id_change"


def _composite_action(column: str, on_delete: str) -> str:
    return f"SET NULL ({column})" if on_delete == "SET NULL" else on_delete


def upgrade() -> None:
    for table in TENANT_PARENTS:
        op.create_unique_constraint(f"uq_{table}_tenant_id_id", table, ["tenant_id", "id"])

    for table, column, parent, on_delete, add_index, had_plain in TENANT_FKS:
        if had_plain:
            op.drop_constraint(f"fk_{table}_{column}_{parent}", table, type_="foreignkey")
        op.create_foreign_key(
            f"fk_{table}_{column}_tenant",
            table,
            parent,
            ["tenant_id", column],
            ["tenant_id", "id"],
            ondelete=_composite_action(column, on_delete),
        )
        if add_index:
            op.create_index(f"ix_{table}_tenant_id_{column}", table, ["tenant_id", column])

    op.execute(
        f"""
        CREATE FUNCTION {TRIGGER_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
                RAISE EXCEPTION 'tenant_id is immutable on %', TG_TABLE_NAME
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    for table in TENANT_ID_TABLES:
        op.execute(
            f"CREATE TRIGGER {TRIGGER_NAME} BEFORE UPDATE OF tenant_id ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {TRIGGER_FUNCTION}()"
        )


def downgrade() -> None:
    for table in TENANT_ID_TABLES:
        op.execute(f"DROP TRIGGER {TRIGGER_NAME} ON {table}")
    op.execute(f"DROP FUNCTION {TRIGGER_FUNCTION}()")

    for table, column, parent, on_delete, add_index, had_plain in reversed(TENANT_FKS):
        if add_index:
            op.drop_index(f"ix_{table}_tenant_id_{column}", table_name=table)
        op.drop_constraint(f"fk_{table}_{column}_tenant", table, type_="foreignkey")
        if had_plain:
            op.create_foreign_key(
                f"fk_{table}_{column}_{parent}", table, parent, [column], ["id"], ondelete=on_delete
            )

    for table in reversed(TENANT_PARENTS):
        op.drop_constraint(f"uq_{table}_tenant_id_id", table, type_="unique")
