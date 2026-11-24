"""Detection Results and Security Decision Engine (Phase 2).

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-24

Implements Phase 2 Deliverables:
- detection_results: durable, auditable record of security detections, classification,
  evidence items, and recommended outcomes.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: Union[str, Sequence[str], None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detection_results",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("detection_category", sa.String(length=64), nullable=False),
        sa.Column("classification_type", sa.String(length=32), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=True),
        sa.Column("profile_version", sa.String(length=32), nullable=True),
        sa.Column("execution_id", sa.String(length=128), nullable=True),
        sa.Column("task_id", sa.String(length=128), nullable=True),
        sa.Column("trace_id", sa.String(length=128), nullable=True),
        sa.Column("action_id", sa.String(length=128), nullable=True),
        sa.Column("detection_method", sa.String(length=64), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("uncertainty_state", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("recommended_outcome", sa.String(length=32), nullable=False),
        sa.Column("policy_decision_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'DETECTED'")),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "memory_refs_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "baseline_refs_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "evidence_items_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "details_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "id", name="uq_detection_results_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_detection_results_branch_tenant",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "detection_category IN ('MEMORY_INTEGRITY', 'PROMPT_INJECTION', 'PROVENANCE_INTEGRITY', 'KNOWLEDGE_INTEGRITY', 'SEMANTIC_INTEGRITY', 'BEHAVIORAL_DEVIATION', 'TOOL_EXECUTION_THREAT')",
            name="ck_detection_category",
        ),
        sa.CheckConstraint(
            "classification_type IN ('OBSERVATION', 'SUSPICIOUS_INDICATOR', 'CONFIRMED_POLICY_VIOLATION', 'CONFIRMED_SECURITY_INCIDENT')",
            name="ck_detection_classification_type",
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name="ck_detection_severity",
        ),
        sa.CheckConstraint(
            "recommended_outcome IN ('ALLOW', 'BLOCK', 'REQUIRE_HUMAN_APPROVAL', 'QUARANTINE_RECORD', 'ALERT_ONLY')",
            name="ck_detection_recommended_outcome",
        ),
        sa.CheckConstraint(
            "status IN ('DETECTED', 'EVALUATED', 'CONFIRMED_VIOLATION', 'CONFIRMED_INCIDENT', 'DISMISSED_FALSE_POSITIVE', 'RESOLVED')",
            name="ck_detection_status",
        ),
    )
    op.create_index("idx_det_tenant_created", "detection_results", ["tenant_id", "created_at"])
    op.create_index("idx_det_tenant_category", "detection_results", ["tenant_id", "detection_category"])
    op.create_index("idx_det_tenant_agent", "detection_results", ["tenant_id", "agent_id"])
    op.create_index("idx_det_tenant_trace", "detection_results", ["tenant_id", "trace_id"])
    op.create_index("idx_det_tenant_status", "detection_results", ["tenant_id", "status"])
    op.create_index("idx_det_tenant_classification", "detection_results", ["tenant_id", "classification_type"])


def downgrade() -> None:
    op.drop_index("idx_det_tenant_classification", table_name="detection_results")
    op.drop_index("idx_det_tenant_status", table_name="detection_results")
    op.drop_index("idx_det_tenant_trace", table_name="detection_results")
    op.drop_index("idx_det_tenant_agent", table_name="detection_results")
    op.drop_index("idx_det_tenant_category", table_name="detection_results")
    op.drop_index("idx_det_tenant_created", table_name="detection_results")
    op.drop_table("detection_results")
