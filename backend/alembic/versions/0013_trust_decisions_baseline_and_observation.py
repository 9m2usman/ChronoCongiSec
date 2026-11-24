"""Enterprise Baseline, Agent Profiles, Trust Decisions and Observation Foundation.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-24

Implements Phase 1 Deliverables:
- trust_decisions: durable storage for memory trust evaluations (VULN-001 / OPEN-02)
- enterprise_baseline_records: independently governed authoritative enterprise knowledge & policies
- enterprise_baseline_versions: immutable, versioned baseline content snapshots with SHA-256 digests
- baseline_governance_logs: auditable governance operations
- agent_security_profiles: authoritative agent security profiles (purpose, goals, branch, restrictions)
- observation_events: structured observation & telemetry foundation with idempotent deduplication
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, Sequence[str], None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. trust_decisions table
    op.create_table(
        "trust_decisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("record_id", sa.String(length=36), nullable=False),
        sa.Column("from_state", sa.String(length=32), nullable=False),
        sa.Column("to_state", sa.String(length=32), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column(
            "evidence_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_trust_decisions_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "record_id"],
            ["memory_records.tenant_id", "memory_records.id"],
            name="fk_trust_decisions_record_tenant",
            ondelete="CASCADE",
        ),
    )
    op.create_index("idx_trust_decisions_tenant_record", "trust_decisions", ["tenant_id", "record_id"])
    op.create_index("idx_trust_decisions_tenant_created", "trust_decisions", ["tenant_id", "created_at"])

    # 2. enterprise_baseline_records table
    op.create_table(
        "enterprise_baseline_records",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False, server_default=sa.text("'POLICY'")),
        sa.Column("source_uri", sa.String(length=1024), nullable=True),
        sa.Column("source_type", sa.String(length=64), nullable=False, server_default=sa.text("'EXECUTIVE_DIRECTIVE'")),
        sa.Column("provenance", sa.Text(), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False, server_default=sa.text("'ENTERPRISE_CONFIDENTIAL'")),
        sa.Column("access_scope", sa.String(length=64), nullable=False, server_default=sa.text("'ALL_BRANCHES'")),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=False, server_default=sa.text("'DRAFT'")),
        sa.Column("superseded_by_id", sa.String(length=36), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("approved_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "id", name="uq_enterprise_baseline_records_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_enterprise_baseline_records_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_baseline_records_branch_tenant",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED', 'ARCHIVED')",
            name="ck_baseline_lifecycle_status",
        ),
    )
    op.create_index("idx_baseline_tenant_status", "enterprise_baseline_records", ["tenant_id", "lifecycle_status"])
    op.create_index("idx_baseline_tenant_branch", "enterprise_baseline_records", ["tenant_id", "branch_id"])

    # 3. enterprise_baseline_versions table
    op.create_table(
        "enterprise_baseline_versions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("baseline_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("baseline_id", "version", name="uq_baseline_version"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_enterprise_baseline_versions_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "baseline_id"],
            ["enterprise_baseline_records.tenant_id", "enterprise_baseline_records.id"],
            name="fk_baseline_versions_record_tenant",
            ondelete="CASCADE",
        ),
    )
    op.create_index("idx_baseline_versions_hash", "enterprise_baseline_versions", ["content_sha256"])
    op.create_index("idx_baseline_versions_tenant_baseline", "enterprise_baseline_versions", ["tenant_id", "baseline_id"])

    # 4. baseline_governance_logs table
    op.create_table(
        "baseline_governance_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("baseline_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("actor_role", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_baseline_governance_logs_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "baseline_id"],
            ["enterprise_baseline_records.tenant_id", "enterprise_baseline_records.id"],
            name="fk_baseline_governance_record_tenant",
            ondelete="CASCADE",
        ),
    )
    op.create_index("idx_baseline_gov_occurred", "baseline_governance_logs", ["tenant_id", "baseline_id", "occurred_at"])

    # 5. agent_security_profiles table
    op.create_table(
        "agent_security_profiles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("owner_department", sa.String(length=128), nullable=False),
        sa.Column("approved_purpose", sa.Text(), nullable=False),
        sa.Column(
            "approved_goals",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column(
            "data_scope",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "operational_restrictions",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "approval_requirements",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("profile_version", sa.String(length=32), nullable=False, server_default=sa.text("'v1.0.0'")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("governed_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "id", name="uq_agent_security_profiles_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_agent_security_profiles_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "agent_id"],
            ["agents.tenant_id", "agents.id"],
            name="fk_agent_profiles_agent_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_agent_profiles_branch_tenant",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("idx_agent_profiles_tenant_agent", "agent_security_profiles", ["tenant_id", "agent_id"])
    op.create_index("idx_agent_profiles_branch", "agent_security_profiles", ["tenant_id", "branch_id"])

    # 6. observation_events table
    op.create_table(
        "observation_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("event_category", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("agent_runtime", sa.String(length=64), nullable=True),
        sa.Column("execution_id", sa.String(length=128), nullable=True),
        sa.Column("trace_id", sa.String(length=128), nullable=True),
        sa.Column("parent_span_id", sa.String(length=128), nullable=True),
        sa.Column("source_component", sa.String(length=64), nullable=False, server_default=sa.text("'GATEWAY'")),
        sa.Column("related_memory_id", sa.String(length=64), nullable=True),
        sa.Column("related_memory_version", sa.Integer(), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=True),
        sa.Column("action_id", sa.String(length=128), nullable=True),
        sa.Column("policy_decision_id", sa.String(length=128), nullable=True),
        sa.Column("execution_receipt_id", sa.String(length=128), nullable=True),
        sa.Column("baseline_version", sa.String(length=32), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column(
            "payload_json",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_obs_tenant_idemp"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_observation_events_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
    )
    op.create_index("idx_obs_tenant_occurred", "observation_events", ["tenant_id", "occurred_at"])
    op.create_index("idx_obs_tenant_trace", "observation_events", ["tenant_id", "trace_id"])
    op.create_index("idx_obs_tenant_agent", "observation_events", ["tenant_id", "agent_id"])
    op.create_index("idx_obs_tenant_category", "observation_events", ["tenant_id", "event_category"])

    for table in (
        "trust_decisions",
        "enterprise_baseline_records",
        "enterprise_baseline_versions",
        "baseline_governance_logs",
        "agent_security_profiles",
        "observation_events",
    ):
        op.execute(
            f"CREATE TRIGGER trg_forbid_tenant_id_change "
            f"BEFORE UPDATE OF tenant_id ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION amsc_forbid_tenant_id_change()"
        )


def downgrade() -> None:
    for table in (
        "observation_events",
        "agent_security_profiles",
        "baseline_governance_logs",
        "enterprise_baseline_versions",
        "enterprise_baseline_records",
        "trust_decisions",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_forbid_tenant_id_change ON {table}")

    op.drop_index("idx_baseline_versions_tenant_baseline", table_name="enterprise_baseline_versions")
    op.drop_table("observation_events")
    op.drop_table("agent_security_profiles")
    op.drop_table("baseline_governance_logs")
    op.drop_table("enterprise_baseline_versions")
    op.drop_table("enterprise_baseline_records")
    op.drop_table("trust_decisions")
