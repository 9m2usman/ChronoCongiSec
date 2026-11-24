"""Enterprise Connectivity, Discovery, Synchronization & Knowledge Intelligence.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-25
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: Union[str, Sequence[str], None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "enterprise_connectors",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("connector_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'PENDING_AUTH'")),
        sa.Column("auth_mode", sa.String(length=64), nullable=False, server_default=sa.text("'LOCAL_SCOPED'")),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("secret_ref", sa.String(length=255), nullable=True),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("monitoring_coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(length=32), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_enterprise_connectors_tenant_id_id"),
    )
    op.create_index("idx_enterprise_connectors_tenant_status", "enterprise_connectors", ["tenant_id", "status"])
    op.create_index("idx_enterprise_connectors_tenant_type", "enterprise_connectors", ["tenant_id", "connector_type"])

    op.create_table(
        "discovered_resources",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=1024), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("parent_resource_id", sa.String(length=36), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("access_scope", sa.String(length=128), nullable=False, server_default=sa.text("'TENANT_SCOPED'")),
        sa.Column("classification", sa.String(length=32), nullable=False, server_default=sa.text("'INTERNAL'")),
        sa.Column("sync_status", sa.String(length=32), nullable=False, server_default=sa.text("'DISCOVERED'")),
        sa.Column("source_version", sa.String(length=255), nullable=True),
        sa.Column("content_checksum", sa.String(length=64), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("retention_policy", sa.String(length=64), nullable=False, server_default=sa.text("'STANDARD_90D'")),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_discovered_resources_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "connector_id", "external_id", name="uq_discovered_resources_tenant_conn_ext"),
        sa.ForeignKeyConstraint(["tenant_id", "connector_id"], ["enterprise_connectors.tenant_id", "enterprise_connectors.id"], name="fk_discovered_resources_connector_id_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "source_id"], ["sources.tenant_id", "sources.id"], name="fk_discovered_resources_source_id_tenant", ondelete="SET NULL (source_id)"),
    )
    op.create_index("ix_discovered_resources_tenant_id_connector_id", "discovered_resources", ["tenant_id", "connector_id"])
    op.create_index("ix_discovered_resources_tenant_id_source_id", "discovered_resources", ["tenant_id", "source_id"])
    op.create_index("idx_discovered_resources_tenant_status", "discovered_resources", ["tenant_id", "sync_status"])

    op.create_table(
        "sync_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("strategy", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resources_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("resources_synced", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("resources_changed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("resources_deleted", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("resources_failed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("checkpoint", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "connector_id"], ["enterprise_connectors.tenant_id", "enterprise_connectors.id"], name="fk_sync_jobs_connector_id_tenant", ondelete="CASCADE"),
    )
    op.create_index("ix_sync_jobs_tenant_id_connector_id", "sync_jobs", ["tenant_id", "connector_id"])
    op.create_index("idx_sync_jobs_tenant_connector", "sync_jobs", ["tenant_id", "connector_id"])
    op.create_index("idx_sync_jobs_tenant_status", "sync_jobs", ["tenant_id", "status"])

    op.create_table(
        "knowledge_claims",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=True),
        sa.Column("claim_type", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("predicate", sa.String(length=128), nullable=False),
        sa.Column("object_value", sa.Text(), nullable=False),
        sa.Column("department", sa.String(length=128), nullable=True),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("trust_state", sa.String(length=32), nullable=False, server_default=sa.text("'UNVERIFIED'")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0.5")),
        sa.Column("conflict_group_id", sa.String(length=36), nullable=True),
        sa.Column("superseded_by_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "resource_id"], ["discovered_resources.tenant_id", "discovered_resources.id"], name="fk_knowledge_claims_resource_id_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "source_id"], ["sources.tenant_id", "sources.id"], name="fk_knowledge_claims_source_id_tenant", ondelete="SET NULL (source_id)"),
    )
    op.create_index("ix_knowledge_claims_tenant_id_resource_id", "knowledge_claims", ["tenant_id", "resource_id"])
    op.create_index("ix_knowledge_claims_tenant_id_source_id", "knowledge_claims", ["tenant_id", "source_id"])
    op.create_index("idx_knowledge_claims_tenant_trust", "knowledge_claims", ["tenant_id", "trust_state"])
    op.create_index("idx_knowledge_claims_tenant_subject", "knowledge_claims", ["tenant_id", "subject"])

    op.create_table(
        "enterprise_memory_links",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("memory_record_id", sa.String(length=36), nullable=False),
        sa.Column("memory_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("source_version", sa.String(length=255), nullable=True),
        sa.Column("agent_id", sa.String(length=36), nullable=True),
        sa.Column("extraction_purpose", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0.8")),
        sa.Column("freshness_status", sa.String(length=32), nullable=False, server_default=sa.text("'CURRENT'")),
        sa.Column("snapshot_checksum", sa.String(length=64), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "memory_record_id"], ["memory_records.tenant_id", "memory_records.id"], name="fk_enterprise_memory_links_memory_record_id_tenant", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "resource_id"], ["discovered_resources.tenant_id", "discovered_resources.id"], name="fk_enterprise_memory_links_resource_id_tenant", ondelete="CASCADE"),
    )
    op.create_index("ix_enterprise_memory_links_tenant_id_memory_record_id", "enterprise_memory_links", ["tenant_id", "memory_record_id"])
    op.create_index("ix_enterprise_memory_links_tenant_id_resource_id", "enterprise_memory_links", ["tenant_id", "resource_id"])
    op.create_index("idx_enterprise_mem_links_tenant_rec", "enterprise_memory_links", ["tenant_id", "memory_record_id"])
    op.create_index("idx_enterprise_mem_links_tenant_res", "enterprise_memory_links", ["tenant_id", "resource_id"])

    op.create_table(
        "connector_audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=True),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "connector_id"], ["enterprise_connectors.tenant_id", "enterprise_connectors.id"], name="fk_connector_audit_logs_connector_id_tenant", ondelete="SET NULL (connector_id)"),
    )
    op.create_index("ix_connector_audit_logs_tenant_id_connector_id", "connector_audit_logs", ["tenant_id", "connector_id"])
    op.create_index("idx_connector_audit_tenant_created", "connector_audit_logs", ["tenant_id", "created_at"])

    for table in (
        "enterprise_connectors",
        "discovered_resources",
        "sync_jobs",
        "knowledge_claims",
        "enterprise_memory_links",
        "connector_audit_logs",
    ):
        op.execute(
            f"CREATE TRIGGER trg_forbid_tenant_id_change "
            f"BEFORE UPDATE OF tenant_id ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION amsc_forbid_tenant_id_change()"
        )


def downgrade() -> None:
    op.drop_table("connector_audit_logs")
    op.drop_table("enterprise_memory_links")
    op.drop_table("knowledge_claims")
    op.drop_table("sync_jobs")
    op.drop_table("discovered_resources")
    op.drop_table("enterprise_connectors")
