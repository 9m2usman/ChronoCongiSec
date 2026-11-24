"""Enterprise Connectivity, Discovery, Synchronization & Knowledge Intelligence Models.

Tables:
- enterprise_connectors: Authorized enterprise data source and agent framework connections.
- discovered_resources: Inventoried databases, tables, files, documents, and agent resources.
- sync_jobs: Synchronization job history, checkpoints, and failure diagnostics.
- knowledge_claims: Structured organizational knowledge claims, conflicts, and provenance.
- enterprise_memory_links: Controlled links between enterprise resources, memory records, and snapshots.
- connector_audit_logs: Append-only integration audit history.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    id_column,
    jsonb_object_column,
    tenant_fk,
    tenant_id_column,
    tenant_parent_key,
)


class EnterpriseConnector(Base):
    """Authorized enterprise data source or agent framework connection."""

    __tablename__ = "enterprise_connectors"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'PENDING_AUTH'")
    )
    auth_mode: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'LOCAL_SCOPED'")
    )
    config_json: Mapped[dict[str, Any]] = jsonb_object_column("config")
    secret_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scope_json: Mapped[dict[str, Any]] = jsonb_object_column("scope")
    monitoring_coverage_json: Mapped[dict[str, Any]] = jsonb_object_column("monitoring_coverage")
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        tenant_parent_key(),
        Index("idx_enterprise_connectors_tenant_status", "tenant_id", "status"),
        Index("idx_enterprise_connectors_tenant_type", "tenant_id", "connector_type"),
    )


class DiscoveredResource(Base):
    """Inventoried enterprise resource (DB table, file, document, policy, agent)."""

    __tablename__ = "discovered_resources"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="CASCADE")
    connector_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_resource_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    access_scope: Mapped[str] = mapped_column(
        String(128), nullable=False, server_default=text("'TENANT_SCOPED'")
    )
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'INTERNAL'")
    )
    sync_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'DISCOVERED'")
    )
    source_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    content_checksum: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    retention_policy: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'STANDARD_90D'")
    )
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        tenant_parent_key(),
        UniqueConstraint(
            "tenant_id",
            "connector_id",
            "external_id",
            name="uq_discovered_resources_tenant_conn_ext",
        ),
        Index("idx_discovered_resources_tenant_status", "tenant_id", "sync_status"),
        *tenant_fk("discovered_resources", "connector_id", "enterprise_connectors", "CASCADE"),
        *tenant_fk("discovered_resources", "source_id", "sources", "SET NULL"),
    )


class SyncJob(Base):
    """Synchronization job execution record and checkpoint."""

    __tablename__ = "sync_jobs"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="CASCADE")
    connector_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    strategy: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    resources_discovered: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    resources_synced: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    resources_changed: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    resources_deleted: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    resources_failed: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    checkpoint_json: Mapped[dict[str, Any]] = jsonb_object_column("checkpoint")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = created_at_column()
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        Index("idx_sync_jobs_tenant_connector", "tenant_id", "connector_id"),
        Index("idx_sync_jobs_tenant_status", "tenant_id", "status"),
        *tenant_fk("sync_jobs", "connector_id", "enterprise_connectors", "CASCADE"),
    )


class KnowledgeClaim(Base):
    """Structured organizational knowledge claim with provenance and conflict tracking."""

    __tablename__ = "knowledge_claims"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="CASCADE")
    resource_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    claim_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    predicate: Mapped[str] = mapped_column(String(128), nullable=False)
    object_value: Mapped[str] = mapped_column(Text, nullable=False)
    department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    provenance_json: Mapped[dict[str, Any]] = jsonb_object_column("provenance")
    trust_state: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'UNVERIFIED'")
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("0.5"))
    conflict_group_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    superseded_by_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        Index("idx_knowledge_claims_tenant_trust", "tenant_id", "trust_state"),
        Index("idx_knowledge_claims_tenant_subject", "tenant_id", "subject"),
        *tenant_fk("knowledge_claims", "resource_id", "discovered_resources", "CASCADE"),
        *tenant_fk("knowledge_claims", "source_id", "sources", "SET NULL"),
    )


class EnterpriseMemoryLink(Base):
    """Controlled link between enterprise resources, memory records, and snapshots."""

    __tablename__ = "enterprise_memory_links"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="CASCADE")
    memory_record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    memory_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    resource_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    source_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    extraction_purpose: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("0.8"))
    freshness_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'CURRENT'")
    )
    snapshot_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_json: Mapped[dict[str, Any]] = jsonb_object_column("snapshot")
    retrieved_at: Mapped[datetime] = created_at_column()
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        Index("idx_enterprise_mem_links_tenant_rec", "tenant_id", "memory_record_id"),
        Index("idx_enterprise_mem_links_tenant_res", "tenant_id", "resource_id"),
        *tenant_fk("enterprise_memory_links", "memory_record_id", "memory_records", "CASCADE"),
        *tenant_fk("enterprise_memory_links", "resource_id", "discovered_resources", "CASCADE"),
    )


class ConnectorAuditLog(Base):
    """Append-only audit log for enterprise connector and synchronization actions."""

    __tablename__ = "connector_audit_logs"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    connector_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    details_json: Mapped[dict[str, Any]] = jsonb_object_column("details")
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        Index("idx_connector_audit_tenant_created", "tenant_id", "created_at"),
        *tenant_fk("connector_audit_logs", "connector_id", "enterprise_connectors", "SET NULL"),
    )
