"""Incidents, Quarantines, Checkpoints & Recovery (AMSC-DOC-005 Section 3.5).

Tables: incidents, incident_evidence, quarantines, checkpoints, checkpoint_items,
recovery_plans, recovery_actions.

All references between these tables (and to memory/agents) are composite
tenant-consistent foreign keys.

Day 5 (migration 0008): the recovery chain checkpoint -> items / plans -> actions and
incident -> evidence is ON DELETE RESTRICT; a checkpoint holds each record at most
once; and a recovery plan's pre-recovery snapshot is fingerprinted, immutable once
captured, and required before any recovery action or execution is recorded.
"""

# SHA-256 of the snapshot as PostgreSQL renders it (jsonb::text, UTF-8). Computed by the
# database, so application code never has to reproduce jsonb's text format.
SNAPSHOT_SHA256_SQL = "encode(sha256(convert_to(pre_recovery_snapshot_json::text, 'UTF8')), 'hex')"

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
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
    Base,
    created_at_column,
    id_column,
    jsonb_object_column,
    tenant_fk,
    tenant_id_column,
    tenant_parent_key,
)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")  # forensic evidence
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'HIGH'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'OPEN'"))
    affected_record_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    evidence_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        tenant_parent_key(),
        *tenant_fk("incidents", "affected_record_id", "memory_records", "SET NULL"),
        *tenant_fk("incidents", "agent_id", "agents", "SET NULL"),
    )


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")  # forensic evidence
    incident_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")

    # RESTRICT (0008): an incident with evidence cannot be deleted.
    __table_args__ = (*tenant_fk("incident_evidence", "incident_id", "incidents", "RESTRICT"),)


class Quarantine(Base):
    __tablename__ = "quarantines"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    incident_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    quarantined_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        *tenant_fk("quarantines", "record_id", "memory_records", "CASCADE"),
        *tenant_fk("quarantines", "incident_id", "incidents", "SET NULL"),
    )


class Checkpoint(Base):
    __tablename__ = "checkpoints"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    snapshot_data_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        tenant_parent_key(),
        *tenant_fk("checkpoints", "agent_id", "agents", "SET NULL"),
    )


class CheckpointItem(Base):
    __tablename__ = "checkpoint_items"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    checkpoint_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        # 0008: a checkpoint holds each record at most once, so a rewind target is unambiguous.
        UniqueConstraint("tenant_id", "checkpoint_id", "record_id"),
        # RESTRICT (0008): a checkpoint with items cannot be deleted.
        *tenant_fk("checkpoint_items", "checkpoint_id", "checkpoints", "RESTRICT"),
        *tenant_fk("checkpoint_items", "record_id", "memory_records", "CASCADE"),
        *tenant_fk("checkpoint_items", "version_id", "memory_versions", "CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "record_id", "version_id"],
            ["memory_versions.tenant_id", "memory_versions.record_id", "memory_versions.id"],
            name="fk_checkpoint_items_version_matches_record",
            ondelete="CASCADE",
        ),
        Index("ix_checkpoint_items_tenant_record_version", "tenant_id", "record_id", "version_id"),
    )


class RecoveryPlan(Base):
    __tablename__ = "recovery_plans"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    incident_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    checkpoint_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    target_record_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    pre_recovery_snapshot_json: Mapped[dict[str, Any]] = jsonb_object_column()
    # 0008: NULL until the snapshot is captured; then the database-computed SHA-256 of
    # the snapshot. Once set, snapshot and hash cannot change and the plan cannot be deleted.
    pre_recovery_snapshot_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    impact_preview_json: Mapped[dict[str, Any]] = jsonb_object_column()
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        tenant_parent_key(),
        *tenant_fk("recovery_plans", "incident_id", "incidents", "SET NULL"),
        # RESTRICT (0008): a checkpoint used by a recovery plan cannot be deleted.
        *tenant_fk("recovery_plans", "checkpoint_id", "checkpoints", "RESTRICT"),
        *tenant_fk("recovery_plans", "target_record_id", "memory_records", "SET NULL"),
        CheckConstraint(
            "(pre_recovery_snapshot_json = '{}'::jsonb AND pre_recovery_snapshot_sha256 IS NULL) OR "
            "(pre_recovery_snapshot_json <> '{}'::jsonb AND pre_recovery_snapshot_sha256 IS NOT NULL "
            f"AND pre_recovery_snapshot_sha256 = {SNAPSHOT_SHA256_SQL})",
            name="snapshot_hash_consistent",
        ),
        CheckConstraint(
            "executed_at IS NULL OR pre_recovery_snapshot_sha256 IS NOT NULL",
            name="executed_requires_snapshot",
        ),
    )


class RecoveryAction(Base):
    __tablename__ = "recovery_actions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    plan_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'SUCCESS'"))

    # RESTRICT (0008): a plan with recorded actions cannot be deleted. A trigger also
    # refuses an action for a plan whose pre-recovery snapshot was not captured.
    __table_args__ = (*tenant_fk("recovery_actions", "plan_id", "recovery_plans", "RESTRICT"),)
