"""Incidents, Quarantines, Checkpoints & Recovery (AMSC-DOC-005 Section 3.5).

Tables: incidents, incident_evidence, quarantines, checkpoints, checkpoint_items,
recovery_plans, recovery_actions.

All references between these tables (and to memory/agents) are composite
tenant-consistent foreign keys.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Integer, String, Text, text
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

    __table_args__ = (*tenant_fk("incident_evidence", "incident_id", "incidents", "CASCADE"),)


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
        *tenant_fk("checkpoint_items", "checkpoint_id", "checkpoints", "CASCADE"),
        *tenant_fk("checkpoint_items", "record_id", "memory_records", "CASCADE"),
        *tenant_fk("checkpoint_items", "version_id", "memory_versions", "CASCADE"),
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
    impact_preview_json: Mapped[dict[str, Any]] = jsonb_object_column()
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        tenant_parent_key(),
        *tenant_fk("recovery_plans", "incident_id", "incidents", "SET NULL"),
        *tenant_fk("recovery_plans", "checkpoint_id", "checkpoints", "CASCADE"),
        *tenant_fk("recovery_plans", "target_record_id", "memory_records", "SET NULL"),
    )


class RecoveryAction(Base):
    __tablename__ = "recovery_actions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    plan_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'SUCCESS'"))

    __table_args__ = (*tenant_fk("recovery_actions", "plan_id", "recovery_plans", "CASCADE"),)
