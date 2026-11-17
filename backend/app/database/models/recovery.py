"""Incidents, Quarantines, Checkpoints & Recovery (AMSC-DOC-005 Section 3.5).

Tables: incidents, incident_evidence, quarantines, checkpoints, checkpoint_items,
recovery_plans, recovery_actions.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    Base,
    created_at_column,
    id_column,
    jsonb_object_column,
    tenant_id_column,
)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'HIGH'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'OPEN'"))
    affected_record_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="SET NULL")
    )
    agent_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("agents.id", ondelete="SET NULL")
    )
    evidence_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    incident_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")


class Quarantine(Base):
    __tablename__ = "quarantines"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    quarantined_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = created_at_column()


class Checkpoint(Base):
    __tablename__ = "checkpoints"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("agents.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    snapshot_data_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()


class CheckpointItem(Base):
    __tablename__ = "checkpoint_items"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    checkpoint_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("checkpoints.id", ondelete="CASCADE"), nullable=False
    )
    record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    version_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_versions.id", ondelete="CASCADE"), nullable=False
    )
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)


class RecoveryPlan(Base):
    __tablename__ = "recovery_plans"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    checkpoint_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("checkpoints.id", ondelete="CASCADE"), nullable=False
    )
    target_record_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    pre_recovery_snapshot_json: Mapped[dict[str, Any]] = jsonb_object_column()
    impact_preview_json: Mapped[dict[str, Any]] = jsonb_object_column()
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class RecoveryAction(Base):
    __tablename__ = "recovery_actions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    plan_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("recovery_plans.id", ondelete="CASCADE"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'SUCCESS'"))
