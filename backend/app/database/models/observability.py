"""Knowledge Graph, Drift, Traces, Audit & Outbox (AMSC-DOC-005 Section 3.6).

Tables: knowledge_entities, knowledge_relations, drift_observations, traces,
trace_spans, audit_events, outbox_events.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
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

TRACE_ID_LENGTH = 128


class KnowledgeEntity(Base):
    __tablename__ = "knowledge_entities"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'CONCEPT'"))
    properties_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (tenant_parent_key(),)


class KnowledgeRelation(Base):
    __tablename__ = "knowledge_relations"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    source_entity_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'REFERENCES'"))
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        *tenant_fk("knowledge_relations", "source_entity_id", "knowledge_entities", "CASCADE"),
        *tenant_fk("knowledge_relations", "target_entity_id", "knowledge_entities", "CASCADE"),
    )


class DriftObservation(Base):
    __tablename__ = "drift_observations"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    classification: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'POTENTIAL_POISONING'")
    )
    divergence_score: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'0.78'"))
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    reviewer_status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (*tenant_fk("drift_observations", "record_id", "memory_records", "CASCADE"),)


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[str] = mapped_column(String(TRACE_ID_LENGTH), primary_key=True)
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'COMPLETED'"))

    __table_args__ = (
        tenant_parent_key(),
        *tenant_fk("traces", "agent_id", "agents", "SET NULL"),
    )


class TraceSpan(Base):
    __tablename__ = "trace_spans"

    id: Mapped[str] = mapped_column(String(TRACE_ID_LENGTH), primary_key=True)
    tenant_id: Mapped[str] = tenant_id_column()
    trace_id: Mapped[str] = mapped_column(String(TRACE_ID_LENGTH), nullable=False)
    # Soft reference (no FK) on purpose: OpenTelemetry exporters routinely deliver a
    # child span before its parent, so an FK would reject valid telemetry.
    parent_span_id: Mapped[Optional[str]] = mapped_column(String(TRACE_ID_LENGTH))
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (*tenant_fk("trace_spans", "trace_id", "traces", "CASCADE"),)


class AuditEvent(Base):
    """Append-only, hash-chained system log.

    - Migration 0004: UPDATE / DELETE / TRUNCATE are rejected by triggers.
    - Migration 0009: every tenant has its own hash chain. A BEFORE INSERT trigger assigns
      ``chain_seq`` (1, 2, 3 ... per tenant), ``prev_hash`` (the previous event's hash, NULL
      for the first) and ``event_hash`` (``amsc_audit_event_hash(...)``). Values supplied by
      the caller for these three columns are ignored. ``amsc_audit_chain_break(tenant_id)``
      returns the first broken ``chain_seq`` (NULL if the chain is intact).
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")  # forensic evidence
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    trace_id: Mapped[Optional[str]] = mapped_column(String(TRACE_ID_LENGTH))
    details_json: Mapped[dict[str, Any]] = jsonb_object_column()
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)
    # Filled by the database trigger (0009); never set these from application code.
    chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "chain_seq"),
        CheckConstraint(
            "(chain_seq = 1 AND prev_hash IS NULL) OR (chain_seq > 1 AND prev_hash IS NOT NULL)",
            name="chain_link",
        ),
    )


Index("idx_audit_tenant_occurred", AuditEvent.tenant_id, AuditEvent.occurred_at.desc())


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    next_attempt_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    locked_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    locked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dead_lettered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = created_at_column()
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_outbox_pending", "status", "created_at"),
        Index("idx_outbox_poll", "status", "next_attempt_at", "created_at"),
        Index("idx_outbox_locked_until", "status", "locked_until"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_outbox_tenant_idempotency"),
    )
