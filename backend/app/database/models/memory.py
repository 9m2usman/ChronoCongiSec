"""Knowledge, Memory & Provenance (AMSC-DOC-005 Section 3.3).

Tables: sources, documents, memory_records, memory_versions, transformations,
provenance_edges, retrieval_events.

Note: the DDL column ``metadata`` is exposed as the attribute ``metadata_json``
because ``metadata`` is reserved by SQLAlchemy's declarative base.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    id_column,
    jsonb_object_column,
    tenant_id_column,
)


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'DOCUMENT_FEED'")
    )
    uri: Mapped[Optional[str]] = mapped_column(String(1024))
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'UNVERIFIED'"))
    created_at: Mapped[datetime] = created_at_column()


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    source_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content_ref: Mapped[Optional[str]] = mapped_column(String(1024))
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    created_at: Mapped[datetime] = created_at_column()


class MemoryRecord(Base):
    __tablename__ = "memory_records"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("agents.id", ondelete="SET NULL")
    )
    source_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("sources.id", ondelete="SET NULL")
    )
    record_type: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'KNOWLEDGE'"))
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'UNVERIFIED'"))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (Index("idx_memory_records_tenant_trust", "tenant_id", "trust_state"),)


class MemoryVersion(Base):
    __tablename__ = "memory_versions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("record_id", "version", name="uq_record_version"),
        Index("idx_memory_versions_checksum", "checksum"),
    )


class Transformation(Base):
    __tablename__ = "transformations"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    input_record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    output_record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    created_at: Mapped[datetime] = created_at_column()


class ProvenanceEdge(Base):
    __tablename__ = "provenance_edges"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    from_record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    to_record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    relation_type: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'DERIVED_FROM'")
    )
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        Index("idx_provenance_from", "tenant_id", "from_record_id"),
        Index("idx_provenance_to", "tenant_id", "to_record_id"),
    )


class RetrievalEvent(Base):
    __tablename__ = "retrieval_events"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    record_id: Mapped[str] = mapped_column(
        String(ID_LENGTH), ForeignKey("memory_records.id", ondelete="CASCADE"), nullable=False
    )
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    query_text: Mapped[Optional[str]] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (Index("idx_retrieval_trace", "tenant_id", "trace_id"),)
