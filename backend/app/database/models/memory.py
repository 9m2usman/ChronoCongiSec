"""Knowledge, Memory & Provenance (AMSC-DOC-005 Section 3.3).

Tables: sources, documents, memory_records, memory_versions, transformations,
provenance_edges, retrieval_events.

Every reference between these tenant-owned tables is a composite
``(tenant_id, <ref>_id)`` foreign key (``tenant_fk``), so a memory row can never
point at an agent, source or record owned by another tenant.

Note: the DDL column ``metadata`` is exposed as the attribute ``metadata_json``
because ``metadata`` is reserved by SQLAlchemy's declarative base.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, text
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

    __table_args__ = (tenant_parent_key(),)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    source_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content_ref: Mapped[Optional[str]] = mapped_column(String(1024))
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (*tenant_fk("documents", "source_id", "sources", "CASCADE"),)


class MemoryRecord(Base):
    __tablename__ = "memory_records"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    source_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    record_type: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'KNOWLEDGE'"))
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'UNVERIFIED'"))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (
        Index("idx_memory_records_tenant_trust", "tenant_id", "trust_state"),
        tenant_parent_key(),
        *tenant_fk("memory_records", "agent_id", "agents", "SET NULL"),
        *tenant_fk("memory_records", "source_id", "sources", "SET NULL"),
    )


class MemoryVersion(Base):
    __tablename__ = "memory_versions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("record_id", "version", name="uq_record_version"),
        Index("idx_memory_versions_checksum", "checksum"),
        tenant_parent_key(),
        *tenant_fk("memory_versions", "record_id", "memory_records", "CASCADE"),
    )


class Transformation(Base):
    __tablename__ = "transformations"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    input_record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    output_record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = jsonb_object_column("metadata")
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        *tenant_fk("transformations", "input_record_id", "memory_records", "CASCADE"),
        *tenant_fk("transformations", "output_record_id", "memory_records", "CASCADE"),
    )


class ProvenanceEdge(Base):
    __tablename__ = "provenance_edges"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    from_record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    to_record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    relation_type: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'DERIVED_FROM'")
    )
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        # DOC-005 indexes already lead with (tenant_id, <ref>), so no extra FK index.
        Index("idx_provenance_from", "tenant_id", "from_record_id"),
        Index("idx_provenance_to", "tenant_id", "to_record_id"),
        *tenant_fk("provenance_edges", "from_record_id", "memory_records", "CASCADE", index=False),
        *tenant_fk("provenance_edges", "to_record_id", "memory_records", "CASCADE", index=False),
    )


class RetrievalEvent(Base):
    __tablename__ = "retrieval_events"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    query_text: Mapped[Optional[str]] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (
        Index("idx_retrieval_trace", "tenant_id", "trace_id"),
        *tenant_fk("retrieval_events", "agent_id", "agents", "CASCADE"),
        *tenant_fk("retrieval_events", "record_id", "memory_records", "CASCADE"),
    )
