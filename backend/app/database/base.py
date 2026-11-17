"""Declarative base, constraint naming convention and shared column helpers.

Module: backend.app.database.base
Owner: M6 (Database Architect & Governance)
Spec: AMSC-DOC-005 Section 3 (Relational DDL)

All ORM models inherit from ``Base``. A deterministic naming convention keeps
constraint names identical between SQLAlchemy metadata and Alembic migrations,
so ``alembic check`` / model-vs-migration comparison stays stable.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Text identifiers (UUIDv4 strings) per AMSC-DOC-005 and team convention.
ID_LENGTH = 36

# Server-side defaults (kept as SQL text so migrations and models match exactly).
NOW = text("CURRENT_TIMESTAMP")
EMPTY_OBJECT = text("'{}'::jsonb")
EMPTY_ARRAY = text("'[]'::jsonb")


class Base(DeclarativeBase):
    """Root declarative class for every AMSC table."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def id_column() -> Mapped[str]:
    """Primary key column: VARCHAR(36) text UUID supplied by the application."""
    return mapped_column(String(ID_LENGTH), primary_key=True)


def tenant_id_column() -> Mapped[str]:
    """Mandatory tenant owner column: NOT NULL FK to tenants.id.

    HARD RULE (AMSC-DOC-006, M6 constraint): every tenant-owned table carries a
    non-nullable ``tenant_id`` referencing ``tenants.id``.
    """
    return mapped_column(
        String(ID_LENGTH),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )


def created_at_column() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)


def jsonb_object_column(name: str | None = None) -> Mapped[dict[str, Any]]:
    """JSONB NOT NULL DEFAULT '{}'::jsonb."""
    if name is None:
        return mapped_column(JSONB, nullable=False, server_default=EMPTY_OBJECT)
    return mapped_column(name, JSONB, nullable=False, server_default=EMPTY_OBJECT)


def jsonb_array_column() -> Mapped[list[Any]]:
    """JSONB NOT NULL DEFAULT '[]'::jsonb."""
    return mapped_column(JSONB, nullable=False, server_default=EMPTY_ARRAY)
