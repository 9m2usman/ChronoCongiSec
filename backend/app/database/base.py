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

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    MetaData,
    String,
    UniqueConstraint,
    text,
)
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


MAX_IDENTIFIER_LENGTH = 63  # PostgreSQL NAMEDATALEN - 1


def tenant_parent_key() -> UniqueConstraint:
    """``UNIQUE (tenant_id, id)``: lets children reference (tenant_id, id) composite keys."""
    return UniqueConstraint("tenant_id", "id")


def tenant_fk(
    table: str, column: str, parent: str, ondelete: str, *, index: bool = True
) -> tuple[ForeignKeyConstraint, ...]:
    """Tenant-consistent composite FK ``(tenant_id, column) -> parent(tenant_id, id)`` plus its index.

    Pass ``index=False`` only when an existing index already leads with
    ``(tenant_id, column)``.

    AMSC-DOC-005 §1: a child row can only point at a parent row of the SAME tenant.
    ``ondelete`` is ``"CASCADE"`` or ``"SET NULL"``. SET NULL is emitted as
    ``SET NULL (column)`` (PostgreSQL 15+) so a parent delete clears only the
    reference and never the child's NOT NULL ``tenant_id``.
    """
    if ondelete == "SET NULL":
        action = f"SET NULL ({column})"
    elif ondelete == "CASCADE":
        action = "CASCADE"
    else:
        raise ValueError(f"Unsupported ondelete {ondelete!r} for tenant FK {table}.{column}")

    fk_name = f"fk_{table}_{column}_tenant"
    ix_name = f"ix_{table}_tenant_id_{column}"
    for name in (fk_name, ix_name):
        if len(name) > MAX_IDENTIFIER_LENGTH:
            raise ValueError(f"Identifier too long for PostgreSQL: {name}")

    fk = ForeignKeyConstraint(
        ["tenant_id", column],
        [f"{parent}.tenant_id", f"{parent}.id"],
        name=fk_name,
        ondelete=action,
    )
    return (fk, Index(ix_name, "tenant_id", column)) if index else (fk,)


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
