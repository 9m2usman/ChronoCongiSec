"""Schema-driven row factory for raw-SQL database tests.

Owner: M6
Reads the REAL migrated schema (information_schema + pg_constraint) and builds
a minimal valid row for any table: NOT NULL columns without defaults get a
generated value, and required references get a freshly created parent row in
the SAME tenant. Tests then override one column to forge a cross-tenant or
missing-parent reference.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

import asyncpg

GLOBAL_PARENT_VALUES = {"users"}


@dataclass
class _Column:
    name: str
    data_type: str
    max_length: int | None
    required: bool  # NOT NULL and no server default


@dataclass
class SchemaInfo:
    columns: dict[str, list[_Column]] = field(default_factory=dict)
    # (table, column) -> referenced table, for single-column refs and composite tenant refs
    references: dict[tuple[str, str], str] = field(default_factory=dict)

    @classmethod
    async def load(cls, conn: asyncpg.Connection) -> "SchemaInfo":
        info = cls()
        rows = await conn.fetch(
            """
            SELECT table_name, column_name, data_type, character_maximum_length,
                   is_nullable = 'NO' AND column_default IS NULL AS required
            FROM information_schema.columns
            WHERE table_schema = 'public'
            ORDER BY table_name, ordinal_position
            """
        )
        for r in rows:
            info.columns.setdefault(r["table_name"], []).append(
                _Column(r["column_name"], r["data_type"], r["character_maximum_length"], r["required"])
            )

        fk_rows = await conn.fetch(
            """
            SELECT src.relname AS child, ref.relname AS parent,
                   array_agg(sa.attname ORDER BY k.ord) AS cols
            FROM pg_constraint c
            JOIN pg_class src ON src.oid = c.conrelid
            JOIN pg_class ref ON ref.oid = c.confrelid
            JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
            JOIN pg_attribute sa ON sa.attrelid = c.conrelid AND sa.attnum = k.attnum
            WHERE c.contype = 'f' AND src.relnamespace = 'public'::regnamespace
            GROUP BY c.oid, src.relname, ref.relname
            """
        )
        for r in fk_rows:
            ref_cols = [c for c in r["cols"] if c != "tenant_id"]
            if len(ref_cols) == 1:
                info.references[(r["child"], ref_cols[0])] = r["parent"]
        return info


def _value_for(col: _Column) -> Any:
    if col.data_type in ("character varying", "text", "character"):
        raw = uuid.uuid4().hex
        return raw[: col.max_length] if col.max_length else raw
    if col.data_type in ("integer", "bigint", "smallint"):
        return 1
    if col.data_type == "jsonb":
        return "{}"
    if col.data_type == "boolean":
        return True
    raise NotImplementedError(f"No generator for {col.name} ({col.data_type})")


class RowFactory:
    def __init__(self, conn: asyncpg.Connection, schema: SchemaInfo) -> None:
        self.conn = conn
        self.schema = schema

    async def tenant(self) -> str:
        return await self.create("tenants", None)

    async def create(self, table: str, tenant_id: str | None, **overrides: Any) -> str:
        """Insert a minimal valid row and return its id."""
        values: dict[str, Any] = {}
        for col in self.schema.columns[table]:
            if col.name in overrides:
                values[col.name] = overrides[col.name]
            elif col.name == "id":
                values["id"] = str(uuid.uuid4())
            elif col.name == "tenant_id":
                if tenant_id is not None:
                    values["tenant_id"] = tenant_id
            elif not col.required:
                continue
            elif (table, col.name) in self.schema.references:
                parent = self.schema.references[(table, col.name)]
                parent_tenant = None if parent in GLOBAL_PARENT_VALUES else tenant_id
                values[col.name] = await self.create(parent, parent_tenant)
            else:
                values[col.name] = _value_for(col)

        names = list(values)
        placeholders = ", ".join(f"${i}" for i in range(1, len(names) + 1))
        await self.conn.execute(
            f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})",
            *values.values(),
        )
        return values["id"]
