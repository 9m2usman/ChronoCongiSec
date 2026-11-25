"""Schema-driven row factory for raw-SQL database tests.

Owner: M6
Reads the REAL migrated schema (information_schema + pg_constraint) and builds
a minimal valid row for any table: NOT NULL columns without defaults get a
generated value, and required references get a freshly created parent row in
the SAME tenant. Tests then override one column to forge a cross-tenant or
missing-parent reference.

Multi-column ("linked") foreign keys such as migration 0005's
``checkpoint_items (tenant_id, record_id, version_id) -> memory_versions
(tenant_id, record_id, id)`` tie several child columns to ONE parent row. The
factory keeps those columns consistent:

- nothing supplied: create the record first, then a version OF that record;
- only the parent row supplied (``version_id``): copy ``record_id`` from it;
- only the other columns supplied (``record_id``): create a version of that record;
- everything supplied: use it unchanged, so negative tests can still forge a
  mismatched or cross-tenant combination and assert that PostgreSQL rejects it.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

import asyncpg

GLOBAL_PARENT_VALUES = {"users"}

DEFAULT_RECOVERY_SNAPSHOT = '{"factory": "captured pre-recovery snapshot"}'


@dataclass
class _Column:
    name: str
    data_type: str
    max_length: int | None
    required: bool  # NOT NULL and no server default


@dataclass(frozen=True)
class LinkedReference:
    """A FK with more than one non-tenant column, e.g. (record_id, version_id) -> (record_id, id)."""

    child: str
    parent: str
    anchor: str  # child column that references parent.id
    derived: tuple[tuple[str, str], ...]  # (child column, parent column) pairs besides the anchor


@dataclass
class SchemaInfo:
    columns: dict[str, list[_Column]] = field(default_factory=dict)
    # (table, column) -> referenced table, for single-column refs and composite tenant refs
    references: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    # table -> linked (multi-column) references
    linked: dict[str, list[LinkedReference]] = field(default_factory=dict)

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
                   array_agg(sa.attname::text ORDER BY k.ord) AS cols,
                   array_agg(ra.attname::text ORDER BY k.ord) AS parent_cols
            FROM pg_constraint c
            JOIN pg_class src ON src.oid = c.conrelid
            JOIN pg_class ref ON ref.oid = c.confrelid
            JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY AS k(attnum, ref_attnum, ord) ON TRUE
            JOIN pg_attribute sa ON sa.attrelid = c.conrelid AND sa.attnum = k.attnum
            JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.ref_attnum
            WHERE c.contype = 'f' AND src.relnamespace = 'public'::regnamespace
            GROUP BY c.oid, src.relname, ref.relname
            """
        )
        for r in fk_rows:
            pairs = [(c, p) for c, p in zip(r["cols"], r["parent_cols"]) if c != "tenant_id"]
            if not pairs:
                continue  # tenant_id -> tenants.id: filled from the tenant argument
            if len(pairs) == 1:
                info.references[(r["child"], pairs[0][0])] = (r["parent"], pairs[0][1])
                continue
            anchors = [c for c, p in pairs if p == "id"]
            if len(anchors) != 1:
                raise NotImplementedError(f"Unsupported multi-column FK {r['child']}{r['cols']} -> {r['parent']}")
            info.linked.setdefault(r["child"], []).append(
                LinkedReference(
                    child=r["child"],
                    parent=r["parent"],
                    anchor=anchors[0],
                    derived=tuple((c, p) for c, p in pairs if p != "id"),
                )
            )
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
        resolved = dict(overrides)
        await self._table_defaults(table, resolved)
        for link in self.schema.linked.get(table, ()):
            await self._resolve_linked(link, tenant_id, resolved)

        values: dict[str, Any] = {}
        for col in self.schema.columns[table]:
            if col.name in resolved:
                values[col.name] = resolved[col.name]
            elif col.name == "id":
                values["id"] = str(uuid.uuid4())
            elif col.name == "tenant_id":
                if tenant_id is not None:
                    values["tenant_id"] = tenant_id
            elif col.required:
                values[col.name] = await self._generate(table, col, tenant_id)

        names = list(values)
        placeholders = ", ".join(f"${i}" for i in range(1, len(names) + 1))
        await self.conn.execute(
            f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})",
            *values.values(),
        )
        return values["id"]

    async def _table_defaults(self, table: str, resolved: dict[str, Any]) -> None:
        """Table-specific defaults that a 'minimal valid row' needs beyond NOT NULL columns.

        recovery_plans (migration 0008): a recovery action may only reference a plan whose
        pre-recovery snapshot was captured, so factory plans are captured by default. The
        hash is computed by PostgreSQL. Pass ``pre_recovery_snapshot_json="{}"`` for an
        uncaptured plan.
        """
        if table == "detection_results":
            # These fields are protected by database CHECK constraints. The generic
            # random-string generator is unsuitable for constrained vocabularies,
            # so fixture rows use a valid, inert observation. Callers may override
            # these values to exercise negative cases.
            for column, value in {
                "detection_category": "MEMORY_INTEGRITY",
                "classification_type": "OBSERVATION",
                "detection_method": "DETERMINISTIC_RULE",
                "uncertainty_state": "DEFINITIVE",
                "severity": "INFORMATIONAL",
                "recommended_outcome": "ALERT_ONLY",
            }.items():
                resolved.setdefault(column, value)
            return
        if table != "recovery_plans" or "pre_recovery_snapshot_json" in resolved:
            return
        if not any(c.name == "pre_recovery_snapshot_sha256" for c in self.schema.columns[table]):
            return  # schema older than 0008
        resolved["pre_recovery_snapshot_json"] = DEFAULT_RECOVERY_SNAPSHOT
        resolved.setdefault(
            "pre_recovery_snapshot_sha256",
            await self.conn.fetchval(
                "SELECT encode(sha256(convert_to($1::jsonb::text, 'UTF8')), 'hex')", DEFAULT_RECOVERY_SNAPSHOT
            ),
        )

    async def _generate(self, table: str, col: _Column, tenant_id: str | None) -> Any:
        """Value for a required column: a new same-tenant parent for references, else a dummy value."""
        reference = self.schema.references.get((table, col.name))
        if reference is None:
            return _value_for(col)
        parent, parent_column = reference
        parent_tenant = None if parent in GLOBAL_PARENT_VALUES else tenant_id
        parent_id = await self.create(parent, parent_tenant)
        if parent_column == "id":
            return parent_id
        # Composite tenant FKs may reference a natural key such as
        # memberships.user_id rather than the parent's primary key.
        return await self.conn.fetchval(
            f'SELECT "{parent_column}" FROM "{parent}" WHERE id = $1',
            parent_id,
        )

    async def _resolve_linked(self, link: LinkedReference, tenant_id: str | None, resolved: dict[str, Any]) -> None:
        """Make the columns of one linked FK point at the SAME parent row (see module docstring)."""
        derived_given = [c for c, _ in link.derived if c in resolved]
        if link.anchor in resolved:
            if len(derived_given) == len(link.derived):
                return  # caller supplied everything: keep it, even if forged
            cols = ", ".join(p for _, p in link.derived)
            row = await self.conn.fetchrow(f"SELECT {cols} FROM {link.parent} WHERE id = $1", resolved[link.anchor])
            if row is not None:
                for child_col, parent_col in link.derived:
                    resolved.setdefault(child_col, row[parent_col])
            # Unknown parent: leave the rest to normal generation; the FK rejects the insert.
            return

        columns = {c.name: c for c in self.schema.columns[link.child]}
        if not columns[link.anchor].required and not derived_given:
            return  # optional link left empty
        for child_col, _ in link.derived:
            if child_col not in resolved:
                resolved[child_col] = await self._generate(link.child, columns[child_col], tenant_id)
        parent_tenant = None if link.parent in GLOBAL_PARENT_VALUES else tenant_id
        resolved[link.anchor] = await self.create(
            link.parent, parent_tenant, **{parent_col: resolved[child_col] for child_col, parent_col in link.derived}
        )
