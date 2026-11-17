"""Tenant-ownership rules, verified against the REAL migrated PostgreSQL schema.

Owner: M6
HARD RULE (AMSC-DOC-005 §1, DOC-006 M6 constraint): every tenant-owned table has a
non-nullable ``tenant_id`` FK to ``tenants.id``. Only ``roles.tenant_id`` may be
NULL (platform-global roles). Global tables are listed explicitly.
"""

import asyncpg
import pytest

from backend.app.database.models import GLOBAL_TABLES, NULLABLE_TENANT_TABLES

pytestmark = pytest.mark.asyncio


async def _tables(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
    )
    return {r["tablename"] for r in rows}


async def _tenant_id_columns(conn: asyncpg.Connection) -> dict[str, bool]:
    """table -> is_nullable for every public.<table>.tenant_id column."""
    rows = await conn.fetch(
        """
        SELECT table_name, is_nullable = 'YES' AS nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' AND column_name = 'tenant_id'
        """
    )
    return {r["table_name"]: r["nullable"] for r in rows}


async def _tables_with_tenant_fk(conn: asyncpg.Connection) -> set[str]:
    """Tables whose FK set includes one where tenant_id references tenants.id."""
    rows = await conn.fetch(
        """
        SELECT DISTINCT src.relname AS table_name
        FROM pg_constraint c
        JOIN pg_class src ON src.oid = c.conrelid
        JOIN pg_class ref ON ref.oid = c.confrelid
        JOIN pg_namespace n ON n.oid = src.relnamespace
        JOIN LATERAL unnest(c.conkey, c.confkey) AS k(src_attnum, ref_attnum) ON TRUE
        JOIN pg_attribute sa ON sa.attrelid = c.conrelid AND sa.attnum = k.src_attnum
        JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.ref_attnum
        WHERE c.contype = 'f' AND n.nspname = 'public'
          AND ref.relname = 'tenants'
          AND sa.attname = 'tenant_id' AND ra.attname = 'id'
          AND array_length(c.conkey, 1) = 1
        """
    )
    return {r["table_name"] for r in rows}


async def test_every_table_is_tenant_owned_or_explicitly_global(ro_conn: asyncpg.Connection) -> None:
    tables = await _tables(ro_conn)
    tenant_cols = await _tenant_id_columns(ro_conn)

    unclassified = tables - GLOBAL_TABLES - set(tenant_cols)
    assert unclassified == set(), (
        f"Tables with no tenant_id that are not in GLOBAL_TABLES: {sorted(unclassified)}"
    )


async def test_global_tables_have_no_tenant_id(ro_conn: asyncpg.Connection) -> None:
    tables = await _tables(ro_conn)
    tenant_cols = await _tenant_id_columns(ro_conn)

    assert GLOBAL_TABLES <= tables, "GLOBAL_TABLES lists a table that does not exist"
    assert GLOBAL_TABLES.isdisjoint(tenant_cols), (
        "A table declared global carries tenant_id; classify it as tenant-owned instead"
    )


async def test_tenant_id_is_not_null_except_global_roles(ro_conn: asyncpg.Connection) -> None:
    tenant_cols = await _tenant_id_columns(ro_conn)

    nullable = {table for table, is_nullable in tenant_cols.items() if is_nullable}
    assert nullable == set(NULLABLE_TENANT_TABLES), (
        f"tenant_id must be NOT NULL; unexpected nullable tables: {sorted(nullable - NULLABLE_TENANT_TABLES)}"
    )


async def test_every_tenant_id_references_tenants(ro_conn: asyncpg.Connection) -> None:
    tenant_cols = await _tenant_id_columns(ro_conn)
    with_fk = await _tables_with_tenant_fk(ro_conn)

    missing = set(tenant_cols) - with_fk
    assert missing == set(), f"tenant_id without FK to tenants.id: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Day 2: composite tenant-consistent references (AMSC-DOC-005 §1)
# ---------------------------------------------------------------------------

from backend.tests.database.relationships import TENANT_RELATIONSHIPS  # noqa: E402

_FK_QUERY = """
SELECT c.conname, src.relname AS child, ref.relname AS parent, c.confdeltype::text AS confdeltype,
       array_agg(sa.attname ORDER BY k.ord) AS child_cols,
       array_agg(ra.attname ORDER BY k.ord) AS parent_cols,
       (SELECT array_agg(a.attname) FROM pg_attribute a
         WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.confdelsetcols)) AS set_null_cols
FROM pg_constraint c
JOIN pg_class src ON src.oid = c.conrelid
JOIN pg_class ref ON ref.oid = c.confrelid
JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY AS k(src_attnum, ref_attnum, ord) ON TRUE
JOIN pg_attribute sa ON sa.attrelid = c.conrelid AND sa.attnum = k.src_attnum
JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.ref_attnum
WHERE c.contype = 'f' AND src.relnamespace = 'public'::regnamespace
GROUP BY c.oid, c.conname, src.relname, ref.relname, c.confdeltype, c.conrelid, c.confdelsetcols
"""

_DELETE_ACTIONS = {"c": "CASCADE", "n": "SET NULL", "a": "NO ACTION", "r": "RESTRICT", "d": "SET DEFAULT"}


async def _foreign_keys(conn: asyncpg.Connection) -> list[asyncpg.Record]:
    return await conn.fetch(_FK_QUERY)


async def test_every_reference_between_tenant_tables_is_composite(ro_conn: asyncpg.Connection) -> None:
    """A tenant-owned child may reference a tenant-owned parent only via (tenant_id, id)."""
    tenant_tables = set(await _tenant_id_columns(ro_conn))
    violations = []
    checked = 0
    for fk in await _foreign_keys(ro_conn):
        if fk["child"] not in tenant_tables or fk["parent"] not in tenant_tables:
            continue  # references to tenants / global tables
        checked += 1
        pairs = dict(zip(fk["child_cols"], fk["parent_cols"]))
        if pairs.get("tenant_id") != "tenant_id" or len(pairs) != 2:
            violations.append(f"{fk['conname']}: {fk['child_cols']} -> {fk['parent']}{fk['parent_cols']}")
    assert violations == [], "Non tenant-consistent references:\n" + "\n".join(violations)
    assert checked >= len(TENANT_RELATIONSHIPS), f"Only {checked} tenant-to-tenant FKs inspected"


async def test_relationships_match_expected_list_exactly(ro_conn: asyncpg.Connection) -> None:
    """Every expected relationship exists as a composite FK with the right delete rule, and no others."""
    actual = set()
    for fk in await _foreign_keys(ro_conn):
        cols = list(fk["child_cols"])
        if len(cols) == 2 and cols[0] == "tenant_id" and list(fk["parent_cols"]) == ["tenant_id", "id"]:
            actual.add((fk["child"], cols[1], fk["parent"], _DELETE_ACTIONS[fk["confdeltype"]]))
    expected = {tuple(rel) for rel in TENANT_RELATIONSHIPS}

    assert expected - actual == set(), f"Missing or wrong composite FKs: {sorted(expected - actual)}"
    assert actual - expected == set(), f"Unlisted composite FKs: {sorted(actual - expected)}"


async def test_set_null_references_never_clear_tenant_id(ro_conn: asyncpg.Connection) -> None:
    """ON DELETE SET NULL must name only the reference column, never tenant_id."""
    checked = 0
    for fk in await _foreign_keys(ro_conn):
        if fk["confdeltype"] != "n" or "tenant_id" not in fk["child_cols"]:
            continue
        checked += 1
        ref_cols = [c for c in fk["child_cols"] if c != "tenant_id"]
        assert fk["set_null_cols"] == ref_cols, (
            f"{fk['conname']} would null {fk['set_null_cols'] or fk['child_cols']}; expected {ref_cols}"
        )
    # Guard against a vacuous pass (e.g. a type mismatch that skips every row).
    expected = sum(1 for rel in TENANT_RELATIONSHIPS if rel.on_delete == "SET NULL")
    assert checked == expected, f"Checked {checked} SET NULL FKs, expected {expected}"


async def test_referenced_parents_have_tenant_parent_key(ro_conn: asyncpg.Connection) -> None:
    rows = await ro_conn.fetch(
        """
        SELECT cl.relname AS table_name
        FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.conrelid
        WHERE c.contype IN ('u', 'p') AND cl.relnamespace = 'public'::regnamespace
          AND (SELECT array_agg(a.attname ORDER BY a.attname) FROM pg_attribute a
               WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)) = ARRAY['id', 'tenant_id']::name[]
        """
    )
    with_key = {r["table_name"] for r in rows}
    parents = {rel.parent for rel in TENANT_RELATIONSHIPS}
    assert parents - with_key == set()


async def test_every_composite_fk_is_backed_by_an_index(ro_conn: asyncpg.Connection) -> None:
    """Each (tenant_id, col) FK needs an index whose leading columns cover it (fast cascades)."""
    indexes = await ro_conn.fetch(
        """
        SELECT t.relname AS table_name,
               array(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY u(attnum, ord)
                     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = u.attnum
                     ORDER BY u.ord) AS cols
        FROM pg_index i JOIN pg_class t ON t.oid = i.indrelid
        WHERE t.relnamespace = 'public'::regnamespace
        """
    )
    leading = {(r["table_name"], tuple(r["cols"][:2])) for r in indexes}
    leading |= {(r["table_name"], (r["cols"][0],)) for r in indexes if r["cols"]}
    missing = [
        rel.id for rel in TENANT_RELATIONSHIPS
        if (rel.child, ("tenant_id", rel.column)) not in leading and (rel.child, (rel.column,)) not in leading
    ]
    assert missing == [], f"Composite FKs without a supporting index: {missing}"


async def test_tenant_id_immutability_trigger_on_every_tenant_table(ro_conn: asyncpg.Connection) -> None:
    tenant_tables = set(await _tenant_id_columns(ro_conn))
    rows = await ro_conn.fetch(
        """
        SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        WHERE t.tgname = 'trg_forbid_tenant_id_change' AND NOT t.tgisinternal AND t.tgenabled <> 'D'
        """
    )
    assert tenant_tables - {r["relname"] for r in rows} == set()
