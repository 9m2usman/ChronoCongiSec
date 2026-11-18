"""Schema fingerprint: everything a migration can create or drop, as comparable data.

Owner: M6
Used by the exact-inverse test: after each downgrade, the schema must be identical to the
schema produced by upgrading a fresh database to that revision. Column order and object
OIDs are ignored; definitions are compared through PostgreSQL's own deparsers.
Alembic's bookkeeping table ``alembic_version`` is excluded.
"""

import asyncpg

QUERIES = {
    "columns": """
        SELECT table_name, column_name, data_type, character_maximum_length, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name <> 'alembic_version'
    """,
    "constraints": """
        SELECT c.conrelid::regclass::text AS table_name, c.conname, c.contype::text, pg_get_constraintdef(c.oid)
        FROM pg_constraint c
        WHERE c.connamespace = 'public'::regnamespace AND c.conrelid <> 0
          AND c.conrelid::regclass::text <> 'alembic_version'
    """,
    "indexes": """
        SELECT tablename, indexname, indexdef FROM pg_indexes
        WHERE schemaname = 'public' AND tablename <> 'alembic_version'
    """,
    "triggers": """
        SELECT t.tgrelid::regclass::text, t.tgname, t.tgenabled::text, pg_get_triggerdef(t.oid)
        FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace
    """,
    "functions": """
        SELECT p.proname, pg_get_function_identity_arguments(p.oid), md5(pg_get_functiondef(p.oid))
        FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace
    """,
}


async def schema_fingerprint(conn: asyncpg.Connection) -> dict[str, list[tuple]]:
    result = {}
    for name, sql in QUERIES.items():
        result[name] = sorted(tuple(row) for row in await conn.fetch(sql))
    return result


def describe_difference(expected: dict[str, list[tuple]], actual: dict[str, list[tuple]]) -> str:
    lines = []
    for name in QUERIES:
        missing = sorted(set(expected[name]) - set(actual[name]))
        extra = sorted(set(actual[name]) - set(expected[name]))
        lines += [f"{name} missing: {m}" for m in missing] + [f"{name} extra: {e}" for e in extra]
    return "\n".join(lines) or "no difference"
