"""Least-privilege database roles: SQL for the owner / application split (Day 6 preparation).

Module: backend.app.database.roles
Owner: M6

Today the application connects as ``amsc``, the docker image's superuser and the owner
of every table. A superuser or table owner can switch triggers off
(``ALTER TABLE ... DISABLE TRIGGER``, ``DROP TRIGGER``, ``SET session_replication_role``),
so the append-only and permanent-record triggers only bind a NON-owner, NON-superuser role.

This module only GENERATES SQL; it never runs it. Creating the roles, passwords and the
switch of the application's ``DATABASE_URL`` belong to M7 (docker-compose, .env, CI):
OPEN-DEPENDENCIES OD-18. The intended split:

- owner role: owns the schema objects and runs Alembic migrations;
- application role (``app_role_create_statement``): LOGIN, NOSUPERUSER, NOCREATEDB,
  NOCREATEROLE, NOREPLICATION, NOBYPASSRLS; no password here (set by M7);
- privileges (``app_role_grant_statements``):
  - SELECT/INSERT/UPDATE/DELETE on application tables, nothing on ``alembic_version``;
  - ``audit_events``: SELECT and INSERT only (append-only);
  - ``policy_decisions``: SELECT, INSERT and UPDATE of ``execution_status`` only (permanent
    records, migration 0009);
  - never TRUNCATE, never ownership, so triggers cannot be disabled or dropped;
  - default privileges so tables created later by the owner get the same grants.

The privilege layer and the database triggers protect the same rules twice: the role is
refused before the trigger even runs (SQLSTATE 42501), and the trigger still refuses the
operation for any role that has the privilege.
"""

import re
from collections.abc import Sequence

ROLE_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SCHEMA = "public"

APP_TABLE_PRIVILEGES = "SELECT, INSERT, UPDATE, DELETE"
# Table -> privileges the application keeps (everything else is revoked).
RESTRICTED_TABLES: dict[str, str] = {
    "audit_events": "SELECT, INSERT",
    "policy_decisions": "SELECT, INSERT, UPDATE (execution_status)",
}
NO_ACCESS_TABLES: tuple[str, ...] = ("alembic_version",)


def quote_role(name: str) -> str:
    """Validate a role name (lower-case identifier, max 63 chars) and return it quoted."""
    if not isinstance(name, str) or not ROLE_NAME_PATTERN.fullmatch(name):
        raise ValueError(f"invalid role name {name!r}: use lower-case letters, digits and _ (max 63)")
    return f'"{name}"'


def app_role_create_statement(app_role: str) -> str:
    """CREATE ROLE for the application login. The password is set separately by M7."""
    return (
        f"CREATE ROLE {quote_role(app_role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        "NOREPLICATION NOBYPASSRLS INHERIT"
    )


def app_role_grant_statements(app_role: str, *, owner_role: str | None = None) -> list[str]:
    """Grants for the application role in the current database, in execution order.

    Run as the owner (or a superuser) after ``alembic upgrade head``. Re-running is safe.
    With ``owner_role``, tables the owner creates later get the same default grants.
    """
    app = quote_role(app_role)
    statements = [
        f"GRANT USAGE ON SCHEMA {SCHEMA} TO {app}",
        f"GRANT {APP_TABLE_PRIVILEGES} ON ALL TABLES IN SCHEMA {SCHEMA} TO {app}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {SCHEMA} TO {app}",
    ]
    for table, keep in RESTRICTED_TABLES.items():
        statements.append(f"REVOKE ALL ON TABLE {SCHEMA}.{table} FROM {app}")
        statements.append(f"GRANT {keep} ON TABLE {SCHEMA}.{table} TO {app}")
    for table in NO_ACCESS_TABLES:
        statements.append(f"REVOKE ALL ON TABLE {SCHEMA}.{table} FROM {app}")
    statements.append(f"REVOKE TRUNCATE ON ALL TABLES IN SCHEMA {SCHEMA} FROM {app}")
    if owner_role is not None:
        owner = quote_role(owner_role)
        statements.append(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA {SCHEMA} "
            f"GRANT {APP_TABLE_PRIVILEGES} ON TABLES TO {app}"
        )
    return statements


def app_role_script(app_role: str, *, owner_role: str | None = None, create: bool = True) -> str:
    """The full provisioning script as text (for M7 to review and run)."""
    lines: Sequence[str] = (
        ([app_role_create_statement(app_role)] if create else [])
        + app_role_grant_statements(app_role, owner_role=owner_role)
    )
    return ";\n".join(lines) + ";\n"


# Read-only checks M7 / CI can run against the real environment.
APP_ROLE_ATTRIBUTES_SQL = (
    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
    "FROM pg_roles WHERE rolname = $1"
)
TABLES_OWNED_BY_ROLE_SQL = (
    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = $1"
)
