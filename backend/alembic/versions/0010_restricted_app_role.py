"""Create restricted application role with least-privilege grants (Phase 7).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-20

Creates a dedicated `amsc_app` role that the backend connects as in production.
The role has SELECT/INSERT/UPDATE/DELETE on application tables but NO DDL
privileges (CREATE, ALTER, DROP) and NO superuser. The migration runner role
retains ownership. This enforces defense-in-depth at the DB layer.

Database name is resolved dynamically via current_database() so the migration
works regardless of the actual database name. Credentials are NOT hardcoded;
the role is created without a password (OS-level auth) or the password is
set via the AMS_APP_DB_PASSWORD environment variable at runtime, not in SQL.
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

APP_ROLE = "amsc_app"


def upgrade() -> None:
    # Create role idempotently WITHOUT a hardcoded password.
    op.execute(
        f"DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "
        f"CREATE ROLE {APP_ROLE} LOGIN NOCREATEDB NOCREATEROLE NOSUPERUSER; "
        f"END IF; END $$;"
    )
    # Grant connect to the CURRENT database (dynamic, never hardcoded).
    op.execute(
        f"DO $$ BEGIN "
        f"EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), '{APP_ROLE}'); "
        f"END $$;"
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE};")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE};")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE};")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE};")
    op.execute(f"REVOKE CREATE ON SCHEMA public FROM {APP_ROLE};")


def downgrade() -> None:
    op.execute(f"DROP ROLE IF EXISTS {APP_ROLE};")
