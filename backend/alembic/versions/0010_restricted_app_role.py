"""Create restricted application role with least-privilege grants (Phase 7).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-20

Creates a dedicated `amsc_app` role that the backend connects as in production.
The role has SELECT/INSERT/UPDATE/DELETE on application tables but NO DDL
privileges (CREATE, ALTER, DROP) and NO superuser. The migration runner role
(`amsc`) retains ownership. This enforces defense-in-depth at the DB layer.
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

APP_ROLE = "amsc_app"


def upgrade() -> None:
    op.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD 'amsc_app_password'; END IF; END $$;")
    # Grant connect
    op.execute(f"GRANT CONNECT ON DATABASE amsc TO {APP_ROLE};")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE};")
    # Grant DML on all existing tables
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE};")
    # Grant usage on sequences
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE};")
    # Default privileges for future tables (created by migration runner)
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE};")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE};")
    # Explicitly deny DDL — revoke CREATE on schema
    op.execute(f"REVOKE CREATE ON SCHEMA public FROM {APP_ROLE};")


def downgrade() -> None:
    op.execute(f"DROP ROLE IF EXISTS {APP_ROLE};")
