"""Throwaway PostgreSQL databases and Alembic helpers for M6 database tests.

Every test database is created as ``amsc_test_<16 hex>`` on the server named by
``TEST_DATABASE_URL``. That variable is REQUIRED: there is deliberately no
fallback to ``DATABASE_URL`` or to built-in defaults, so destructive test setup
can never be pointed at an application database by accident.

``TEST_DATABASE_URL`` names the server plus a maintenance database (``postgres``)
or a dedicated ``amsc_test*`` database. The helpers only CREATE / DROP their own
``amsc_test_<hex>`` databases; they never write into the database in the URL.
The role needs CREATEDB. Local example (docker-compose credentials)::

    $env:TEST_DATABASE_URL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres"

Safety checks (``resolve_test_server_url``):
- host must be local (localhost / 127.0.0.1 / ::1) or listed in
  ``TEST_DATABASE_ALLOWED_HOSTS`` (comma separated, e.g. ``postgres`` for a CI service);
- the database must be ``postgres`` or start with ``amsc_test``;
- host, database and user must not look like production (prod / production / prd / live);
- the target must not be the same server + database as ``DATABASE_URL``.
"""

import asyncio
import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path

import asyncpg
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

REPO_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"

TEMP_DB_PREFIX = "amsc_test_"
TEMP_DB_PATTERN = re.compile(r"^amsc_test_[0-9a-f]{16}$")
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
ALLOWED_DRIVERS = frozenset({"postgresql", "postgresql+asyncpg"})
MAINTENANCE_DATABASE = "postgres"
PRODUCTION_MARKERS = re.compile(r"(^|[^a-z0-9])(prod|production|prd|live)([^a-z0-9]|$)", re.IGNORECASE)


class UnsafeTestDatabaseError(RuntimeError):
    """Raised when the test database configuration is missing or could hit a real database."""


def _same_target(a: URL, b: URL) -> bool:
    return (a.host or "").lower() == (b.host or "").lower() and (a.port or 5432) == (b.port or 5432)         and a.database == b.database


def resolve_test_server_url(env: Mapping[str, str] | None = None) -> URL:
    """Validate ``TEST_DATABASE_URL`` and return it, or raise ``UnsafeTestDatabaseError``."""
    env = os.environ if env is None else env
    raw = (env.get("TEST_DATABASE_URL") or "").strip()
    if not raw:
        raise UnsafeTestDatabaseError(
            "TEST_DATABASE_URL is required for M6 database tests (DATABASE_URL is never used). "
            'Example: $env:TEST_DATABASE_URL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/postgres"'
        )
    try:
        url = make_url(raw)
    except ArgumentError as exc:
        raise UnsafeTestDatabaseError("TEST_DATABASE_URL is not a valid database URL.") from exc

    if url.drivername not in ALLOWED_DRIVERS:
        raise UnsafeTestDatabaseError(f"TEST_DATABASE_URL must use PostgreSQL, got driver {url.drivername!r}.")

    extra_hosts = {h.strip().lower() for h in env.get("TEST_DATABASE_ALLOWED_HOSTS", "").split(",") if h.strip()}
    host = (url.host or "").lower()
    if host not in LOCAL_HOSTS | extra_hosts:
        raise UnsafeTestDatabaseError(
            f"Test database host {host or '<none>'!r} is not local. Add it to TEST_DATABASE_ALLOWED_HOSTS "
            "only if it is a dedicated test server."
        )

    database = url.database or ""
    if database != MAINTENANCE_DATABASE and not database.startswith("amsc_test"):
        raise UnsafeTestDatabaseError(
            f"Test database name {database!r} is not allowed: use 'postgres' or a name starting with 'amsc_test'."
        )

    for label, value in (("host", host), ("database", database), ("user", url.username or "")):
        if PRODUCTION_MARKERS.search(value):
            raise UnsafeTestDatabaseError(f"Test database {label} {value!r} looks like production.")

    app_raw = (env.get("DATABASE_URL") or "").strip()
    if app_raw:
        try:
            app_url = make_url(app_raw)
        except ArgumentError:
            app_url = None
        if app_url is not None and _same_target(url, app_url):
            raise UnsafeTestDatabaseError("TEST_DATABASE_URL points at the same database as DATABASE_URL.")
    return url


def _server_url() -> URL:
    return resolve_test_server_url()


def check_temp_database_name(name: str) -> str:
    """Only names produced by ``create_temp_database`` may ever be dropped."""
    if not isinstance(name, str) or not TEMP_DB_PATTERN.fullmatch(name):
        raise UnsafeTestDatabaseError(f"Refusing to touch non-test database {name!r}")
    return name


def sqlalchemy_url(database: str) -> str:
    return _server_url().set(drivername="postgresql+asyncpg", database=database).render_as_string(
        hide_password=False
    )


def asyncpg_dsn(database: str) -> str:
    return _server_url().set(drivername="postgresql", database=database).render_as_string(
        hide_password=False
    )


async def _admin_execute(sql: str) -> None:
    conn = await asyncpg.connect(asyncpg_dsn(MAINTENANCE_DATABASE))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def create_temp_database() -> str:
    name = check_temp_database_name(f"{TEMP_DB_PREFIX}{uuid.uuid4().hex[:16]}")
    asyncio.run(_admin_execute(f'CREATE DATABASE "{name}"'))
    return name


def drop_temp_database(name: str) -> None:
    # Hard guard: this helper may only ever drop databases it created.
    check_temp_database_name(name)
    asyncio.run(_admin_execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


TEMP_ROLE_PREFIX = "amsc_test_role_"
TEMP_ROLE_PATTERN = re.compile(r"^amsc_test_role_[0-9a-f]{16}$")


def check_temp_role_name(name: str) -> str:
    """Only roles produced by ``create_temp_login_role`` may ever be dropped."""
    if not isinstance(name, str) or not TEMP_ROLE_PATTERN.fullmatch(name):
        raise UnsafeTestDatabaseError(f"Refusing to touch non-test role {name!r}")
    return name


async def create_temp_login_role(create_statement_for) -> tuple[str, str]:
    """Create a throwaway LOGIN role (cluster-wide) and return (name, password).

    ``create_statement_for(name)`` returns the CREATE ROLE statement under test
    (``backend.app.database.roles.app_role_create_statement``). Needs CREATEROLE.
    """
    name = check_temp_role_name(f"{TEMP_ROLE_PREFIX}{uuid.uuid4().hex[:16]}")
    password = uuid.uuid4().hex
    conn = await asyncpg.connect(asyncpg_dsn(MAINTENANCE_DATABASE))
    try:
        await conn.execute(create_statement_for(name))
        await conn.execute(f"ALTER ROLE \"{name}\" PASSWORD '{password}'")  # generated hex only
    finally:
        await conn.close()
    return name, password


async def drop_temp_login_role(name: str, databases: list[str]) -> None:
    """Remove the role's privileges in each database, then drop the role."""
    check_temp_role_name(name)
    for database in databases:
        check_temp_database_name(database)
        conn = await asyncpg.connect(asyncpg_dsn(database))
        try:
            await conn.execute(f'DROP OWNED BY "{name}"')
        finally:
            await conn.close()
    conn = await asyncpg.connect(asyncpg_dsn(MAINTENANCE_DATABASE))
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{name}"')
    finally:
        await conn.close()


def role_dsn(database: str, role: str, password: str) -> str:
    """asyncpg DSN for the test server, logging in as ``role``."""
    url = _server_url().set(drivername="postgresql", database=database, username=role, password=password)
    return url.render_as_string(hide_password=False)


def alembic_config(database: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.attributes["database_url"] = sqlalchemy_url(database)
    cfg.attributes["configure_logger"] = False
    return cfg


def upgrade(database: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database), revision)


def downgrade(database: str, revision: str = "base") -> None:
    command.downgrade(alembic_config(database), revision)
