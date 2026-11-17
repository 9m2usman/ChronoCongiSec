"""Throwaway PostgreSQL databases and Alembic helpers for M6 database tests.

Every test database is created as ``amsc_test_<random>`` on the server named by
``TEST_DATABASE_URL`` (falls back to ``DATABASE_URL``, then to the docker-compose
defaults). The developer database itself is never touched: only the server
connection details are reused and the maintenance ``postgres`` database is used
to CREATE / DROP the temporary databases. The role needs CREATEDB.
"""

import asyncio
import os
import uuid
from pathlib import Path

import asyncpg
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

REPO_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"

# docker-compose.yml / .env.example development defaults.
DEFAULT_SERVER_URL = "postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/amsc"
TEMP_DB_PREFIX = "amsc_test_"


def _server_url():
    raw = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL") or DEFAULT_SERVER_URL
    return make_url(raw)


def sqlalchemy_url(database: str) -> str:
    return _server_url().set(drivername="postgresql+asyncpg", database=database).render_as_string(
        hide_password=False
    )


def asyncpg_dsn(database: str) -> str:
    return _server_url().set(drivername="postgresql", database=database).render_as_string(
        hide_password=False
    )


async def _admin_execute(sql: str) -> None:
    conn = await asyncpg.connect(asyncpg_dsn("postgres"))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def create_temp_database() -> str:
    name = f"{TEMP_DB_PREFIX}{uuid.uuid4().hex[:16]}"
    asyncio.run(_admin_execute(f'CREATE DATABASE "{name}"'))
    return name


def drop_temp_database(name: str) -> None:
    # Hard guard: this helper may only ever drop databases it created.
    if not name.startswith(TEMP_DB_PREFIX):
        raise ValueError(f"Refusing to drop non-test database {name!r}")
    asyncio.run(_admin_execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


def alembic_config(database: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.attributes["database_url"] = sqlalchemy_url(database)
    cfg.attributes["configure_logger"] = False
    return cfg


def upgrade(database: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database), revision)


def downgrade(database: str, revision: str = "base") -> None:
    command.downgrade(alembic_config(database), revision)
