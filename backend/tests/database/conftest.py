"""Fixtures for M6 database tests (real PostgreSQL, temporary databases).

Module: backend.tests.database.conftest
Owner: M6

These tests require a reachable PostgreSQL 15+ server (``docker compose up -d postgres``).
They fail, rather than skip, when the server is unavailable so that a missing
database can never be mistaken for a passing schema.
"""

from collections.abc import AsyncIterator, Iterator

import asyncpg
import pytest
import pytest_asyncio

from backend.tests.database import helpers


@pytest.fixture
def empty_db() -> Iterator[str]:
    """A brand new, blank database (no migrations applied)."""
    name = helpers.create_temp_database()
    try:
        yield name
    finally:
        helpers.drop_temp_database(name)


@pytest.fixture
def migrated_db(empty_db: str) -> str:
    """A fresh database migrated to head (function scope: safe for inserts)."""
    helpers.upgrade(empty_db, "head")
    return empty_db


@pytest.fixture(scope="module")
def migrated_db_readonly() -> Iterator[str]:
    """A database migrated to head shared by one module. Read-only tests only."""
    name = helpers.create_temp_database()
    try:
        helpers.upgrade(name, "head")
        yield name
    finally:
        helpers.drop_temp_database(name)


@pytest_asyncio.fixture
async def conn(migrated_db: str) -> AsyncIterator[asyncpg.Connection]:
    """Raw asyncpg connection to a fresh migrated database."""
    connection = await asyncpg.connect(helpers.asyncpg_dsn(migrated_db))
    try:
        yield connection
    finally:
        await connection.close()


@pytest_asyncio.fixture
async def ro_conn(migrated_db_readonly: str) -> AsyncIterator[asyncpg.Connection]:
    """Raw asyncpg connection to the shared read-only migrated database."""
    connection = await asyncpg.connect(helpers.asyncpg_dsn(migrated_db_readonly))
    try:
        yield connection
    finally:
        await connection.close()
