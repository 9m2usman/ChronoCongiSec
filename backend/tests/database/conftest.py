"""Fixtures for M6 database tests (real PostgreSQL, temporary databases).

Module: backend.tests.database.conftest
Owner: M6

These tests require a reachable PostgreSQL 15+ server (``docker compose up -d postgres``)
and an explicit ``TEST_DATABASE_URL`` (see ``helpers.py``; ``DATABASE_URL`` is never used).
They fail, rather than skip, when either is missing so that a missing database
can never be mistaken for a passing schema.

Fixture guide:
- ``empty_db`` / ``migrated_db``: a private database per test (migration tests).
- ``module_db``: one migrated database shared by a test module.
- ``ro_conn``: connection to ``module_db`` for read-only schema inspection.
- ``tx_conn``: connection to ``module_db`` inside a transaction that is ROLLED BACK
  after the test, so every test sees a clean database. Wrap statements that are
  expected to fail in ``async with tx_conn.transaction():`` (a savepoint) when the
  test continues afterwards.
- ``factory``: schema-driven ``RowFactory`` bound to ``tx_conn``.
- ``session``: SQLAlchemy ``AsyncSession`` on ``module_db``, rolled back after the test.
"""

from collections.abc import AsyncIterator, Iterator

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from backend.tests.database import helpers
from backend.tests.database.factory import RowFactory, SchemaInfo


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
    """A fresh database migrated to head (function scope)."""
    helpers.upgrade(empty_db, "head")
    return empty_db


@pytest.fixture(scope="module")
def module_db() -> Iterator[str]:
    """A database migrated to head, shared by one test module."""
    name = helpers.create_temp_database()
    try:
        helpers.upgrade(name, "head")
        yield name
    finally:
        helpers.drop_temp_database(name)


@pytest_asyncio.fixture
async def conn(migrated_db: str) -> AsyncIterator[asyncpg.Connection]:
    """Raw asyncpg connection to a private migrated database (autocommit)."""
    connection = await asyncpg.connect(helpers.asyncpg_dsn(migrated_db))
    try:
        yield connection
    finally:
        await connection.close()


@pytest_asyncio.fixture
async def ro_conn(module_db: str) -> AsyncIterator[asyncpg.Connection]:
    """Connection to the shared module database. Schema inspection only."""
    connection = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
    try:
        yield connection
    finally:
        await connection.close()


@pytest_asyncio.fixture
async def tx_conn(module_db: str) -> AsyncIterator[asyncpg.Connection]:
    """Connection inside an outer transaction that is always rolled back."""
    connection = await asyncpg.connect(helpers.asyncpg_dsn(module_db))
    tx = connection.transaction()
    await tx.start()
    try:
        yield connection
    finally:
        await tx.rollback()
        await connection.close()


@pytest_asyncio.fixture
async def factory(tx_conn: asyncpg.Connection) -> RowFactory:
    return RowFactory(tx_conn, await SchemaInfo.load(tx_conn))


@pytest_asyncio.fixture
async def session(module_db: str) -> AsyncIterator[AsyncSession]:
    """ORM session whose work is rolled back after the test.

    ``join_transaction_mode="create_savepoint"`` turns ``session.commit()`` into a
    savepoint release, so even committed work disappears at the outer rollback.
    """
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), poolclass=NullPool)
    async with engine.connect() as connection:
        outer = await connection.begin()
        db_session = AsyncSession(
            bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
        )
        try:
            yield db_session
        finally:
            await db_session.close()
            await outer.rollback()
    await engine.dispose()
