"""Async engine and session factory.

Module: backend.app.database.session
Owner: M6 (Database Architect & Governance)

The connection string comes from ``DATABASE_URL`` (environment) or, if unset,
from M1's ``Settings.DATABASE_URL``. Only the ``postgresql+asyncpg`` driver is
accepted: SQLite or other drivers cannot enforce the composite tenant foreign
keys, triggers and JSONB defaults the schema depends on.
"""

import os

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

REQUIRED_DRIVER_PREFIX = "postgresql+asyncpg://"


def get_database_url() -> str:
    """Resolve the database URL (env first, then application settings)."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        from backend.app.core.config import get_settings

        url = get_settings().DATABASE_URL
    if not url.startswith(REQUIRED_DRIVER_PREFIX):
        raise ValueError(
            "DATABASE_URL must use the 'postgresql+asyncpg://' driver; "
            "other engines cannot enforce AMSC tenant constraints."
        )
    return url


def create_engine(url: str | None = None, **kwargs) -> AsyncEngine:
    """Create an async engine. ``pool_pre_ping`` avoids stale connections."""
    kwargs.setdefault("pool_pre_ping", True)
    return create_async_engine(url or get_database_url(), **kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory. ``expire_on_commit=False`` keeps loaded attributes usable after commit."""
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
