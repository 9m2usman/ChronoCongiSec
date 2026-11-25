"""PostgreSQL database integration tests for the persistent Outbox Worker.

Tests real PostgreSQL schema (migration 0016), FOR UPDATE SKIP LOCKED concurrent
claiming across sessions, retry/dead-letter transitions, and tenant isolation.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.database.models.observability import OutboxEvent
from backend.app.workers.outbox import (
    STATUS_DEAD_LETTER,
    STATUS_PUBLISHED,
    OutboxProcessor,
    publish_outbox_event,
)
from backend.tests.database import helpers

pytestmark = pytest.mark.asyncio


async def test_postgres_outbox_concurrent_skip_locked_and_tenant_isolation(module_db: str):
    """Verify two concurrent workers on real PostgreSQL never claim the same event."""
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), poolclass=NullPool)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    tenant_a = f"ten-{uuid.uuid4().hex[:8]}"
    tenant_b = f"ten-{uuid.uuid4().hex[:8]}"

    try:
        async with session_factory() as session:
            async with session.begin():
                await session.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
                    [
                        {"id": tenant_a, "name": "Tenant A", "slug": tenant_a},
                        {"id": tenant_b, "name": "Tenant B", "slug": tenant_b},
                    ],
                )
                for i in range(4):
                    await publish_outbox_event(
                        session=session,
                        tenant_id=tenant_a if i % 2 == 0 else tenant_b,
                        event_type="PG_TEST_EVENT",
                        payload={"seq": i},
                        idempotency_key=f"idem-{i // 2}",
                    )
                await publish_outbox_event(
                    session=session,
                    tenant_id=tenant_a,
                    event_type="PG_UNKNOWN_EVENT",
                    payload={"seq": 99},
                )

        seen_a: list[str] = []
        seen_b: list[str] = []

        async def handle_a(ev: OutboxEvent) -> None:
            await asyncio.sleep(0.03)
            seen_a.append(ev.id)

        async def handle_b(ev: OutboxEvent) -> None:
            await asyncio.sleep(0.03)
            seen_b.append(ev.id)

        worker_a = OutboxProcessor(session_factory, {"PG_TEST_EVENT": handle_a}, worker_id="pg-worker-a")
        worker_b = OutboxProcessor(session_factory, {"PG_TEST_EVENT": handle_b}, worker_id="pg-worker-b")

        c1, c2 = await asyncio.gather(
            worker_a.process_batch(limit=3),
            worker_b.process_batch(limit=3),
        )
        assert c1 + c2 == 4
        assert len(seen_a) + len(seen_b) == 4
        assert set(seen_a).isdisjoint(set(seen_b))

        async with session_factory() as session:
            rows = list(
                (
                    await session.execute(
                        select(OutboxEvent).where(OutboxEvent.tenant_id.in_([tenant_a, tenant_b]))
                    )
                )
                .scalars()
                .all()
            )
            published = [r for r in rows if r.status == STATUS_PUBLISHED]
            dead_lettered = [r for r in rows if r.status == STATUS_DEAD_LETTER]
            assert len(published) == 4
            assert len(dead_lettered) == 1
            assert dead_lettered[0].event_type == "PG_UNKNOWN_EVENT"
            assert dead_lettered[0].published_at is None
    finally:
        async with session_factory() as session:
            async with session.begin():
                await session.execute(
                    text("DELETE FROM outbox_events WHERE tenant_id IN (:a, :b)"),
                    {"a": tenant_a, "b": tenant_b},
                )
                await session.execute(
                    text("DELETE FROM tenants WHERE id IN (:a, :b)"),
                    {"a": tenant_a, "b": tenant_b},
                )
        await engine.dispose()
