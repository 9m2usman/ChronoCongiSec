"""Unit tests for the persistent Outbox Worker (Phase 1).

Covers all required behaviors:
- Pending event processing
- Concurrent multi-worker claiming without duplicate dispatch
- Unknown event type never marked PUBLISHED (moves to DEAD_LETTER)
- Transient handler failure retries with bounded exponential backoff
- Exhausted retries move to DEAD_LETTER
- Idempotent publishing and processing
- Tenant boundary preservation
- Graceful shutdown without losing claimed work + lifespan startup/fail-closed
- Database outage resilience without losing events
- Worker restart and resumption of pending/stale-claimed events
- No sensitive payload leakage in logs
"""

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
from typing import List

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.core.config import Settings
from backend.app.database.models.observability import OutboxEvent
from backend.app.main import create_app, lifespan
from backend.app.workers.outbox import (
    STATUS_DEAD_LETTER,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_PUBLISHED,
    OutboxProcessor,
    publish_outbox_event,
)


async def _make_sqlite_factory(db_url: str = "sqlite+aiosqlite:///:memory:"):
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(OutboxEvent.__table__.create)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return engine, factory


@pytest.mark.asyncio
async def test_pending_event_gets_processed():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-1",
                    event_type="TEST_EVENT",
                    payload={"action": "sync"},
                )
                ev_id = ev.id

        handled: List[str] = []
        processor = OutboxProcessor(session_factory, worker_id="worker-a")
        processor.register_handler("TEST_EVENT", lambda e: handled.append(e.id))

        count = await processor.process_batch()
        assert count == 1
        assert handled == [ev_id]

        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
            assert stored.status == STATUS_PUBLISHED
            assert stored.published_at is not None
            assert stored.attempts == 1
            assert stored.locked_by is None
            assert stored.locked_until is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_multiple_workers_do_not_claim_same_event(tmp_path: Path):
    db_file = tmp_path / "concurrent_outbox.db"
    engine, session_factory = await _make_sqlite_factory(f"sqlite+aiosqlite:///{db_file}")
    try:
        async with session_factory() as session:
            async with session.begin():
                for i in range(6):
                    await publish_outbox_event(
                        session=session,
                        tenant_id="tenant-conc",
                        event_type="CONCURRENT_EVENT",
                        payload={"seq": i},
                    )

        dispatched_by_a: List[str] = []
        dispatched_by_b: List[str] = []

        async def handle_a(event: OutboxEvent) -> None:
            await asyncio.sleep(0.02)
            dispatched_by_a.append(event.id)

        async def handle_b(event: OutboxEvent) -> None:
            await asyncio.sleep(0.02)
            dispatched_by_b.append(event.id)

        worker_a = OutboxProcessor(session_factory, {"CONCURRENT_EVENT": handle_a}, worker_id="worker-a")
        worker_b = OutboxProcessor(session_factory, {"CONCURRENT_EVENT": handle_b}, worker_id="worker-b")

        res_a, res_b = await asyncio.gather(
            worker_a.process_batch(limit=3),
            worker_b.process_batch(limit=3),
        )
        # Drain any remaining events if SQLite's lack of SKIP LOCKED caused one worker to skip contended rows
        rem_a, rem_b = await asyncio.gather(
            worker_a.process_batch(limit=3),
            worker_b.process_batch(limit=3),
        )
        assert (res_a + res_b + rem_a + rem_b) == 6
        assert len(dispatched_by_a) + len(dispatched_by_b) == 6
        assert set(dispatched_by_a).isdisjoint(set(dispatched_by_b))
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unknown_event_type_is_never_marked_published():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-unknown",
                    event_type="UNREGISTERED_EVENT_TYPE",
                    payload={"secret_token": "do-not-leak"},
                )
                ev_id = ev.id

        processor = OutboxProcessor(session_factory, worker_id="worker-unknown")
        count = await processor.process_batch()
        assert count == 0

        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
            assert stored.status == STATUS_DEAD_LETTER
            assert stored.published_at is None
            assert stored.dead_lettered_at is not None
            assert "No handler registered" in (stored.last_error or "")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_handler_failure_is_retried_with_bounded_backoff():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-retry",
                    event_type="FLAKY_EVENT",
                    payload={"step": 1},
                )
                ev_id = ev.id

        attempts_seen = 0

        def flaky_handler(_event: OutboxEvent) -> None:
            nonlocal attempts_seen
            attempts_seen += 1
            if attempts_seen < 2:
                raise RuntimeError("Temporary downstream timeout")

        processor = OutboxProcessor(
            session_factory,
            {"FLAKY_EVENT": flaky_handler},
            worker_id="worker-retry",
            max_attempts=4,
            backoff_base_seconds=1.0,
            backoff_max_seconds=5.0,
        )

        # First attempt fails -> FAILED with next_attempt_at in the future
        assert await processor.process_batch() == 0
        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
            assert stored.status == STATUS_FAILED
            assert stored.attempts == 1
            assert stored.next_attempt_at is not None
            assert stored.published_at is None

        # Immediately polling again should NOT claim it while backoff is active
        assert await processor.process_batch() == 0
        assert attempts_seen == 1

        # Simulate backoff elapsed
        async with session_factory() as session:
            async with session.begin():
                stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
                stored.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Second attempt succeeds -> PUBLISHED
        assert await processor.process_batch() == 1
        assert attempts_seen == 2
        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
            assert stored.status == STATUS_PUBLISHED
            assert stored.attempts == 2
            assert stored.last_error is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_exhausted_retries_result_in_dead_letter():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-dlq",
                    event_type="ALWAYS_FAIL",
                    payload={"k": "v"},
                    max_attempts=2,
                )
                ev_id = ev.id

        processor = OutboxProcessor(
            session_factory,
            {"ALWAYS_FAIL": lambda _e: (_ for _ in ()).throw(ValueError("Permanent error"))},
            worker_id="worker-dlq",
            backoff_base_seconds=0.1,
            backoff_max_seconds=0.5,
        )

        assert await processor.process_batch() == 0
        async with session_factory() as session:
            async with session.begin():
                stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
                assert stored.status == STATUS_FAILED
                assert stored.attempts == 1
                stored.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        assert await processor.process_batch() == 0
        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent).where(OutboxEvent.id == ev_id))).scalar_one()
            assert stored.status == STATUS_DEAD_LETTER
            assert stored.attempts == 2
            assert stored.dead_lettered_at is not None
            assert stored.published_at is None
            assert "ValueError: Permanent error" in (stored.last_error or "")

        # Subsequent batches ignore DEAD_LETTER events
        assert await processor.process_batch() == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_duplicate_processing_is_idempotent():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev1 = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-idem",
                    event_type="IDEMPOTENT_EVENT",
                    payload={"seq": 1},
                    idempotency_key="req-abc-123",
                )
                ev2 = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-idem",
                    event_type="IDEMPOTENT_EVENT",
                    payload={"seq": 1},
                    idempotency_key="req-abc-123",
                )
                assert ev1.id == ev2.id

        calls: List[str] = []
        processor = OutboxProcessor(
            session_factory,
            {"IDEMPOTENT_EVENT": lambda e: calls.append(e.id)},
            worker_id="worker-idem",
        )
        assert await processor.process_batch() == 1
        assert await processor.process_batch() == 0
        assert len(calls) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_tenant_boundaries_are_preserved():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                ev_a = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-alpha",
                    event_type="TENANT_EVENT",
                    payload={"tenant_marker": "alpha"},
                    idempotency_key="shared-key-1",
                )
                ev_b = await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-beta",
                    event_type="TENANT_EVENT",
                    payload={"tenant_marker": "beta"},
                    idempotency_key="shared-key-1",
                )
                assert ev_a.id != ev_b.id

        seen: List[tuple[str, str]] = []
        processor = OutboxProcessor(
            session_factory,
            {"TENANT_EVENT": lambda e: seen.append((e.tenant_id, e.payload["tenant_marker"]))},
            worker_id="worker-tenant",
        )
        assert await processor.process_batch() == 2
        assert sorted(seen) == [("tenant-alpha", "alpha"), ("tenant-beta", "beta")]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_worker_shuts_down_gracefully_without_losing_claimed_work():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-shut",
                    event_type="SLOW_EVENT",
                    payload={"idx": 1},
                )
                await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-shut",
                    event_type="SLOW_EVENT",
                    payload={"idx": 2},
                )

        processed: List[int] = []
        first_started = asyncio.Event()
        processor = OutboxProcessor(session_factory, worker_id="worker-shut")

        async def slow_handler(event: OutboxEvent) -> None:
            first_started.set()
            await asyncio.sleep(0.05)
            processed.append(event.payload["idx"])
            processor.stop()

        processor.register_handler("SLOW_EVENT", slow_handler)
        task = asyncio.create_task(processor.run_loop(poll_interval_sec=0.05))
        await first_started.wait()
        await processor.shutdown(task, timeout=2.0)

        assert processed == [1]
        async with session_factory() as session:
            rows = list(
                (
                    await session.execute(
                        select(OutboxEvent).order_by(OutboxEvent.created_at.asc())
                    )
                )
                .scalars()
                .all()
            )
            statuses = sorted(r.status for r in rows)
            # One completed, the second released back to PENDING (not stuck in PROCESSING)
            assert statuses == [STATUS_PENDING, STATUS_PUBLISHED]
            pending_row = next(r for r in rows if r.status == STATUS_PENDING)
            assert pending_row.locked_by is None
            assert pending_row.attempts == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_database_outage_does_not_silently_lose_events():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-outage",
                    event_type="RESILIENT_EVENT",
                    payload={"ok": True},
                )

        delivered: List[str] = []
        processor = OutboxProcessor(
            session_factory,
            {"RESILIENT_EVENT": lambda e: delivered.append(e.id)},
            worker_id="worker-outage",
        )

        original_process_batch = processor.process_batch
        call_count = 0

        async def flaky_db_process_batch(limit=None):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise OperationalError("SELECT 1", {}, Exception("PostgreSQL connection lost"))
            res = await original_process_batch(limit=limit)
            if res > 0:
                processor.stop()
            return res

        processor.process_batch = flaky_db_process_batch  # type: ignore[method-assign]
        await asyncio.wait_for(processor.run_loop(poll_interval_sec=0.05), timeout=3.0)

        assert len(delivered) == 1
        async with session_factory() as session:
            stored = (await session.execute(select(OutboxEvent))).scalar_one()
            assert stored.status == STATUS_PUBLISHED
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_worker_can_restart_and_resume_pending_and_stale_events(tmp_path: Path):
    db_file = tmp_path / "restart_outbox.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    # First worker lifecycle: stage one pending event and one stale PROCESSING event (simulating crash)
    engine1, factory1 = await _make_sqlite_factory(db_url)
    async with factory1() as session:
        async with session.begin():
            await publish_outbox_event(
                session=session,
                tenant_id="tenant-restart",
                event_type="RESUME_EVENT",
                payload={"kind": "pending"},
            )
            stale = await publish_outbox_event(
                session=session,
                tenant_id="tenant-restart",
                event_type="RESUME_EVENT",
                payload={"kind": "stale"},
            )
            stale.status = STATUS_PROCESSING
            stale.locked_by = "crashed-worker"
            stale.locked_at = datetime.now(timezone.utc) - timedelta(minutes=5)
            stale.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            stale.attempts = 1
    await engine1.dispose()

    # Second worker lifecycle after restart
    engine2 = create_async_engine(db_url)
    factory2 = async_sessionmaker(engine2, class_=AsyncSession, expire_on_commit=False)
    try:
        resumed: List[str] = []
        worker2 = OutboxProcessor(
            factory2,
            {"RESUME_EVENT": lambda e: resumed.append(e.payload["kind"])},
            worker_id="worker-restarted",
        )
        count = await worker2.process_batch()
        assert count == 2
        assert sorted(resumed) == ["pending", "stale"]
    finally:
        await engine2.dispose()


@pytest.mark.asyncio
async def test_logs_never_expose_sensitive_event_payload(caplog: pytest.LogCaptureFixture):
    engine, session_factory = await _make_sqlite_factory()
    secret_value = "TOP_SECRET_CREDENTIAL_998877"
    try:
        async with session_factory() as session:
            async with session.begin():
                await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-sec",
                    event_type="UNKNOWN_SECRET_EVENT",
                    payload={"api_key": secret_value},
                )

        processor = OutboxProcessor(session_factory, worker_id="worker-sec")
        with caplog.at_level(logging.DEBUG, logger="amsc.workers.outbox"):
            await processor.process_batch()

        assert secret_value not in caplog.text
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_lifespan_fails_closed_when_worker_enabled_without_db():
    settings = Settings(
        APP_ENV="development",
        OUTBOX_WORKER_ENABLED=True,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
    )
    app = create_app(settings)
    with pytest.raises(RuntimeError, match="PostgreSQL session factory is not configured"):
        async with lifespan(app):
            pass


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_outbox_worker_when_enabled():
    engine, session_factory = await _make_sqlite_factory()
    try:
        async with session_factory() as session:
            async with session.begin():
                await publish_outbox_event(
                    session=session,
                    tenant_id="tenant-life",
                    event_type="LIFE_EVENT",
                    payload={"ping": True},
                )

        processed = asyncio.Event()
        processor = OutboxProcessor(
            session_factory,
            {"LIFE_EVENT": lambda _e: processed.set()},
            worker_id="worker-lifespan",
        )
        settings = Settings(
            APP_ENV="development",
            OUTBOX_WORKER_ENABLED=True,
            OUTBOX_POLL_INTERVAL_SECONDS=0.05,
        )
        app = create_app(settings)
        app.state.db_session_factory = session_factory
        app.state.outbox_processor = processor

        async with lifespan(app):
            assert app.state.outbox_worker_task is not None
            await asyncio.wait_for(processed.wait(), timeout=2.0)

        assert app.state.outbox_worker_task is None
        assert processor._running is False
    finally:
        await engine.dispose()
