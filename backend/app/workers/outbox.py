"""Transactional Outbox Pattern implementation and persistent background worker.

Module: backend.app.workers.outbox
Owner: M6 (Database Architect & Governance) + M1 (Platform Systems)
Spec: AMSC-DOC-002 TRD Section 14 & 16, AMSC-DOC-005 Section 3.5
"""

import asyncio
from datetime import datetime, timedelta, timezone
import inspect
import logging
import os
import signal
import socket
import sys
from typing import Any, Callable, Dict, List, Optional
import uuid

from sqlalchemy import and_, or_, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.observability import OutboxEvent

logger = logging.getLogger("amsc.workers.outbox")

EventHandler = Callable[[OutboxEvent], Any]

STATUS_PENDING = "PENDING"
STATUS_PROCESSING = "PROCESSING"
STATUS_PUBLISHED = "PUBLISHED"
STATUS_FAILED = "FAILED"
STATUS_DEAD_LETTER = "DEAD_LETTER"

_MAX_ERROR_LENGTH = 500


def _sanitize_error(exc: Exception) -> str:
    """Format an exception without newlines or unbounded length.

    Never includes event payloads.
    """
    raw = f"{type(exc).__name__}: {exc}"
    cleaned = raw.replace("\r", " ").replace("\n", " ").strip()
    if len(cleaned) > _MAX_ERROR_LENGTH:
        return cleaned[: _MAX_ERROR_LENGTH - 3] + "..."
    return cleaned


def _default_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


async def publish_outbox_event(
    session: AsyncSession,
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any],
    event_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    max_attempts: Optional[int] = None,
) -> OutboxEvent:
    """Stage an outbox event within the caller's active database transaction.

    Guarantees that business state changes and outbox events commit atomically.
    When ``idempotency_key`` is supplied, duplicate staging within the same
    tenant returns the existing event rather than creating a duplicate row.
    """
    if idempotency_key is not None:
        for pending_obj in session.new:
            if (
                isinstance(pending_obj, OutboxEvent)
                and pending_obj.tenant_id == tenant_id
                and pending_obj.idempotency_key == idempotency_key
            ):
                return pending_obj

        existing_stmt = select(OutboxEvent).where(
            OutboxEvent.tenant_id == tenant_id,
            OutboxEvent.idempotency_key == idempotency_key,
        )
        existing = (await session.execute(existing_stmt)).scalar_one_or_none()
        if existing is not None:
            return existing

    event = OutboxEvent(
        id=event_id or f"out-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        event_type=event_type,
        payload=payload,
        status=STATUS_PENDING,
        attempts=0,
        max_attempts=max_attempts,
        idempotency_key=idempotency_key,
        created_at=datetime.now(timezone.utc),
        published_at=None,
    )
    session.add(event)
    return event


class OutboxProcessor:
    """Asynchronous persistent worker processor for transactional outbox events."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        handlers: Optional[Dict[str, EventHandler]] = None,
        *,
        worker_id: Optional[str] = None,
        max_attempts: int = 5,
        backoff_base_seconds: float = 2.0,
        backoff_max_seconds: float = 300.0,
        lease_seconds: int = 60,
        batch_size: int = 50,
    ) -> None:
        self.session_factory = session_factory
        self.handlers: Dict[str, EventHandler] = dict(handlers) if handlers else {}
        self.worker_id: str = worker_id or _default_worker_id()
        self.max_attempts: int = max(1, max_attempts)
        self.backoff_base_seconds: float = max(0.1, backoff_base_seconds)
        self.backoff_max_seconds: float = max(self.backoff_base_seconds, backoff_max_seconds)
        self.lease_seconds: int = max(5, lease_seconds)
        self.batch_size: int = max(1, min(batch_size, 1000))
        self._running: bool = False
        self._stop_requested: bool = False
        self._stop_event: Optional[asyncio.Event] = None

    def register_handler(self, event_type: str, handler: EventHandler) -> None:
        """Register a callback handler for an outbox event type."""
        self.handlers[event_type] = handler

    def _compute_backoff_seconds(self, attempts: int) -> float:
        """Compute bounded exponential backoff delay for retry attempt ``attempts``."""
        exponent = max(0, attempts - 1)
        delay = self.backoff_base_seconds * (2**exponent)
        return float(min(delay, self.backoff_max_seconds))

    async def _release_claimed_events(self, events: List[OutboxEvent]) -> None:
        """Release unstarted claimed events back to PENDING/FAILED on graceful shutdown."""
        if not events:
            return
        try:
            async with self.session_factory() as session:
                async with session.begin():
                    for event in events:
                        prior_attempts = max(0, (event.attempts or 1) - 1)
                        restore_status = STATUS_PENDING if prior_attempts == 0 else STATUS_FAILED
                        stmt = (
                            update(OutboxEvent)
                            .where(
                                OutboxEvent.id == event.id,
                                OutboxEvent.tenant_id == event.tenant_id,
                                OutboxEvent.status == STATUS_PROCESSING,
                                OutboxEvent.locked_by == self.worker_id,
                            )
                            .values(
                                status=restore_status,
                                attempts=prior_attempts,
                                locked_by=None,
                                locked_at=None,
                                locked_until=None,
                            )
                        )
                        await session.execute(stmt)
            logger.info(
                "Released %d unstarted claimed outbox event(s) during shutdown (worker_id=%s).",
                len(events),
                self.worker_id,
            )
        except Exception as exc:
            logger.warning(
                "Failed to release %d claimed outbox event(s) during shutdown (worker_id=%s): %s",
                len(events),
                self.worker_id,
                _sanitize_error(exc),
            )

    async def _persist_published(self, event: OutboxEvent, now: datetime) -> bool:
        """Atomically transition a claimed event to PUBLISHED."""
        async with self.session_factory() as session:
            async with session.begin():
                stmt = (
                    update(OutboxEvent)
                    .where(
                        OutboxEvent.id == event.id,
                        OutboxEvent.tenant_id == event.tenant_id,
                        OutboxEvent.status == STATUS_PROCESSING,
                        OutboxEvent.locked_by == self.worker_id,
                        OutboxEvent.published_at.is_(None),
                    )
                    .values(
                        status=STATUS_PUBLISHED,
                        published_at=now,
                        locked_by=None,
                        locked_at=None,
                        locked_until=None,
                        next_attempt_at=None,
                        last_error=None,
                    )
                )
                result = await session.execute(stmt)
                return (result.rowcount or 0) == 1

    async def _persist_failure(
        self,
        event: OutboxEvent,
        now: datetime,
        error_message: str,
        *,
        force_dead_letter: bool = False,
    ) -> str:
        """Persist a retryable FAILED state or terminal DEAD_LETTER state."""
        effective_max = event.max_attempts if event.max_attempts is not None else self.max_attempts
        if force_dead_letter or event.attempts >= effective_max:
            new_status = STATUS_DEAD_LETTER
            values: Dict[str, Any] = {
                "status": STATUS_DEAD_LETTER,
                "dead_lettered_at": now,
                "next_attempt_at": None,
                "last_error": error_message,
                "locked_by": None,
                "locked_at": None,
                "locked_until": None,
            }
        else:
            new_status = STATUS_FAILED
            backoff = self._compute_backoff_seconds(event.attempts)
            values = {
                "status": STATUS_FAILED,
                "next_attempt_at": now + timedelta(seconds=backoff),
                "last_error": error_message,
                "locked_by": None,
                "locked_at": None,
                "locked_until": None,
            }

        async with self.session_factory() as session:
            async with session.begin():
                stmt = (
                    update(OutboxEvent)
                    .where(
                        OutboxEvent.id == event.id,
                        OutboxEvent.tenant_id == event.tenant_id,
                        OutboxEvent.status == STATUS_PROCESSING,
                        OutboxEvent.locked_by == self.worker_id,
                    )
                    .values(**values)
                )
                await session.execute(stmt)
        return new_status

    async def process_batch(self, limit: Optional[int] = None) -> int:
        """Claim and process a batch of eligible outbox events safely."""
        requested_limit = self.batch_size if limit is None else limit
        safe_limit = max(1, min(requested_limit, 1000))
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=self.lease_seconds)

        claimed_events: List[OutboxEvent] = []
        async with self.session_factory() as session:
            async with session.begin():
                stmt = (
                    select(OutboxEvent)
                    .where(
                        OutboxEvent.published_at.is_(None),
                        or_(
                            and_(
                                OutboxEvent.status == STATUS_PENDING,
                                or_(
                                    OutboxEvent.next_attempt_at.is_(None),
                                    OutboxEvent.next_attempt_at <= now,
                                ),
                            ),
                            and_(
                                OutboxEvent.status == STATUS_FAILED,
                                or_(
                                    OutboxEvent.next_attempt_at.is_(None),
                                    OutboxEvent.next_attempt_at <= now,
                                ),
                            ),
                            and_(
                                OutboxEvent.status == STATUS_PROCESSING,
                                OutboxEvent.locked_until.is_not(None),
                                OutboxEvent.locked_until <= now,
                            ),
                        ),
                    )
                    .order_by(OutboxEvent.created_at.asc())
                    .limit(safe_limit)
                    .with_for_update(skip_locked=True)
                )
                rows = list((await session.execute(stmt)).scalars().all())
                for event in rows:
                    effective_max = (
                        event.max_attempts if event.max_attempts is not None else self.max_attempts
                    )
                    current_attempts = event.attempts or 0
                    if current_attempts >= effective_max:
                        event.status = STATUS_DEAD_LETTER
                        event.dead_lettered_at = now
                        event.next_attempt_at = None
                        event.locked_by = None
                        event.locked_at = None
                        event.locked_until = None
                        event.last_error = (
                            event.last_error or "Exhausted maximum delivery attempts before claim"
                        )
                        logger.error(
                            "outbox_event_dead_lettered event_id=%s tenant_id=%s event_type=%s attempts=%d worker_id=%s",
                            event.id,
                            event.tenant_id,
                            event.event_type,
                            current_attempts,
                            self.worker_id,
                        )
                        continue

                    claim_stmt = (
                        update(OutboxEvent)
                        .where(
                            OutboxEvent.id == event.id,
                            OutboxEvent.tenant_id == event.tenant_id,
                            OutboxEvent.published_at.is_(None),
                            or_(
                                OutboxEvent.status.in_([STATUS_PENDING, STATUS_FAILED]),
                                and_(
                                    OutboxEvent.status == STATUS_PROCESSING,
                                    OutboxEvent.locked_until.is_not(None),
                                    OutboxEvent.locked_until <= now,
                                ),
                            ),
                        )
                        .values(
                            status=STATUS_PROCESSING,
                            locked_by=self.worker_id,
                            locked_at=now,
                            locked_until=lease_until,
                            attempts=current_attempts + 1,
                        )
                        .execution_options(synchronize_session=False)
                    )
                    claim_res = await session.execute(claim_stmt)
                    if (claim_res.rowcount or 0) == 1:
                        session.expunge(event)
                        event.status = STATUS_PROCESSING
                        event.locked_by = self.worker_id
                        event.locked_at = now
                        event.locked_until = lease_until
                        event.attempts = current_attempts + 1
                        claimed_events.append(event)

        if not claimed_events:
            return 0

        processed_count = 0
        for idx, event in enumerate(claimed_events):
            if self._stop_requested:
                await self._release_claimed_events(claimed_events[idx:])
                break

            try:
                handler = self.handlers.get(event.event_type) or self.handlers.get("*")
                if handler is None:
                    err_msg = f"No handler registered for event_type '{event.event_type}'"
                    await self._persist_failure(
                        event,
                        datetime.now(timezone.utc),
                        err_msg,
                        force_dead_letter=True,
                    )
                    logger.error(
                        "outbox_event_unhandled event_id=%s tenant_id=%s event_type=%s status=%s worker_id=%s",
                        event.id,
                        event.tenant_id,
                        event.event_type,
                        STATUS_DEAD_LETTER,
                        self.worker_id,
                    )
                    continue

                res = handler(event)
                if inspect.isawaitable(res):
                    await res

                persisted = await self._persist_published(event, datetime.now(timezone.utc))
                if persisted:
                    processed_count += 1
                    logger.info(
                        "outbox_event_published event_id=%s tenant_id=%s event_type=%s attempts=%d worker_id=%s",
                        event.id,
                        event.tenant_id,
                        event.event_type,
                        event.attempts,
                        self.worker_id,
                    )
                else:
                    logger.warning(
                        "outbox_event_claim_lost event_id=%s tenant_id=%s event_type=%s worker_id=%s",
                        event.id,
                        event.tenant_id,
                        event.event_type,
                        self.worker_id,
                    )
            except asyncio.CancelledError:
                await self._release_claimed_events(claimed_events[idx:])
                raise
            except Exception as exc:
                sanitized = _sanitize_error(exc)
                try:
                    outcome_status = await self._persist_failure(
                        event,
                        datetime.now(timezone.utc),
                        sanitized,
                        force_dead_letter=False,
                    )
                    logger.warning(
                        "outbox_event_failed event_id=%s tenant_id=%s event_type=%s attempts=%d status=%s error=%s worker_id=%s",
                        event.id,
                        event.tenant_id,
                        event.event_type,
                        event.attempts,
                        outcome_status,
                        sanitized,
                        self.worker_id,
                    )
                except Exception as persist_exc:
                    logger.error(
                        "outbox_outcome_persist_failed event_id=%s tenant_id=%s event_type=%s error=%s worker_id=%s",
                        event.id,
                        event.tenant_id,
                        event.event_type,
                        _sanitize_error(persist_exc),
                        self.worker_id,
                    )

        return processed_count

    async def _wait_or_stop(self, seconds: float) -> None:
        if self._stop_event is None:
            await asyncio.sleep(seconds)
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def run_loop(self, poll_interval_sec: float = 1.0) -> None:
        """Background continuous execution loop."""
        self._running = True
        self._stop_requested = False
        self._stop_event = asyncio.Event()
        logger.info(
            "Outbox processor loop started (worker_id=%s, poll_interval=%.2fs, batch_size=%d)",
            self.worker_id,
            poll_interval_sec,
            self.batch_size,
        )
        try:
            while self._running and not self._stop_requested:
                try:
                    count = await self.process_batch()
                    if count == 0 and not self._stop_requested:
                        await self._wait_or_stop(poll_interval_sec)
                except asyncio.CancelledError:
                    break
                except (SQLAlchemyError, OSError, TimeoutError) as exc:
                    logger.error(
                        "Database/transient error in outbox processing loop (worker_id=%s): %s",
                        self.worker_id,
                        _sanitize_error(exc),
                    )
                    if not self._stop_requested:
                        await self._wait_or_stop(poll_interval_sec)
                except Exception as exc:
                    logger.warning(
                        "Unexpected error in outbox processing loop (worker_id=%s): %s",
                        self.worker_id,
                        _sanitize_error(exc),
                    )
                    if not self._stop_requested:
                        await self._wait_or_stop(poll_interval_sec)
        finally:
            self._running = False
            logger.info("Outbox processor loop stopped (worker_id=%s).", self.worker_id)

    def stop(self) -> None:
        """Signal processor to stop gracefully."""
        self._running = False
        self._stop_requested = True
        if self._stop_event is not None:
            self._stop_event.set()

    async def shutdown(
        self,
        task: Optional[asyncio.Task[Any]] = None,
        timeout: float = 10.0,
    ) -> None:
        """Signal graceful stop and wait for an active worker task to drain."""
        self.stop()
        if task is None or task.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "Outbox worker task did not stop within %.1fs; cancelling (worker_id=%s).",
                timeout,
                self.worker_id,
            )
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass


PHASE1_OUTBOX_EVENT_TYPES = (
    "IAM_REGISTRATION_SUBMITTED",
    "IAM_REGISTRATION_APPROVED",
    "IAM_REGISTRATION_REJECTED",
    "AGENT_PROFILE_UPDATED",
    "TRUST_DECISION_RECORDED",
    "AUDIT_EVENT_EMITTED",
)


def register_default_outbox_handlers(
    processor: OutboxProcessor,
    on_event: Optional[Callable[[OutboxEvent], Any]] = None,
) -> None:
    """Register handlers for supported Phase 1 outbox event types.

    Unknown event types remain deliberately unregistered so they move to
    DEAD_LETTER and are never falsely reported as PUBLISHED.
    """
    async def _default_handler(event: OutboxEvent) -> None:
        logger.info(
            "outbox_handler_dispatched event_id=%s tenant_id=%s event_type=%s",
            event.id,
            event.tenant_id,
            event.event_type,
        )
        if on_event is not None:
            res = on_event(event)
            if inspect.isawaitable(res):
                await res

    for event_type in PHASE1_OUTBOX_EVENT_TYPES:
        if event_type not in processor.handlers:
            processor.register_handler(event_type, _default_handler)


async def run_worker() -> int:
    """Standalone persistent outbox worker entrypoint."""
    from backend.app.core.config import get_settings
    from backend.app.core.logging import setup_logging
    from backend.app.database.session import create_engine, create_session_factory, get_database_url

    settings = get_settings()
    setup_logging(settings.LOG_LEVEL)

    if not settings.OUTBOX_WORKER_ENABLED:
        logger.error("Outbox worker refused to start: OUTBOX_WORKER_ENABLED is False.")
        return 1

    db_url = get_database_url()
    engine = create_engine(db_url)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Outbox worker startup failed: PostgreSQL unreachable (%s).", _sanitize_error(exc))
        await engine.dispose()
        return 1

    session_factory = create_session_factory(engine)
    processor = OutboxProcessor(
        session_factory=session_factory,
        worker_id=settings.OUTBOX_WORKER_ID or None,
        max_attempts=settings.OUTBOX_MAX_ATTEMPTS,
        backoff_base_seconds=settings.OUTBOX_BACKOFF_BASE_SECONDS,
        backoff_max_seconds=settings.OUTBOX_BACKOFF_MAX_SECONDS,
        lease_seconds=settings.OUTBOX_LEASE_SECONDS,
        batch_size=settings.OUTBOX_BATCH_SIZE,
    )
    register_default_outbox_handlers(processor)

    loop = asyncio.get_running_loop()

    def _handle_signal() -> None:
        logger.info("Received shutdown signal; stopping outbox worker.")
        processor.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda _s, _f: loop.call_soon_threadsafe(_handle_signal))

    try:
        await processor.run_loop(poll_interval_sec=settings.OUTBOX_POLL_INTERVAL_SECONDS)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_worker()))
