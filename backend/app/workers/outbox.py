"""Transactional Outbox Pattern implementation for reliable asynchronous event delivery.

Module: backend.app.workers.outbox
Owner: M6 (Database Architect & Governance) + M1 (Platform Systems)
Spec: AMSC-DOC-002 TRD Section 14 & 16, AMSC-DOC-005 Section 3.5
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, List, Optional
import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.observability import OutboxEvent

logger = logging.getLogger("amsc.workers.outbox")

EventHandler = Callable[[OutboxEvent], Any]


async def publish_outbox_event(
    session: AsyncSession,
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any],
    event_id: Optional[str] = None,
) -> OutboxEvent:
    """Stage an outbox event within the caller's active database transaction.

    Guarantees that business state changes and outbox events commit atomically.
    """
    event = OutboxEvent(
        id=event_id or f"out-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        event_type=event_type,
        payload=payload,
        status="PENDING",
        created_at=datetime.now(timezone.utc),
        published_at=None,
    )
    session.add(event)
    return event


class OutboxProcessor:
    """Asynchronous worker processor for transactional outbox events."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        handlers: Optional[Dict[str, EventHandler]] = None,
    ) -> None:
        self.session_factory = session_factory
        self.handlers: Dict[str, EventHandler] = handlers or {}
        self._running: bool = False

    def register_handler(self, event_type: str, handler: EventHandler) -> None:
        """Register a callback handler for an outbox event type."""
        self.handlers[event_type] = handler

    async def process_batch(self, limit: int = 50) -> int:
        """Process a batch of pending outbox events using pessimistic locking."""
        safe_limit = max(1, min(limit, 1000))
        processed_count = 0
        async with self.session_factory() as session:
            async with session.begin():
                # Select pending events with skip_locked to prevent worker race conditions
                stmt = (
                    select(OutboxEvent)
                    .where(OutboxEvent.status == "PENDING")
                    .order_by(OutboxEvent.created_at.asc())
                    .limit(safe_limit)
                    .with_for_update(skip_locked=True)
                )
                events = list((await session.execute(stmt)).scalars().all())

                for event in events:
                    try:
                        handler = self.handlers.get(event.event_type) or self.handlers.get("*")
                        if handler is not None:
                            res = handler(event)
                            if asyncio.iscoroutine(res):
                                await res
                        else:
                            logger.info(
                                "No specific handler registered for outbox event '%s' (type: %s); marking PUBLISHED.",
                                event.id,
                                event.event_type,
                            )

                        event.status = "PUBLISHED"
                        event.published_at = datetime.now(timezone.utc)
                        processed_count += 1
                    except Exception as exc:
                        logger.error(
                            "Failed to process outbox event '%s' (%s): %s",
                            event.id,
                            event.event_type,
                            exc,
                        )
                        event.status = "FAILED"

        return processed_count

    async def run_loop(self, poll_interval_sec: float = 1.0) -> None:
        """Background continuous execution loop."""
        self._running = True
        logger.info("Outbox processor loop started (poll interval: %.2fs)", poll_interval_sec)
        while self._running:
            try:
                count = await self.process_batch()
                if count == 0:
                    await asyncio.sleep(poll_interval_sec)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Error in outbox processing loop: %s", exc)
                await asyncio.sleep(poll_interval_sec)
        logger.info("Outbox processor loop stopped.")

    def stop(self) -> None:
        """Signal processor to stop."""
        self._running = False
