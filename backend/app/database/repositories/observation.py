"""Observation and Telemetry Repository Layer (Phase 1 §3 & §4).

Provides durable, tenant-isolated persistence for structured observation events
across all 10 Phase 1 categories, with duplicate protection and idempotency handling.
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
import uuid

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.baseline import ObservationEvent as OrmObservationEvent

logger = logging.getLogger("amsc.repository.observation")


@runtime_checkable
class ObservationRepositoryProtocol(Protocol):
    """Protocol for observation events repository."""

    is_persistent: bool
    is_in_memory: bool

    async def record_event(
        self,
        event_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Persist observation event with idempotent deduplication."""
        ...

    async def get_event(
        self,
        tenant_id: str,
        event_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch single event by ID and tenant."""
        ...

    async def list_events(
        self,
        tenant_id: str,
        event_category: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Query correlated events with pagination."""
        ...


class InMemoryObservationRepository(ObservationRepositoryProtocol):
    """Thread-safe in-memory observation event store for dev and test."""

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        # key: event_id -> event dict
        self._events: Dict[str, Dict[str, Any]] = {}
        # key: (tenant_id, idempotency_key) -> event_id (for deduplication)
        self._idempotency_map: Dict[Tuple[str, str], str] = {}

    async def record_event(
        self,
        event_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        tenant_id = event_dict["tenant_id"]
        idemp_key = event_dict.get("idempotency_key")

        # Idempotency / Duplicate protection check (Phase 1 §4)
        if idemp_key:
            lookup_key = (tenant_id, idemp_key)
            if lookup_key in self._idempotency_map:
                existing_id = self._idempotency_map[lookup_key]
                logger.info(
                    "Duplicate observation event detected with idempotency key '%s'. Returning existing event.",
                    idemp_key,
                )
                return deepcopy(self._events[existing_id])

        event_id = event_dict.get("id") or f"obs-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        clean_event = deepcopy(event_dict)
        clean_event["id"] = event_id
        if "payload" not in clean_event:
            clean_event["payload"] = clean_event.get("payload_json", {})
        if "occurred_at" not in clean_event or not clean_event["occurred_at"]:
            clean_event["occurred_at"] = now.isoformat()
        if "created_at" not in clean_event or not clean_event["created_at"]:
            clean_event["created_at"] = clean_event["occurred_at"]

        self._events[event_id] = clean_event
        if idemp_key:
            self._idempotency_map[(tenant_id, idemp_key)] = event_id

        return deepcopy(clean_event)

    async def get_event(
        self,
        tenant_id: str,
        event_id: str,
    ) -> Optional[Dict[str, Any]]:
        ev = self._events.get(event_id)
        if ev and ev.get("tenant_id") == tenant_id:
            return deepcopy(ev)
        return None

    async def list_events(
        self,
        tenant_id: str,
        event_category: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        matched = [
            e for e in self._events.values()
            if e.get("tenant_id") == tenant_id
        ]
        if event_category:
            matched = [e for e in matched if e.get("event_category") == event_category]
        if event_type:
            matched = [e for e in matched if e.get("event_type") == event_type]
        if agent_id:
            matched = [e for e in matched if e.get("agent_id") == agent_id]
        if trace_id:
            matched = [e for e in matched if e.get("trace_id") == trace_id]
        if branch_id:
            matched = [e for e in matched if e.get("branch_id") == branch_id or e.get("branch_id") is None]

        # Order by occurred_at descending
        matched.sort(key=lambda x: (x.get("occurred_at", ""), x.get("id", "")), reverse=True)
        total = len(matched)
        page = matched[offset : offset + limit]
        has_more = (offset + limit) < total

        return [deepcopy(e) for e in page], has_more


class SqlAlchemyObservationRepository(ObservationRepositoryProtocol):
    """PostgreSQL durable repository for observation events."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def record_event(
        self,
        event_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        tenant_id = event_dict["tenant_id"]
        idemp_key = event_dict.get("idempotency_key")
        event_id = event_dict.get("id") or f"obs-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        raw_occurred = event_dict.get("occurred_at") or event_dict.get("created_at")
        if isinstance(raw_occurred, datetime):
            occurred_dt = raw_occurred
        elif isinstance(raw_occurred, str) and raw_occurred:
            try:
                occurred_dt = datetime.fromisoformat(raw_occurred)
            except Exception:
                occurred_dt = now
        else:
            occurred_dt = now

        async with self.session_factory() as session:
            try:
                async with session.begin():
                    # Check for existing idempotency key within active transaction
                    if idemp_key:
                        stmt_lookup = select(OrmObservationEvent).where(
                            OrmObservationEvent.tenant_id == tenant_id,
                            OrmObservationEvent.idempotency_key == idemp_key,
                        )
                        existing = (await session.execute(stmt_lookup)).scalar_one_or_none()
                        if existing:
                            return self._orm_to_dict(existing)

                    orm_event = OrmObservationEvent(
                        id=event_id,
                        tenant_id=tenant_id,
                        branch_id=event_dict.get("branch_id"),
                        event_type=event_dict.get("event_type", "UNKNOWN"),
                        event_category=event_dict.get("event_category", "UNKNOWN"),
                        agent_id=event_dict.get("agent_id"),
                        agent_runtime=event_dict.get("agent_runtime"),
                        execution_id=event_dict.get("execution_id"),
                        trace_id=event_dict.get("trace_id"),
                        parent_span_id=event_dict.get("parent_span_id"),
                        source_component=event_dict.get("source_component", "GATEWAY"),
                        related_memory_id=event_dict.get("related_memory_id"),
                        related_memory_version=event_dict.get("related_memory_version"),
                        tool_name=event_dict.get("tool_name"),
                        action_id=event_dict.get("action_id"),
                        policy_decision_id=event_dict.get("policy_decision_id"),
                        execution_receipt_id=event_dict.get("execution_receipt_id"),
                        baseline_version=event_dict.get("baseline_version"),
                        outcome=event_dict.get("outcome", "SUCCESS"),
                        idempotency_key=idemp_key,
                        payload_json=event_dict.get("payload_json") or event_dict.get("payload") or {},
                        occurred_at=occurred_dt,
                    )
                    session.add(orm_event)
                    event_result = self._orm_to_dict(orm_event)
            except IntegrityError:
                if idemp_key:
                    async with self.session_factory() as retry_session:
                        stmt_lookup = select(OrmObservationEvent).where(
                            OrmObservationEvent.tenant_id == tenant_id,
                            OrmObservationEvent.idempotency_key == idemp_key,
                        )
                        existing = (await retry_session.execute(stmt_lookup)).scalar_one_or_none()
                        if existing:
                            return self._orm_to_dict(existing)
                raise

        return event_result

    async def get_event(
        self,
        tenant_id: str,
        event_id: str,
    ) -> Optional[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmObservationEvent).where(
                OrmObservationEvent.tenant_id == tenant_id,
                OrmObservationEvent.id == event_id,
            )
            r = (await session.execute(stmt)).scalar_one_or_none()
            return self._orm_to_dict(r) if r else None

    async def list_events(
        self,
        tenant_id: str,
        event_category: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        async with self.session_factory() as session:
            stmt = select(OrmObservationEvent).where(OrmObservationEvent.tenant_id == tenant_id)
            if event_category:
                stmt = stmt.where(OrmObservationEvent.event_category == event_category)
            if event_type:
                stmt = stmt.where(OrmObservationEvent.event_type == event_type)
            if agent_id:
                stmt = stmt.where(OrmObservationEvent.agent_id == agent_id)
            if trace_id:
                stmt = stmt.where(OrmObservationEvent.trace_id == trace_id)
            if branch_id:
                stmt = stmt.where(
                    (OrmObservationEvent.branch_id == branch_id) | (OrmObservationEvent.branch_id.is_(None))
                )

            stmt = (
                stmt.order_by(desc(OrmObservationEvent.occurred_at), desc(OrmObservationEvent.id))
                .limit(limit + 1)
                .offset(offset)
            )
            rows = list((await session.execute(stmt)).scalars().all())
            has_more = len(rows) > limit
            page = rows[:limit]
            return [self._orm_to_dict(r) for r in page], has_more

    def _orm_to_dict(self, r: OrmObservationEvent) -> Dict[str, Any]:
        occurred_iso = r.occurred_at.isoformat() if r.occurred_at else None
        return {
            "id": r.id,
            "tenant_id": r.tenant_id,
            "branch_id": r.branch_id,
            "event_type": r.event_type,
            "event_category": r.event_category,
            "agent_id": r.agent_id,
            "agent_runtime": r.agent_runtime,
            "execution_id": r.execution_id,
            "trace_id": r.trace_id,
            "parent_span_id": r.parent_span_id,
            "source_component": r.source_component,
            "related_memory_id": r.related_memory_id,
            "related_memory_version": r.related_memory_version,
            "tool_name": r.tool_name,
            "action_id": r.action_id,
            "policy_decision_id": r.policy_decision_id,
            "execution_receipt_id": r.execution_receipt_id,
            "baseline_version": r.baseline_version,
            "outcome": r.outcome,
            "idempotency_key": r.idempotency_key,
            "payload": r.payload_json,
            "occurred_at": occurred_iso,
            "created_at": occurred_iso,
        }
