"""Durable Phase 3 agent runtime cancellation integration (CrewAI & LangGraph).

Implements ``AgentRuntimeCancellation`` for active executions, queued jobs,
retries, and outbox tasks, persisting cancellation requests and outcomes and
verifying runtime/queue state before reporting completion.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import ForbiddenError
from backend.app.database.models.agents import Agent
from backend.app.database.models.baseline import ObservationEvent
from backend.app.database.models.observability import OutboxEvent
from backend.app.workers.outbox import (
    STATUS_DEAD_LETTER,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_PROCESSING,
)

logger = logging.getLogger("amsc.security.runtime_cancellation")

SUPPORTED_RUNTIMES = frozenset({"CREWAI", "LANGGRAPH"})


class SqlAgentRuntimeCancellationService:
    """Authoritative active/queued agent execution & cancellation coordinator."""

    is_persistent = True
    is_in_memory = False

    def __init__(
        self,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
        *,
        observation_repo: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._observation_repo = observation_repo
        self._lock = asyncio.Lock()
        # key: (tenant_id, execution_id) -> metadata dict
        self._active_executions: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # key: (tenant_id, job_id) -> metadata dict
        self._queued_jobs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # key: (tenant_id, agent_id) -> set of cancelled execution/job IDs
        self._cancelled_agents: Set[Tuple[str, str]] = set()
        self._cancelled_executions: Set[Tuple[str, str]] = set()

    @staticmethod
    def _normalize_runtime(runtime: str) -> str:
        norm = (runtime or "").strip().upper()
        if norm not in SUPPORTED_RUNTIMES:
            raise ValueError(f"Unsupported agent runtime: '{runtime}'.")
        return norm

    async def is_agent_cancelled(self, tenant_id: str, agent_id: str) -> bool:
        if (tenant_id, agent_id) in self._cancelled_agents:
            return True
        if self._session_factory is not None:
            async with self._session_factory() as session:
                agent_status = (
                    await session.execute(
                        select(Agent.status).where(
                            Agent.tenant_id == tenant_id,
                            Agent.id == agent_id,
                        )
                    )
                ).scalar_one_or_none()
                if agent_status == "ISOLATED":
                    return True
                obs = (
                    await session.execute(
                        select(ObservationEvent.id).where(
                            ObservationEvent.tenant_id == tenant_id,
                            ObservationEvent.agent_id == agent_id,
                            ObservationEvent.event_type == "AGENT_RUNTIME_CANCELLED",
                        )
                    )
                ).scalar_one_or_none()
                if obs is not None:
                    return True
        return False

    async def is_execution_cancelled(
        self,
        tenant_id: str,
        agent_id: str,
        execution_id: Optional[str] = None,
    ) -> bool:
        if execution_id and (tenant_id, execution_id) in self._cancelled_executions:
            return True
        return await self.is_agent_cancelled(tenant_id, agent_id)

    async def register_execution(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        runtime: str,
        execution_id: str,
        trace_id: Optional[str] = None,
        cancel_callback: Optional[Callable[[], Any]] = None,
    ) -> None:
        norm_runtime = self._normalize_runtime(runtime)
        if await self.is_execution_cancelled(tenant_id, agent_id, execution_id):
            raise ForbiddenError(
                f"Agent '{agent_id}' is cancelled or isolated; execution '{execution_id}' cannot start."
            )
        async with self._lock:
            if await self.is_execution_cancelled(tenant_id, agent_id, execution_id):
                raise ForbiddenError(
                    f"Agent '{agent_id}' is cancelled or isolated; execution '{execution_id}' cannot start."
                )
            self._active_executions[(tenant_id, execution_id)] = {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "runtime": norm_runtime,
                "execution_id": execution_id,
                "trace_id": trace_id,
                "status": "RUNNING",
                "cancel_callback": cancel_callback,
            }
        await self._record_obs(
            tenant_id=tenant_id,
            agent_id=agent_id,
            runtime=norm_runtime,
            execution_id=execution_id,
            trace_id=trace_id,
            event_type="AGENT_EXECUTION_STARTED",
            outcome="RUNNING",
            idempotency_key=f"exec-start:{tenant_id}:{execution_id}",
            payload={"execution_id": execution_id, "runtime": norm_runtime},
        )

    async def complete_execution(self, tenant_id: str, execution_id: str) -> None:
        async with self._lock:
            meta = self._active_executions.pop((tenant_id, execution_id), None)
        if meta is not None:
            await self._record_obs(
                tenant_id=tenant_id,
                agent_id=meta["agent_id"],
                runtime=meta["runtime"],
                execution_id=execution_id,
                trace_id=meta.get("trace_id"),
                event_type="AGENT_EXECUTION_COMPLETED",
                outcome="COMPLETED",
                idempotency_key=f"exec-done:{tenant_id}:{execution_id}",
                payload={"execution_id": execution_id, "runtime": meta["runtime"]},
            )

    async def enqueue_execution(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        runtime: str,
        job_id: str,
        payload: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> str:
        norm_runtime = self._normalize_runtime(runtime)
        if await self.is_agent_cancelled(tenant_id, agent_id):
            raise ForbiddenError(
                f"Agent '{agent_id}' is cancelled or isolated; queued job '{job_id}' refused."
            )
        job_payload = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "runtime": norm_runtime,
            "job_id": job_id,
            "trace_id": trace_id,
            "payload": dict(payload or {}),
        }
        async with self._lock:
            self._queued_jobs[(tenant_id, job_id)] = {**job_payload, "status": "QUEUED"}
        if self._session_factory is not None:
            async with self._session_factory() as session:
                session.add(
                    OutboxEvent(
                        id=job_id,
                        tenant_id=tenant_id,
                        event_type=f"AGENT_RUN_QUEUED:{norm_runtime}",
                        payload=job_payload,
                        status=STATUS_PENDING,
                        attempts=0,
                        idempotency_key=f"queue:{tenant_id}:{job_id}",
                        created_at=datetime.now(timezone.utc),
                    )
                )
                await session.commit()
        return job_id

    async def start_queued_execution(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        job_id: str,
    ) -> Dict[str, Any]:
        if await self.is_execution_cancelled(tenant_id, agent_id, job_id):
            raise ForbiddenError(
                f"Queued job '{job_id}' for agent '{agent_id}' was cancelled and cannot start."
            )
        async with self._lock:
            job = self._queued_jobs.get((tenant_id, job_id))
            if job is not None and job.get("status") == "CANCELLED":
                raise ForbiddenError(f"Queued job '{job_id}' was cancelled and cannot start.")
            if job is not None:
                job["status"] = "RUNNING"
                return dict(job)
        if self._session_factory is not None:
            async with self._session_factory() as session:
                row = (
                    await session.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.tenant_id == tenant_id,
                            OutboxEvent.id == job_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None or row.status != STATUS_PENDING:
                    raise ForbiddenError(
                        f"Queued job '{job_id}' is not runnable (status={getattr(row, 'status', 'MISSING')})."
                    )
                return dict(row.payload or {})
        raise ForbiddenError(f"Queued job '{job_id}' not found.")

    async def cancel_agent_work(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        incident_id: Optional[str],
        trace_id: Optional[str],
    ) -> Mapping[str, Any]:
        active_cancelled = 0
        queued_cancelled = 0
        outbox_cancelled = 0
        partial_failure = False
        cancelled_runtimes: List[str] = []

        async with self._lock:
            self._cancelled_agents.add((tenant_id, agent_id))

            for (t_id, exec_id), meta in list(self._active_executions.items()):
                if t_id != tenant_id or meta.get("agent_id") != agent_id:
                    continue
                self._cancelled_executions.add((tenant_id, exec_id))
                cb = meta.get("cancel_callback")
                if callable(cb):
                    try:
                        res = cb()
                        if inspect.isawaitable(res):
                            res = await res
                        if res is False:
                            partial_failure = True
                            continue
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Runtime cancel callback failed for %s: %s", exec_id, exc)
                        partial_failure = True
                        continue
                meta["status"] = "CANCELLED"
                self._active_executions.pop((t_id, exec_id), None)
                active_cancelled += 1
                cancelled_runtimes.append(str(meta.get("runtime", "UNKNOWN")))

            for (t_id, job_id), meta in list(self._queued_jobs.items()):
                if t_id != tenant_id or meta.get("agent_id") != agent_id:
                    continue
                if meta.get("status") != "CANCELLED":
                    meta["status"] = "CANCELLED"
                    self._cancelled_executions.add((tenant_id, job_id))
                    queued_cancelled += 1
                    cancelled_runtimes.append(str(meta.get("runtime", "UNKNOWN")))

        if self._session_factory is not None:
            now = datetime.now(timezone.utc)
            async with self._session_factory() as session:
                pending_rows = (
                    await session.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.tenant_id == tenant_id,
                            OutboxEvent.status.in_(
                                [STATUS_PENDING, STATUS_PROCESSING, STATUS_FAILED]
                            ),
                        )
                    )
                ).scalars().all()
                for row in pending_rows:
                    payload = row.payload or {}
                    if payload.get("agent_id") == agent_id:
                        row.status = STATUS_DEAD_LETTER
                        row.dead_lettered_at = now
                        row.next_attempt_at = None
                        row.locked_by = None
                        row.locked_at = None
                        row.locked_until = None
                        row.last_error = f"CANCELLED_BY_CONTAINMENT:{incident_id or 'SECURITY'}"
                        outbox_cancelled += 1
                        self._cancelled_executions.add((tenant_id, row.id))
                        if row.event_type.startswith("AGENT_RUN_QUEUED:"):
                            queued_cancelled += 0 if (tenant_id, row.id) in self._queued_jobs else 1
                await session.commit()

                # Verify no active/pending/retryable outbox jobs remain for this agent
                remaining_rows = (
                    await session.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.tenant_id == tenant_id,
                            OutboxEvent.status.in_(
                                [STATUS_PENDING, STATUS_PROCESSING, STATUS_FAILED]
                            ),
                        )
                    )
                ).scalars().all()
                for row in remaining_rows:
                    if (row.payload or {}).get("agent_id") == agent_id:
                        partial_failure = True

        await self._record_obs(
            tenant_id=tenant_id,
            agent_id=agent_id,
            runtime=",".join(sorted(set(cancelled_runtimes))) or "CREWAI,LANGGRAPH",
            execution_id=None,
            trace_id=trace_id,
            event_type="AGENT_RUNTIME_CANCELLED",
            outcome="RECONCILIATION_REQUIRED" if partial_failure else "CANCELLED",
            idempotency_key=f"cancel:{tenant_id}:{agent_id}:{incident_id or uuid.uuid4().hex[:12]}",
            payload={
                "incident_id": incident_id,
                "active_runs_cancelled": active_cancelled,
                "queued_jobs_cancelled": queued_cancelled,
                "outbox_jobs_cancelled": outbox_cancelled,
                "partial_failure": partial_failure,
            },
        )

        return {
            "complete": not partial_failure,
            "reconciliation_required": partial_failure,
            "active_runs_cancelled": active_cancelled,
            "queued_jobs_cancelled": queued_cancelled,
            "outbox_jobs_cancelled": outbox_cancelled,
            "runtimes": sorted(set(cancelled_runtimes)),
        }

    async def _record_obs(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        runtime: str,
        execution_id: Optional[str],
        trace_id: Optional[str],
        event_type: str,
        outcome: str,
        idempotency_key: str,
        payload: Dict[str, Any],
    ) -> None:
        event_data = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "runtime": runtime,
            "execution_id": execution_id,
            "trace_id": trace_id,
            "event_type": event_type,
            "event_category": "AGENT_EXECUTION_LIFECYCLE",
            "source_component": "AGENT_RUNTIME_CANCELLATION",
            "outcome": outcome,
            "idempotency_key": idempotency_key,
            "payload_json": payload,
        }
        if self._observation_repo is not None:
            await self._observation_repo.record_event(event_data)
        elif self._session_factory is not None:
            async with self._session_factory() as session:
                existing = (
                    await session.execute(
                        select(ObservationEvent.id).where(
                            ObservationEvent.tenant_id == tenant_id,
                            ObservationEvent.idempotency_key == idempotency_key,
                        )
                    )
                ).scalar_one_or_none()
                if existing is None:
                    session.add(
                        ObservationEvent(
                            id=f"obs-{uuid.uuid4().hex[:24]}",
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            agent_runtime=runtime,
                            execution_id=execution_id,
                            trace_id=trace_id,
                            event_type=event_type,
                            event_category="AGENT_EXECUTION_LIFECYCLE",
                            source_component="AGENT_RUNTIME_CANCELLATION",
                            outcome=outcome,
                            idempotency_key=idempotency_key,
                            payload_json=payload,
                            occurred_at=datetime.now(timezone.utc),
                        )
                    )
                    await session.commit()


__all__ = ["SqlAgentRuntimeCancellationService"]
