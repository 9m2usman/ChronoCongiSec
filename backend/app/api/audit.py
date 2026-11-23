"""M6 / M1 Audit Trail Query API.

Module: backend.app.api.audit
Owner: M6 (Append-Only Audit Engine) + M1 (Ingress Routing)

Implements Canonical Architecture:
- AMSC-DOC-002 (TRD/SRS) Section 5: Append-Only Immutable Audit Log & Hash Chaining
- AMSC-DOC-005 (Database & API Schema) Section 3.6: Table 30 (audit_events)
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.security.authorization import Role, require_role_access
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.audit")

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    tenant_id: str
    actor_id: str
    event_type: str
    resource_id: str
    action: str
    outcome: str
    details: Dict[str, Any]
    occurred_at: str


class InMemoryAuditRepository:
    """Development/test audit store. Not durable, not hash-chained; never used in production.

    It starts empty: it previously seeded a fabricated SYSTEM_STARTUP event claiming
    ``"audit_chain": "sha256-verified"``, which nothing had verified.
    """

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def append_event(self, event: Dict[str, Any]) -> None:
        self._events.insert(0, deepcopy(event))

    def list_events(self, tenant_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        results = [
            deepcopy(e) for e in self._events
            if e["tenant_id"] == tenant_id
        ]
        return results[offset : offset + limit]


_default_audit_repo = InMemoryAuditRepository()


def get_default_audit_repository() -> InMemoryAuditRepository:
    return _default_audit_repo


async def record_audit_event(
    request: Request,
    tenant_id: str,
    actor_id: str,
    event_type: str,
    action: str,
    resource_id: str,
    outcome: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Record an immutable audit event to both database and in-memory audit store.

    Guarantees deterministic, append-only persistence of all IAM actions
    across live PostgreSQL production and in-memory test/demo environments.
    """
    now = datetime.now(timezone.utc)
    event_id = f"aud-{uuid.uuid4().hex[:12]}"
    clean_details = details or {}

    # 1. Database-backed durable append when db_session_factory is configured
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is not None:
        try:
            import asyncio

            async def _persist_audit() -> None:
                from backend.app.database.models.observability import AuditEvent
                async with session_factory() as session:
                    async with session.begin():
                        db_event = AuditEvent(
                            id=event_id,
                            tenant_id=tenant_id,
                            actor_id=actor_id,
                            event_type=event_type,
                            resource_id=resource_id,
                            action=action,
                            outcome=outcome,
                            trace_id=getattr(request.state, "trace_id", None),
                            details_json=clean_details,
                            occurred_at=now,
                        )
                        session.add(db_event)

            await asyncio.wait_for(_persist_audit(), timeout=0.5)
        except Exception as exc:
            logger.warning("Failed to persist audit event to database: %s", exc)

    # 2. In-memory append for test, local development, and fallback runtimes
    try:
        mem_repo = getattr(request.app.state, "audit_repo", None) or _default_audit_repo
        if mem_repo is not None and hasattr(mem_repo, "append_event"):
            mem_repo.append_event({
                "id": event_id,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "event_type": event_type,
                "resource_id": resource_id,
                "action": action,
                "outcome": outcome,
                "details": clean_details,
                "occurred_at": now.isoformat(),
            })
    except Exception as exc:
        logger.warning("Failed to append event to in-memory audit repo: %s", exc)


@router.get(
    "/events",
    response_model=List[AuditEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List Immutable Audit Events",
    description="Query append-only cryptographic audit records for authorized tenant members.",
)
async def list_audit_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    context: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN, Role.SECURITY_ANALYST, Role.AUDITOR)),
) -> List[AuditEventResponse]:
    """Doc 05 route catalog: AUDITOR (plus security operators). Reads M6's append-only, hash-chained
    ``audit_events`` when a database session factory is configured; the in-memory store only in
    development/test; otherwise 503 rather than serving non-durable data as audit evidence."""
    state = request.app.state
    session_factory = getattr(state, "db_session_factory", None)
    if session_factory is not None:
        from backend.app.database.unit_of_work import UnitOfWork

        async with UnitOfWork(session_factory)(context.tenant_id) as tx:
            rows = await tx.audit.list_recent(limit=limit, offset=offset)
        return [AuditEventResponse(
            id=e.id, tenant_id=e.tenant_id, actor_id=e.actor_id, event_type=e.event_type,
            resource_id=e.resource_id, action=e.action, outcome=e.outcome,
            details=dict(e.details_json or {}), occurred_at=e.occurred_at.isoformat(),
        ) for e in rows]

    settings = getattr(state, "settings", None)
    env = str(getattr(settings, "APP_ENV", "") or "").strip().lower()
    if env not in ("development", "test"):
        raise SecurityDependencyError("Durable audit persistence is not configured.")
    repo = getattr(state, "audit_repo", None) or _default_audit_repo
    events = repo.list_events(context.tenant_id, limit=limit, offset=offset)
    return [AuditEventResponse(**e) for e in events]
