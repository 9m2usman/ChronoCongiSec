"""Phase 6B Real-Time Event Streaming (WebSocket + SSE) fed by persisted Outbox events."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, Header, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import SecurityDependencyError
from backend.app.database.models.observability import OutboxEvent
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.realtime")

router = APIRouter(prefix="/realtime", tags=["realtime"])

_SECURITY_ROLES = frozenset({"TENANT_ADMIN", "BRANCH_ADMIN", "SECURITY_ANALYST", "AUDITOR"})
_SECURITY_PREFIXES = ("SECURITY_", "RECOVERY_", "GATEWAY_", "IAM_", "AUDIT_")


def is_event_visible_to_context(event: OutboxEvent, context: TenantContext) -> bool:
    """Enforce strict tenant, branch, role, and actor scoping for live events."""
    if event.tenant_id != context.tenant_id:
        return False

    payload = event.payload if isinstance(event.payload, dict) else {}
    event_type = str(event.event_type or "")

    # Role scoping: security/recovery/gateway/IAM events require security/admin/auditor roles
    if event_type.startswith(_SECURITY_PREFIXES) and context.role not in _SECURITY_ROLES:
        return False

    # Branch scoping: non-TENANT_ADMIN users only see events in their branch (when branch_id is present)
    ev_branch = payload.get("branch_id")
    if (
        context.role != "TENANT_ADMIN"
        and context.branch_id
        and ev_branch
        and ev_branch != context.branch_id
    ):
        return False

    # Actor-private notifications & direct messages
    if event_type.startswith("COMPANY_NOTIFICATION_") and context.role not in ("TENANT_ADMIN", "BRANCH_ADMIN"):
        target_uid = payload.get("target_user_id") or payload.get("user_id")
        if target_uid and target_uid != context.user_id:
            return False

    if event_type.startswith("COMPANY_MESSAGE_") and context.role not in ("TENANT_ADMIN", "BRANCH_ADMIN"):
        sender = payload.get("sender_user_id")
        recipient = payload.get("recipient_user_id")
        if (sender or recipient) and context.user_id not in (sender, recipient):
            return False

    return True


def _serialize_event(event: OutboxEvent) -> Dict[str, Any]:
    return {
        "id": event.id,
        "tenant_id": event.tenant_id,
        "event_type": event.event_type,
        "status": event.status,
        "payload": event.payload if isinstance(event.payload, dict) else {},
        "created_at": event.created_at.isoformat() if event.created_at else datetime.now(timezone.utc).isoformat(),
    }


async def _fetch_outbox_events(
    session_factory: Any,
    context: TenantContext,
    *,
    since_created_at: Optional[datetime] = None,
    seen_ids: Set[str],
    limit: int = 100,
) -> List[Dict[str, Any]]:
    async with session_factory() as session:
        stmt = (
            select(OutboxEvent)
            .where(OutboxEvent.tenant_id == context.tenant_id)
            .order_by(OutboxEvent.created_at.asc(), OutboxEvent.id.asc())
            .limit(limit)
        )
        if since_created_at is not None:
            stmt = stmt.where(OutboxEvent.created_at >= since_created_at)
        rows = (await session.execute(stmt)).scalars().all()

    out: List[Dict[str, Any]] = []
    for ev in rows:
        if ev.id in seen_ids:
            continue
        seen_ids.add(ev.id)
        if is_event_visible_to_context(ev, context):
            out.append(_serialize_event(ev))
    return out


@router.get("/events")
async def stream_realtime_events(
    request: Request,
    once: bool = Query(default=False),
    last_event_id_query: Optional[str] = Query(default=None, alias="last_event_id"),
    last_event_id_header: Optional[str] = Header(default=None, alias="Last-Event-ID"),
    context: TenantContext = Depends(get_tenant_context),
) -> StreamingResponse:
    """Server-Sent Events stream of tenant/branch/role-scoped Outbox events."""
    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is None:
        raise SecurityDependencyError("Real-time event store is unavailable.")

    resume_id = last_event_id_header or last_event_id_query
    seen_ids: Set[str] = set()
    since_ts: Optional[datetime] = None

    if resume_id:
        seen_ids.add(resume_id)
        async with session_factory() as session:
            anchor = (
                await session.execute(
                    select(OutboxEvent).where(
                        OutboxEvent.tenant_id == context.tenant_id,
                        OutboxEvent.id == resume_id,
                    )
                )
            ).scalar_one_or_none()
            if anchor is not None:
                since_ts = anchor.created_at

    async def _event_generator() -> AsyncIterator[str]:
        nonlocal since_ts
        while True:
            if await request.is_disconnected():
                break
            events = await _fetch_outbox_events(
                session_factory,
                context,
                since_created_at=since_ts,
                seen_ids=seen_ids,
            )
            for item in events:
                yield f"id: {item['id']}\nevent: {item['event_type']}\ndata: {json.dumps(item)}\n\n"
            if once:
                break
            yield ": keepalive\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _resolve_ws_context(websocket: WebSocket, token: Optional[str]) -> Optional[TenantContext]:
    auth_header = websocket.headers.get("authorization") or ""
    raw_token = token
    if not raw_token and auth_header.lower().startswith("bearer "):
        raw_token = auth_header[7:].strip()
    if not raw_token:
        return None
    token_service = getattr(websocket.app.state, "token_service", None)
    auth_service = getattr(websocket.app.state, "auth_service", None)
    if token_service is None:
        return None
    try:
        claims = token_service.verify_access_token(raw_token)
        if auth_service is not None and hasattr(auth_service, "resolve_context_from_claims"):
            return await auth_service.resolve_context_from_claims(claims)
        return TenantContext(
            tenant_id=claims.tenant_id,
            tenant_slug=claims.tenant_slug,
            tenant_name=claims.tenant_name,
            user_id=claims.user_id,
            role=claims.role,
            is_active=True,
            branch_id=getattr(claims, "branch_id", None),
        )
    except Exception:
        return None


@router.websocket("/ws")
async def websocket_realtime_events(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
    last_event_id: Optional[str] = Query(default=None),
) -> None:
    """Tenant/branch/role-scoped WebSocket stream fed by persisted Outbox events."""
    context = await _resolve_ws_context(websocket, token)
    if context is None:
        await websocket.close(code=4401)
        return

    session_factory = getattr(websocket.app.state, "db_session_factory", None)
    if session_factory is None:
        await websocket.close(code=1011)
        return

    await websocket.accept()
    seen_ids: Set[str] = set()
    since_ts: Optional[datetime] = None
    if last_event_id:
        seen_ids.add(last_event_id)
        async with session_factory() as session:
            anchor = (
                await session.execute(
                    select(OutboxEvent).where(
                        OutboxEvent.tenant_id == context.tenant_id,
                        OutboxEvent.id == last_event_id,
                    )
                )
            ).scalar_one_or_none()
            if anchor is not None:
                since_ts = anchor.created_at

    try:
        while True:
            events = await _fetch_outbox_events(
                session_factory,
                context,
                since_created_at=since_ts,
                seen_ids=seen_ids,
            )
            for item in events:
                await websocket.send_json(item)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return


__all__ = ["is_event_visible_to_context", "router"]
