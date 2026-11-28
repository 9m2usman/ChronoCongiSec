"""Phase 6B Real-Time Event Streaming (WebSocket + SSE) fed by persisted Outbox events."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, or_, select

from backend.app.core.config import get_settings
from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import SecurityDependencyError
from backend.app.database.models.observability import OutboxEvent
from backend.app.tenancy.context import (
    TenantContext,
    decode_access_token,
    get_default_auth_repository,
)

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


async def _resolve_anchor_cursor(
    session_factory: Any,
    tenant_id: str,
    resume_id: Optional[str],
) -> Tuple[Optional[datetime], Optional[str]]:
    if not resume_id:
        return None, None
    async with session_factory() as session:
        anchor = (
            await session.execute(
                select(OutboxEvent).where(
                    OutboxEvent.tenant_id == tenant_id,
                    OutboxEvent.id == resume_id,
                )
            )
        ).scalar_one_or_none()
        if anchor is not None:
            return anchor.created_at, anchor.id
    return None, None


async def _fetch_outbox_events(
    session_factory: Any,
    context: TenantContext,
    *,
    last_created_at: Optional[datetime] = None,
    last_event_id: Optional[str] = None,
    limit: int = 100,
) -> Tuple[List[Dict[str, Any]], Optional[datetime], Optional[str]]:
    async with session_factory() as session:
        stmt = (
            select(OutboxEvent)
            .where(OutboxEvent.tenant_id == context.tenant_id)
            .order_by(OutboxEvent.created_at.asc(), OutboxEvent.id.asc())
            .limit(limit)
        )
        if last_created_at is not None:
            if last_event_id is not None:
                stmt = stmt.where(
                    or_(
                        OutboxEvent.created_at > last_created_at,
                        and_(
                            OutboxEvent.created_at == last_created_at,
                            OutboxEvent.id > last_event_id,
                        ),
                    )
                )
            else:
                stmt = stmt.where(OutboxEvent.created_at > last_created_at)
        rows = (await session.execute(stmt)).scalars().all()

    out: List[Dict[str, Any]] = []
    next_ts = last_created_at
    next_id = last_event_id
    for ev in rows:
        next_ts = ev.created_at
        next_id = ev.id
        if is_event_visible_to_context(ev, context):
            out.append(_serialize_event(ev))
    return out, next_ts, next_id


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
    last_ts, last_id = await _resolve_anchor_cursor(session_factory, context.tenant_id, resume_id)

    async def _event_generator() -> AsyncIterator[str]:
        nonlocal last_ts, last_id
        while True:
            if await request.is_disconnected():
                break
            while True:
                events, next_ts, next_id = await _fetch_outbox_events(
                    session_factory,
                    context,
                    last_created_at=last_ts,
                    last_event_id=last_id,
                )
                advanced = (next_ts != last_ts) or (next_id != last_id)
                last_ts, last_id = next_ts, next_id
                for item in events:
                    yield f"id: {item['id']}\nevent: {item['event_type']}\ndata: {json.dumps(item)}\n\n"
                if not advanced:
                    break
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

    app_settings = getattr(websocket.app.state, "settings", None) or get_settings()
    try:
        payload = decode_access_token(raw_token, settings=app_settings)
        user_id = payload.get("sub")
        token_tenant_id = payload.get("tenant_id")
        if not user_id or not token_tenant_id:
            return None

        revocation_store = getattr(websocket.app.state, "revocation_store", None)
        if revocation_store is not None:
            jti = payload.get("jti")
            iat = payload.get("iat", 0)
            if jti and await revocation_store.is_token_revoked(jti):
                return None
            if await revocation_store.is_user_revoked(user_id, token_tenant_id, iat):
                return None

        repository = getattr(websocket.app.state, "auth_repo", None)
        if repository is None:
            session_factory = getattr(websocket.app.state, "db_session_factory", None)
            if session_factory is not None and (
                app_settings.AUTH_BACKEND == "database"
                or app_settings.APP_ENV == "production"
                or not app_settings.ALLOW_IN_MEMORY_AUTH
            ):
                from backend.app.database.repositories.auth import DatabaseAuthRepository
                repository = DatabaseAuthRepository(session_factory)
                websocket.app.state.auth_repo = repository
            elif app_settings.APP_ENV != "production" and app_settings.ALLOW_IN_MEMORY_AUTH:
                repository = get_default_auth_repository(app_settings)
            else:
                return None

        user = await repository.get_user_by_id(user_id)
        if not user or user.status != "ACTIVE":
            return None
        tenant = await repository.get_tenant_by_id(token_tenant_id)
        if not tenant or tenant.status != "ACTIVE":
            return None
        membership = await repository.get_membership(user_id, token_tenant_id)
        if not membership or membership.status != "ACTIVE":
            return None

        branch_id = getattr(membership, "branch_id", None)
        if branch_id is not None:
            branch_id = str(branch_id).strip() or None

        return TenantContext(
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            tenant_name=tenant.name,
            user_id=user.id,
            role=membership.role,
            is_active=True,
            branch_id=branch_id,
        )
    except Exception as exc:
        logger.warning("WebSocket auth failed: %s", type(exc).__name__)
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
    last_ts, last_id = await _resolve_anchor_cursor(session_factory, context.tenant_id, last_event_id)

    try:
        while True:
            while True:
                events, next_ts, next_id = await _fetch_outbox_events(
                    session_factory,
                    context,
                    last_created_at=last_ts,
                    last_event_id=last_id,
                )
                advanced = (next_ts != last_ts) or (next_id != last_id)
                last_ts, last_id = next_ts, next_id
                for item in events:
                    await websocket.send_json(item)
                if not advanced:
                    break
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return


__all__ = ["is_event_visible_to_context", "router"]
