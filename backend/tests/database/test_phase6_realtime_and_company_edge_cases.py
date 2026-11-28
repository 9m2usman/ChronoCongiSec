"""Phase 6 verification tests for WebSocket/SSE realtime streaming and Company edge cases."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.websockets import WebSocketDisconnect

from backend.app.core.config import Settings
from backend.app.database.models.observability import OutboxEvent
from backend.app.database.seed import seed_database
from backend.app.main import create_app
from backend.tests.database import helpers

T_A = "tenant-a-uuid-001"
PASSWORD = "SecurePassword123!"
DAVE_EMAIL = "dave.developer@alphacorp.com"
SARAH_EMAIL = "sarah.admin@alphacorp.com"
SARAH_ID = "usr-admin-sarah-01"
ALEX_EMAIL = "alex.analyst@alphacorp.com"
ALEX_ID = "usr-analyst-alex-02"
BILAL_EMAIL = "bilal.dev@alphacorp.com"
BILAL_ID = "usr-dev-bilal-05"


async def _prepare_db(url: str) -> None:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            await seed_database(session)
    finally:
        await engine.dispose()


@pytest.fixture
def rt_env(migrated_db: str):
    url = helpers.sqlalchemy_url(migrated_db)
    asyncio.run(_prepare_db(url))
    settings = Settings(
        APP_ENV="development",
        DEBUG=False,
        DATABASE_URL=url,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_AUTH=False,
        RATE_LIMITER_BACKEND="in_memory",
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
        JWT_SECRET="realtime-edge-case-secret-key-32-chars",
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        yield client, url


def _login(client: TestClient, email: str) -> str:
    res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD, "tenant_slug": "alphacorp"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def test_websocket_auth_scoping_and_resume(rt_env):
    client, db_url = rt_env
    sarah_token = _login(client, SARAH_EMAIL)
    dave_token = _login(client, DAVE_EMAIL)
    sarah_headers = {"Authorization": f"Bearer {sarah_token}", "X-Tenant-ID": T_A}
    dave_headers = {"Authorization": f"Bearer {dave_token}", "X-Tenant-ID": T_A}

    # Unauthenticated WebSocket must fail closed with 4401
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/realtime/ws?token=invalid-jwt"):
            pass
    assert exc.value.code == 4401

    # Seed a company event + a security event via Outbox
    async def _seed_events():
        eng = create_async_engine(db_url, poolclass=NullPool)
        try:
            now = datetime.now(timezone.utc)
            async with AsyncSession(eng) as s:
                s.add(
                    OutboxEvent(
                        id="out-ws-sec-1",
                        tenant_id=T_A,
                        event_type="SECURITY_CONTAINMENT_EXECUTED",
                        payload={"branch_id": "branch-khi-003", "incident_id": "inc-1"},
                        status="PENDING",
                        created_at=now,
                    )
                )
                s.add(
                    OutboxEvent(
                        id="out-ws-comp-2",
                        tenant_id=T_A,
                        event_type="COMPANY_FILE_CREATED",
                        payload={"branch_id": "branch-khi-003", "file_id": "file-1"},
                        status="PENDING",
                        created_at=now + timedelta(milliseconds=10),
                    )
                )
                await s.commit()
        finally:
            await eng.dispose()

    asyncio.run(_seed_events())

    # Security admin (Sarah) receives both events over WebSocket
    with client.websocket_connect(f"/api/v1/realtime/ws?token={sarah_token}") as ws:
        ev1 = ws.receive_json()
        ev2 = ws.receive_json()
        assert {ev1["id"], ev2["id"]} == {"out-ws-sec-1", "out-ws-comp-2"}

    # Developer (Dave) only receives COMPANY_* event, never SECURITY_*
    with client.websocket_connect(f"/api/v1/realtime/ws?token={dave_token}") as ws:
        ev = ws.receive_json()
        assert ev["id"] == "out-ws-comp-2"
        assert ev["event_type"] == "COMPANY_FILE_CREATED"

    # Resume from out-ws-sec-1 yields only out-ws-comp-2
    with client.websocket_connect(
        f"/api/v1/realtime/ws?token={sarah_token}&last_event_id=out-ws-sec-1"
    ) as ws:
        ev = ws.receive_json()
        assert ev["id"] == "out-ws-comp-2"

    # SSE pagination beyond 100 events (105 events) + Last-Event-ID dedup
    async def _seed_many():
        eng = create_async_engine(db_url, poolclass=NullPool)
        try:
            base = datetime.now(timezone.utc) + timedelta(seconds=1)
            async with AsyncSession(eng) as s:
                for i in range(105):
                    s.add(
                        OutboxEvent(
                            id=f"out-bulk-{i:03d}",
                            tenant_id=T_A,
                            event_type="COMPANY_FILE_UPDATED",
                            payload={"branch_id": "branch-khi-003", "seq": i},
                            status="PENDING",
                            created_at=base + timedelta(milliseconds=i),
                        )
                    )
                await s.commit()
        finally:
            await eng.dispose()

    asyncio.run(_seed_many())

    sse_all = client.get("/api/v1/realtime/events?once=true", headers=sarah_headers)
    assert sse_all.status_code == 200
    assert "out-bulk-104" in sse_all.text

    sse_resumed = client.get(
        "/api/v1/realtime/events?once=true",
        headers={**dave_headers, "Last-Event-ID": "out-bulk-102"},
    )
    assert sse_resumed.status_code == 200
    assert "out-bulk-102" not in sse_resumed.text
    assert "out-bulk-103" in sse_resumed.text
    assert "out-bulk-104" in sse_resumed.text


def test_company_delete_restore_transfer_reject_cancel_and_mark_read(rt_env):
    client, db_url = rt_env

    async def _seed_khi_peer():
        from backend.app.core.security import hash_password
        from backend.app.database.models.identity import Membership, User

        eng = create_async_engine(db_url, poolclass=NullPool)
        try:
            async with AsyncSession(eng) as s:
                s.add(
                    User(
                        id=BILAL_ID,
                        email=BILAL_EMAIL,
                        full_name="Bilal KHI",
                        hashed_password=hash_password(PASSWORD),
                        status="ACTIVE",
                    )
                )
                await s.flush()
                s.add(
                    Membership(
                        id="mem-bilal-khi-05",
                        tenant_id=T_A,
                        user_id=BILAL_ID,
                        branch_id="branch-khi-003",
                        role="DEVELOPER",
                        status="ACTIVE",
                    )
                )
                await s.commit()
        finally:
            await eng.dispose()

    asyncio.run(_seed_khi_peer())

    dave_token = _login(client, DAVE_EMAIL)
    alex_token = _login(client, ALEX_EMAIL)
    bilal_token = _login(client, BILAL_EMAIL)
    dave_h = {"Authorization": f"Bearer {dave_token}", "X-Tenant-ID": T_A}
    alex_h = {"Authorization": f"Bearer {alex_token}", "X-Tenant-ID": T_A}
    bilal_h = {"Authorization": f"Bearer {bilal_token}", "X-Tenant-ID": T_A}

    ws = client.post(
        "/api/v1/company/workspaces",
        headers=dave_h,
        json={"name": "Edge Case Ops", "visibility": "BRANCH"},
    )
    assert ws.status_code == 201, ws.text
    ws_id = ws.json()["id"]

    f1 = client.post(
        "/api/v1/company/files",
        headers=dave_h,
        json={"workspace_id": ws_id, "name": "notes.txt", "content": "v1-content"},
    )
    assert f1.status_code == 201
    file_id = f1.json()["id"]

    f2 = client.put(
        f"/api/v1/company/files/{file_id}",
        headers=dave_h,
        json={"content": "v2-content"},
    )
    assert f2.status_code == 200
    assert f2.json()["current_version"] == 2

    # Non-owner (Alex, SECURITY_ANALYST) cannot delete Dave's file
    alex_del = client.delete(f"/api/v1/company/files/{file_id}", headers=alex_h)
    assert alex_del.status_code == 403

    # Owner deletes and restores to v1
    del_res = client.delete(f"/api/v1/company/files/{file_id}", headers=dave_h)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "DELETED"

    rest_res = client.post(
        f"/api/v1/company/files/{file_id}/restore",
        headers=dave_h,
        json={"target_version": 1},
    )
    assert rest_res.status_code == 200
    assert rest_res.json()["status"] == "ACTIVE"
    assert rest_res.json()["current_version"] == 1

    # Transfer reject & cancel (same-branch recipient Bilal can reject; sender Dave can cancel)
    tr1 = client.post(
        "/api/v1/company/transfers",
        headers=dave_h,
        json={"file_id": file_id, "recipient_user_id": BILAL_ID, "message": "please review"},
    )
    assert tr1.status_code == 201
    tr1_id = tr1.json()["id"]

    rej = client.post(f"/api/v1/company/transfers/{tr1_id}/reject", headers=bilal_h)
    assert rej.status_code == 200
    assert rej.json()["status"] == "REJECTED"

    tr2 = client.post(
        "/api/v1/company/transfers",
        headers=dave_h,
        json={"file_id": file_id, "recipient_user_id": BILAL_ID, "message": "second try"},
    )
    assert tr2.status_code == 201
    tr2_id = tr2.json()["id"]

    can = client.post(f"/api/v1/company/transfers/{tr2_id}/cancel", headers=dave_h)
    assert can.status_code == 200
    assert can.json()["status"] == "CANCELLED"

    # Message mark-read
    msg = client.post(
        "/api/v1/company/messages",
        headers=dave_h,
        json={"recipient_user_id": ALEX_ID, "subject": "Hello", "body": f"Body-{uuid.uuid4().hex[:6]}"},
    )
    assert msg.status_code == 201
    msg_id = msg.json()["id"]

    read_res = client.post(f"/api/v1/company/messages/{msg_id}/read", headers=alex_h)
    assert read_res.status_code == 200
    assert read_res.json()["status"] == "READ"
