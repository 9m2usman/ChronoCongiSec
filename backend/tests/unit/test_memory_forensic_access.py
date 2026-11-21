"""Forensic memory access through the real app (M1 route -> M4 ForensicAccess -> audit).

The M5 client used to send ``for_forensic=true`` on the normal detail route, which the backend
ignored. Per GAP-012 no route accepts a forensic flag; forensic reads use the dedicated
``POST /memory/{id}/forensic-access`` route, served only by M4's ForensicAccess (role from the
verified context, an investigation reason, audit written before the read).
"""

import httpx
import pytest

from backend.app.api.audit import InMemoryAuditRepository
from backend.tests.unit.test_incident_management import (  # noqa: F401  (pytest fixtures)
    MEM_A_SUSPICIOUS,
    TENANT_A_ID,
    USER_A_ANALYST,
    client,
    create_token_for,
    isolated_agent_repo,
    isolated_gateway_repo,
    isolated_incident_repo,
    isolated_memory_repo,
    test_settings,
)


def _auth(settings, role="SECURITY_ANALYST", user=USER_A_ANALYST):
    return {"Authorization": f"Bearer {create_token_for(user, 'u@company-a.com', TENANT_A_ID, role, settings)}"}


AUDITOR_USER = "user-a-auditor-901"


@pytest.fixture
def auditor(client, test_settings):
    """M1 resolves roles from the membership row, not the token: seed a real AUDITOR membership."""
    from backend.app.tenancy.context import MembershipRecord, UserRecord, create_demo_auth_repository
    repo = create_demo_auth_repository(test_settings)
    repo.add_user(UserRecord(id=AUDITOR_USER, email="auditor@company-a.com", hashed_password="x", full_name="Auditor"))
    repo.add_membership(MembershipRecord(id="mem-aud-901", tenant_id=TENANT_A_ID, user_id=AUDITOR_USER,
                                         role="AUDITOR", status="ACTIVE"))
    client._transport.app.state.auth_repo = repo
    return AUDITOR_USER


@pytest.fixture
def audit_repo(client):
    repo = InMemoryAuditRepository()
    repo._events.clear()                    # no seeded events: assert only what this request wrote
    client._transport.app.state.audit_repo = repo
    return repo


@pytest.mark.asyncio
async def test_normal_detail_of_non_trusted_record_is_404_even_with_a_forensic_flag(
    client: httpx.AsyncClient, test_settings,
):
    for params in ({}, {"for_forensic": "true"}):
        resp = await client.get(f"/api/v1/memory/{MEM_A_SUSPICIOUS}", params=params, headers=_auth(test_settings))
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyst_forensic_read_with_reason_is_served_and_audited_first(
    client: httpx.AsyncClient, test_settings, audit_repo,
):
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/forensic-access",
        json={"reason": "INC-001 root cause analysis"},
        headers=_auth(test_settings),
    )
    assert resp.status_code == 200
    assert resp.json()["record"]["id"] == MEM_A_SUSPICIOUS
    (event,) = audit_repo.list_events(TENANT_A_ID)
    assert event["event_type"] == "FORENSIC_MEMORY_ACCESSED" and event["resource_id"] == MEM_A_SUSPICIOUS
    assert event["actor_id"] == f"user:{USER_A_ANALYST}"


@pytest.mark.asyncio
async def test_forensic_flag_without_reason_is_refused(client: httpx.AsyncClient, test_settings, audit_repo):
    resp = await client.post(f"/api/v1/memory/{MEM_A_SUSPICIOUS}/forensic-access", json={},
                             headers=_auth(test_settings))
    assert resp.status_code in (400, 422) and audit_repo.list_events(TENANT_A_ID) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("role,user", [("AI_DEVELOPER", "user-a-dev-009"), ("AUDITOR", AUDITOR_USER)])
async def test_query_flag_is_not_authorization(client: httpx.AsyncClient, test_settings, audit_repo, auditor,
                                               role, user):
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/forensic-access",
        json={"reason": "curious about this record"},
        headers=_auth(test_settings, role=role, user=user),
    )
    assert resp.status_code == 403 and audit_repo.list_events(TENANT_A_ID) == []


@pytest.mark.asyncio
async def test_audit_failure_refuses_forensic_read(client: httpx.AsyncClient, test_settings, audit_repo):
    def broken(_event):
        raise RuntimeError("audit store down")

    audit_repo.append_event = broken
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/forensic-access",
        json={"reason": "INC-001 root cause analysis"},
        headers=_auth(test_settings),
    )
    assert resp.status_code == 503 and MEM_A_SUSPICIOUS not in resp.text


# ---------------------------------------------------------------------------
# Audit API (Doc 05: AUDITOR + security operators; no fabricated or non-durable evidence)
# ---------------------------------------------------------------------------

def test_dev_audit_store_has_no_fabricated_events():
    assert InMemoryAuditRepository().list_events(TENANT_A_ID) == []


@pytest.mark.asyncio
async def test_forensic_access_event_is_visible_to_auditor(client: httpx.AsyncClient, test_settings, audit_repo,
                                                           auditor):
    await client.post(f"/api/v1/memory/{MEM_A_SUSPICIOUS}/forensic-access",
                      json={"reason": "INC-001 root cause analysis"}, headers=_auth(test_settings))
    resp = await client.get("/api/v1/audit/events", headers=_auth(test_settings, role="AUDITOR", user=auditor))
    assert resp.status_code == 200
    assert [e["event_type"] for e in resp.json()] == ["FORENSIC_MEMORY_ACCESSED"]


@pytest.mark.asyncio
async def test_ai_developer_cannot_read_audit_log(client: httpx.AsyncClient, test_settings, audit_repo):
    resp = await client.get("/api/v1/audit/events", headers=_auth(test_settings, role="AI_DEVELOPER", user="user-a-dev-009"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_production_without_database_refuses_to_serve_audit(client: httpx.AsyncClient, test_settings, audit_repo):
    from types import SimpleNamespace
    app = client._transport.app
    original = app.state.settings
    app.state.settings = SimpleNamespace(**{**original.__dict__, "APP_ENV": "production"}) if hasattr(original, "__dict__") else original
    try:
        resp = await client.get("/api/v1/audit/events", headers=_auth(test_settings))
    finally:
        app.state.settings = original
    assert resp.status_code == 503
