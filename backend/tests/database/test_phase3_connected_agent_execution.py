"""Phase 3 end-to-end: agents -> Gateway -> M4 -> company adapter -> PostgreSQL.

Every test drives the real FastAPI application against a throwaway PostgreSQL
database migrated to head and seeded with the canonical seed. Proposals are
authenticated with real employee logins (JWT) and evaluated by the real M4
policy engine and guard. Assertions read the persisted company rows and the
gateway's decision / execution / audit evidence back from the database. No
response, decision or adapter is mocked.

Principals (canonical seed + Phase 3 test setup):
* Dave (usr-dev-dave-03, AI_DEVELOPER, Karachi branch-khi-003) drives agents.
* agent-crew-branch-004 is governed for branch-khi-003 (granted all company ops).
* agent-crew-coord-005 is governed for branch-ho-001 (granted coordination ops).
* Hina (usr-dev-hina-06, AI_DEVELOPER, Head Office) is added for cross-branch cases.
* Kamran (usr-khi-ops-05, Karachi) is a colleague who receives work.
* Tenant B has its own employee, agent, workspace and file for cross-tenant cases.

Requires ``TEST_DATABASE_URL`` (see ``helpers.py``); fails without it, like every
other M6 database test.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.adapters.contracts import ActionProposal, LangGraphAdapterContract
from backend.app.core.config import Settings
from backend.app.core.security import hash_password
from backend.app.database.models.agents import Agent, AgentToolPermission, ToolRegistration
from backend.app.database.models.baseline import AgentSecurityProfile
from backend.app.database.models.company import (
    CompanyFile,
    CompanyFileVersion,
    CompanyMessage,
    CompanyWorkspace,
)
from backend.app.database.models.identity import Branch, Membership, User
from backend.app.database.seed import seed_database
from backend.app.database.session import create_session_factory
from backend.app.main import create_app
from backend.app.security import policy as policy_mod
from backend.tests.database import helpers

T_A, T_B = "tenant-a-uuid-001", "tenant-b-uuid-002"
PASSWORD = "SecurePassword123!"
DAVE, HINA, KAMRAN, SARAH = "usr-dev-dave-03", "usr-dev-hina-06", "usr-khi-ops-05", "usr-admin-sarah-01"
DAVE_EMAIL, HINA_EMAIL = "dave.developer@alphacorp.com", "hina.developer@alphacorp.com"
BRANCH_AGENT, COORD_AGENT, HR_AGENT = "agent-crew-branch-004", "agent-crew-coord-005", "agent-crew-hr-002"
TB_AGENT = "agent-tb-ops-001"
KHI, HO = "branch-khi-003", "branch-ho-001"
WS_KHI, WS_HO, WS_TB = "ws-p3-khi-001", "ws-p3-ho-001", "ws-p3-tb-001"
FILE_KHI, FILE_HO, FILE_TB = "file-p3-khi-001", "file-p3-ho-001", "file-p3-tb-001"
TOOL = "company_workspace"


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


async def _prepare(url: str) -> None:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            await seed_database(session)
        now = datetime.now(timezone.utc)
        pw = hash_password(PASSWORD)
        async with AsyncSession(engine, expire_on_commit=False) as session:
            async with session.begin():
                session.add_all([
                    User(id=HINA, email=HINA_EMAIL, full_name="Hina Developer", hashed_password=pw,
                         status="ACTIVE", created_at=now),
                    User(id=KAMRAN, email="kamran.ops@alphacorp.com", full_name="Kamran Ops",
                         hashed_password=pw, status="ACTIVE", created_at=now),
                    User(id="usr-tb-dev-07", email="dev@betashield.example", full_name="Beta Dev",
                         hashed_password=pw, status="ACTIVE", created_at=now),
                    Branch(id="branch-tb-001", tenant_id=T_B, name="Beta HQ", code="BHQ",
                           status="ACTIVE", created_at=now),
                ])
                await session.flush()
                session.add_all([
                    Membership(id="mem-p3-hina", user_id=HINA, tenant_id=T_A, role="AI_DEVELOPER",
                               status="ACTIVE", branch_id=HO, created_at=now),
                    Membership(id="mem-p3-kamran", user_id=KAMRAN, tenant_id=T_A, role="SECURITY_ANALYST",
                               status="ACTIVE", branch_id=KHI, created_at=now),
                    Membership(id="mem-p3-tb-dev", user_id="usr-tb-dev-07", tenant_id=T_B, role="AI_DEVELOPER",
                               status="ACTIVE", branch_id="branch-tb-001", created_at=now),
                    Agent(id=TB_AGENT, tenant_id=T_B, name="Beta Ops", runtime="CREWAI", model="m",
                          status="ACTIVE", config_version="v1", system_prompt="Beta ops agent",
                          created_at=now, updated_at=now),
                ])
                await session.flush()
                session.add_all([
                    AgentSecurityProfile(
                        id="profile-p3-tb", tenant_id=T_B, agent_id=TB_AGENT, owner_department="Ops",
                        approved_purpose="Beta operations", approved_goals_json=["ops"],
                        branch_id="branch-tb-001", data_scope_json=["branch:branch-tb-001:*"],
                        operational_restrictions_json={}, approval_requirements_json={},
                        profile_version="v1.0.0", status="ACTIVE", governed_by_user_id="usr-tb-dev-07",
                        created_at=now, updated_at=now),
                    ToolRegistration(id="tool-p3-tb-company", tenant_id=T_B, name=TOOL, adapter_type="INTERNAL",
                                     description="company", is_protected=True, schema_definition={},
                                     created_at=now),
                    CompanyWorkspace(id=WS_KHI, tenant_id=T_A, branch_id=KHI, owner_user_id=DAVE,
                                     name="Karachi Logistics", visibility="BRANCH"),
                    CompanyWorkspace(id=WS_HO, tenant_id=T_A, branch_id=HO, owner_user_id=HINA,
                                     name="Head Office Board Papers", visibility="BRANCH"),
                    CompanyWorkspace(id=WS_TB, tenant_id=T_B, branch_id="branch-tb-001",
                                     owner_user_id="usr-tb-dev-07", name="Beta Secrets", visibility="BRANCH"),
                ])
                await session.flush()
                session.add_all([
                    AgentToolPermission(id="perm-p3-tb-company", tenant_id=T_B, agent_id=TB_AGENT,
                                        tool_id="tool-p3-tb-company", allowed_operations="read_file",
                                        constraints_json={}, created_at=now),
                    CompanyFile(id=FILE_KHI, tenant_id=T_A, workspace_id=WS_KHI, owner_user_id=DAVE,
                                name="port-schedule.txt", current_version=1, status="ACTIVE"),
                    CompanyFile(id=FILE_HO, tenant_id=T_A, workspace_id=WS_HO, owner_user_id=HINA,
                                name="board-minutes.txt", current_version=1, status="ACTIVE"),
                    CompanyFile(id=FILE_TB, tenant_id=T_B, workspace_id=WS_TB, owner_user_id="usr-tb-dev-07",
                                name="beta-secret.txt", current_version=1, status="ACTIVE"),
                ])
                await session.flush()
                for fid, tid, owner, content in [
                    (FILE_KHI, T_A, DAVE, "Berth 7 reserved Tuesday 06:00."),
                    (FILE_HO, T_A, HINA, "Board minutes: confidential."),
                    (FILE_TB, T_B, "usr-tb-dev-07", "TENANT-B-SECRET"),
                ]:
                    session.add(CompanyFileVersion(id=f"ver-{fid}", tenant_id=tid, file_id=fid, version_number=1,
                                                   content=content, checksum=_sha(content),
                                                   created_by_user_id=owner))
                session.add(CompanyMessage(id="msg-p3-to-dave", tenant_id=T_A, sender_user_id=KAMRAN,
                                           recipient_user_id=DAVE, subject="Crane maintenance",
                                           body="Crane 3 is offline until Friday.", status="SENT"))
                session.add(CompanyMessage(id="msg-p3-to-hina", tenant_id=T_A, sender_user_id=SARAH,
                                           recipient_user_id=HINA, subject="Private",
                                           body="Only for Hina.", status="SENT"))
    finally:
        await engine.dispose()


@pytest.fixture(scope="module")
def db_url():
    name = helpers.create_temp_database()
    try:
        helpers.upgrade(name, "head")
        url = helpers.sqlalchemy_url(name)
        asyncio.run(_prepare(url))
        yield url
    finally:
        helpers.drop_temp_database(name)


@pytest.fixture(scope="module")
def app(db_url):
    settings = Settings(
        APP_ENV="development",
        JWT_SECRET="phase3-test-secret-key-at-least-32-characters",
        DATABASE_URL=db_url,
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )
    application = create_app(settings)
    engine = create_async_engine(db_url, poolclass=NullPool)
    application.state.db_session_factory = create_session_factory(engine)
    application.state.approvals_store = {}
    with TestClient(application) as client:
        application.state._phase3_client = client
        yield application
    asyncio.run(engine.dispose())


@pytest.fixture(scope="module")
def client(app) -> TestClient:
    return app.state._phase3_client


_tokens: dict = {}


def _headers(client: TestClient, email: str = DAVE_EMAIL, slug: str = "alphacorp") -> dict:
    key = (email, slug)
    if key not in _tokens:
        res = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD, "tenant_slug": slug})
        assert res.status_code == 200, res.text
        body = res.json()
        _tokens[key] = (body["access_token"], body.get("active_tenant", {}).get("id", T_A))
    token, tenant = _tokens[key]
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant}


def _proposal(agent: str, operation: str, parameters: dict, **extra) -> dict:
    body = {
        "action_id": f"act-p3-{uuid.uuid4().hex[:12]}",
        "agent_id": agent,
        "tool_name": TOOL,
        "operation": operation,
        "parameters": parameters,
        "memory_refs": [],
        "idempotency_key": f"idem-p3-{uuid.uuid4().hex}",
        "trace_id": f"trace-p3-{uuid.uuid4().hex[:16]}",
    }
    body.update(extra)
    return body


def _propose(client: TestClient, agent: str, operation: str, parameters: dict,
             email: str = DAVE_EMAIL, body: dict | None = None):
    payload = body or _proposal(agent, operation, parameters)
    res = client.post("/api/v1/gateway/actions/propose", json=payload, headers=_headers(client, email))
    return res, payload


def _q(db_url: str, sql: str, **params):
    async def go():
        engine = create_async_engine(db_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:  # commits (used for setup UPDATEs too)
                return [dict(r._mapping) for r in (await conn.execute(text(sql), params)).all()]
        finally:
            await engine.dispose()
    return asyncio.run(go())


def _evidence(db_url: str, proposal_id: str) -> dict:
    prop = _q(db_url, "SELECT * FROM tool_proposals WHERE id = :p", p=proposal_id)
    dec = _q(db_url, "SELECT * FROM policy_decisions WHERE proposal_id = :p", p=proposal_id)
    exe = _q(db_url, "SELECT * FROM tool_executions WHERE proposal_id = :p", p=proposal_id)
    audit = _q(db_url, "SELECT * FROM audit_events WHERE resource_id = :p AND event_type = 'TOOL_POLICY_DECIDED'",
               p=proposal_id)
    return {"proposal": prop, "decision": dec, "execution": exe, "audit": audit}


def _assert_executed(res, payload, db_url):
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decision"] == "ALLOW" and body["execution_status"] == "EXECUTED", body
    ev = _evidence(db_url, body["proposal_id"])
    assert len(ev["proposal"]) == 1 and ev["proposal"][0]["tool_name"] == TOOL
    assert ev["proposal"][0]["agent_id"] == payload["agent_id"]
    assert ev["decision"][0]["decision"] == "ALLOW" and ev["decision"][0]["execution_status"] == "EXECUTED"
    assert ev["execution"][0]["status"] == "SUCCESS"
    stored = ev["execution"][0]["result_payload_json"]
    stored = json.loads(stored) if isinstance(stored, str) else stored
    assert stored["provenance"]["agent_id"] == payload["agent_id"]
    assert stored["provenance"]["proposal_id"] == body["proposal_id"]
    assert len(ev["audit"]) == 1 and ev["audit"][0]["outcome"] == "ALLOW"
    return body["result"]["result"], body


def _assert_adapter_refused(res, db_url, status_code, error_code=None):
    """M4 allowed dispatch but the server-side adapter refused: FAILED, never success."""
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decision"] == "ALLOW" and body["execution_status"] == "FAILED", body
    assert body["result"]["error"]
    if error_code:
        assert body["result"]["error_code"] == error_code, body["result"]
    ev = _evidence(db_url, body["proposal_id"])
    assert ev["execution"][0]["status"] == "FAILED"
    assert ev["execution"][0]["status_code"] == status_code
    assert ev["decision"][0]["execution_status"] == "FAILED"
    return body


# ----------------------------------------------------------------------------
# Wiring
# ----------------------------------------------------------------------------

def test_company_adapter_registered_with_persistence(app):
    registry = app.state.tool_registry
    assert registry.get_adapter(TOOL) is not None
    assert registry.get_adapter("sandbox_transfer") is not None


# ----------------------------------------------------------------------------
# ALLOW: persisted company operations with decision / execution / audit evidence
# ----------------------------------------------------------------------------

def test_agent_creates_file_persisted_with_full_evidence(client, db_url):
    res, payload = _propose(client, BRANCH_AGENT, "create_file", {
        "workspace_id": WS_KHI, "name": "berth-plan.txt", "content": "Berth 4 cleared for MV Indus.",
    })
    result, body = _assert_executed(res, payload, db_url)
    rows = _q(db_url, "SELECT * FROM company_files WHERE id = :i", i=result["id"])
    assert rows and rows[0]["tenant_id"] == T_A and rows[0]["workspace_id"] == WS_KHI
    assert rows[0]["owner_user_id"] == DAVE and rows[0]["current_version"] == 1
    ver = _q(db_url, "SELECT * FROM company_file_versions WHERE file_id = :i", i=result["id"])
    assert ver[0]["checksum"] == _sha("Berth 4 cleared for MV Indus.") == result["checksum"]
    act = _q(db_url, "SELECT * FROM company_activity WHERE resource_id = :i", i=result["id"])
    assert act[0]["event_type"] == "FILE_CREATED" and act[0]["actor_user_id"] == DAVE
    assert act[0]["branch_id"] == KHI


def test_agent_reads_and_updates_file_with_versioning(client, db_url):
    res, payload = _propose(client, BRANCH_AGENT, "read_file", {"file_id": FILE_KHI})
    result, _ = _assert_executed(res, payload, db_url)
    assert result["content"] == "Berth 7 reserved Tuesday 06:00." and result["version"] == 1

    res, payload = _propose(client, BRANCH_AGENT, "update_file",
                            {"file_id": FILE_KHI, "content": "Berth 7 reserved Wednesday 06:00."})
    result, _ = _assert_executed(res, payload, db_url)
    assert result["version"] == 2
    versions = _q(db_url, "SELECT version_number, content FROM company_file_versions WHERE file_id = :f "
                          "ORDER BY version_number", f=FILE_KHI)
    assert [v["version_number"] for v in versions] == [1, 2]
    assert versions[1]["content"] == "Berth 7 reserved Wednesday 06:00."


def test_agent_lists_only_in_scope_workspaces_and_files(client, db_url):
    res, payload = _propose(client, BRANCH_AGENT, "list_workspaces", {})
    result, _ = _assert_executed(res, payload, db_url)
    ids = {w["id"] for w in result}
    assert WS_KHI in ids and WS_HO not in ids and WS_TB not in ids
    assert all(w["branch_id"] == KHI for w in result)

    res, payload = _propose(client, BRANCH_AGENT, "list_files", {"workspace_id": WS_KHI})
    result, _ = _assert_executed(res, payload, db_url)
    assert FILE_KHI in {f["id"] for f in result}


def test_agent_task_lifecycle_and_handoff_persisted(client, db_url):
    res, payload = _propose(client, BRANCH_AGENT, "create_task", {
        "workspace_id": WS_KHI, "title": "Inspect crane 3", "priority": "HIGH",
    })
    task, _ = _assert_executed(res, payload, db_url)
    task_id = task["id"]

    res, payload = _propose(client, BRANCH_AGENT, "update_task_status", {"task_id": task_id, "status": "IN_PROGRESS"})
    _assert_executed(res, payload, db_url)
    res, payload = _propose(client, BRANCH_AGENT, "handoff_task", {"task_id": task_id, "assigned_to_user_id": KAMRAN})
    handed, _ = _assert_executed(res, payload, db_url)
    assert handed["assigned_to_user_id"] == KAMRAN

    row = _q(db_url, "SELECT * FROM company_tasks WHERE id = :t", t=task_id)[0]
    assert row["branch_id"] == KHI and row["status"] == "IN_PROGRESS"
    assert row["created_by_user_id"] == DAVE and row["assigned_to_user_id"] == KAMRAN
    events = _q(db_url, "SELECT event_type FROM company_task_events WHERE task_id = :t ORDER BY created_at", t=task_id)
    assert [e["event_type"] for e in events] == ["CREATED", "UPDATED", "UPDATED"]
    notes = _q(db_url, "SELECT * FROM company_notifications WHERE resource_id = :t AND user_id = :u",
               t=task_id, u=KAMRAN)
    assert notes and notes[0]["event_type"] == "TASK_ASSIGNED"


def test_agent_sends_message_and_reads_only_own_inbox(client, db_url):
    res, payload = _propose(client, BRANCH_AGENT, "send_message", {
        "recipient_user_id": KAMRAN, "subject": "Crane 3", "body": "Please inspect crane 3 today.",
    })
    sent, _ = _assert_executed(res, payload, db_url)
    msg = _q(db_url, "SELECT * FROM company_messages WHERE id = :m", m=sent["id"])[0]
    assert msg["sender_user_id"] == DAVE and msg["recipient_user_id"] == KAMRAN and msg["status"] == "SENT"

    res, payload = _propose(client, BRANCH_AGENT, "read_inbox", {})
    inbox, _ = _assert_executed(res, payload, db_url)
    ids = {m["id"] for m in inbox}
    assert "msg-p3-to-dave" in ids and "msg-p3-to-hina" not in ids


def test_idempotent_replay_does_not_repeat_the_operation(client, db_url):
    body = _proposal(BRANCH_AGENT, "create_file",
                     {"workspace_id": WS_KHI, "name": "replay-check.txt", "content": "once"})
    first, _ = _propose(client, BRANCH_AGENT, "create_file", {}, body=body)
    second, _ = _propose(client, BRANCH_AGENT, "create_file", {}, body=body)
    assert first.status_code == second.status_code == 200
    assert first.json()["proposal_id"] == second.json()["proposal_id"]
    rows = _q(db_url, "SELECT id FROM company_files WHERE name = 'replay-check.txt'")
    assert len(rows) == 1


# ----------------------------------------------------------------------------
# REVIEW: high-impact transfer needs bound human approval
# ----------------------------------------------------------------------------

def test_file_transfer_requires_approval_and_is_not_executed(client, db_url):
    res, _ = _propose(client, BRANCH_AGENT, "transfer_file", {"file_id": FILE_KHI, "recipient_user_id": KAMRAN})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decision"] == "REQUIRES_APPROVAL" and body["execution_status"] == "PENDING_APPROVAL"
    assert "HIGH_IMPACT_APPROVAL_REQUIRED" in body["reason_codes"]
    ev = _evidence(db_url, body["proposal_id"])
    assert ev["decision"][0]["decision"] == "REQUIRES_APPROVAL" and ev["execution"] == []
    assert _q(db_url, "SELECT id FROM company_file_transfers WHERE file_id = :f", f=FILE_KHI) == []


def test_file_transfer_executes_once_with_bound_human_approval(app, client, db_url):
    body = _proposal(BRANCH_AGENT, "transfer_file", {"file_id": FILE_KHI, "recipient_user_id": KAMRAN,
                                                     "message": "Updated berth schedule"})
    facts = policy_mod.normalize_proposal(body)
    approval_id = f"appr-p3-{uuid.uuid4().hex[:8]}"
    app.state.approvals_store[(T_A, approval_id)] = {
        "status": "APPROVED",
        "proposal_fingerprint": policy_mod.proposal_fingerprint(facts, T_A, DAVE),
        "approver_user_id": SARAH,
        "approver_role": "TENANT_ADMIN",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=30),
        "consumed": False,
    }
    body["approval_id"] = approval_id
    res, payload = _propose(client, BRANCH_AGENT, "transfer_file", {}, body=body)
    transfer, _ = _assert_executed(res, payload, db_url)
    row = _q(db_url, "SELECT * FROM company_file_transfers WHERE id = :t", t=transfer["id"])[0]
    assert row["sender_user_id"] == DAVE and row["recipient_user_id"] == KAMRAN and row["status"] == "PENDING"
    assert app.state.approvals_store[(T_A, approval_id)]["consumed"] is True

    reuse = _proposal(BRANCH_AGENT, "transfer_file", {"file_id": FILE_KHI, "recipient_user_id": KAMRAN})
    reuse["approval_id"] = approval_id
    res, _ = _propose(client, BRANCH_AGENT, "transfer_file", {}, body=reuse)
    assert res.json()["decision"] == "BLOCK" and res.json()["execution_status"] == "NOT_EXECUTED"
    assert len(_q(db_url, "SELECT id FROM company_file_transfers WHERE file_id = :f", f=FILE_KHI)) == 1


# ----------------------------------------------------------------------------
# BLOCK at M4: no grant / operation not granted / suspended governance
# ----------------------------------------------------------------------------

def test_agent_without_company_grant_is_blocked(client, db_url):
    res, _ = _propose(client, HR_AGENT, "create_file", {"workspace_id": WS_KHI, "name": "x.txt", "content": "x"})
    body = res.json()
    assert body["decision"] == "BLOCK" and body["execution_status"] == "NOT_EXECUTED"
    assert "TOOL_NOT_ASSIGNED" in body["reason_codes"]
    assert _evidence(db_url, body["proposal_id"])["execution"] == []
    assert _q(db_url, "SELECT id FROM company_files WHERE name = 'x.txt'") == []


def test_operation_outside_grant_is_blocked_before_adapter(client, db_url):
    res, _ = _propose(client, COORD_AGENT, "create_file",
                      {"workspace_id": WS_HO, "name": "coord.txt", "content": "x"}, email=HINA_EMAIL)
    body = res.json()
    assert body["decision"] == "BLOCK" and "OPERATION_DENIED" in body["reason_codes"]
    assert _evidence(db_url, body["proposal_id"])["execution"] == []
    assert _q(db_url, "SELECT id FROM company_files WHERE name = 'coord.txt'") == []


def test_suspended_agent_profile_is_blocked(client, db_url):
    _q(db_url, "UPDATE agent_security_profiles SET status = 'SUSPENDED' WHERE agent_id = :a RETURNING id",
       a=BRANCH_AGENT)
    try:
        res, _ = _propose(client, BRANCH_AGENT, "create_file",
                          {"workspace_id": WS_KHI, "name": "suspended.txt", "content": "x"})
        body = res.json()
        assert body["decision"] == "BLOCK" and body["execution_status"] == "NOT_EXECUTED"
        assert _q(db_url, "SELECT id FROM company_files WHERE name = 'suspended.txt'") == []
    finally:
        _q(db_url, "UPDATE agent_security_profiles SET status = 'ACTIVE' WHERE agent_id = :a RETURNING id",
           a=BRANCH_AGENT)


# ----------------------------------------------------------------------------
# Server-side scope: forged scope, cross-branch, cross-tenant
# ----------------------------------------------------------------------------

def test_agent_cannot_forge_user_or_tenant_scope(client, db_url):
    res, _ = _propose(client, BRANCH_AGENT, "create_file", {
        "workspace_id": WS_KHI, "name": "forged.txt", "content": "x", "user_id": KAMRAN, "tenant_id": T_B,
    })
    _assert_adapter_refused(res, db_url, 403, "AGENT_SUPPLIED_SCOPE_REJECTED")
    assert _q(db_url, "SELECT id FROM company_files WHERE name = 'forged.txt'") == []


def test_forged_branch_parameter_is_blocked_before_adapter(client, db_url):
    # Head Office agent naming a Karachi branch: detection blocks at the gateway.
    res, _ = _propose(client, COORD_AGENT, "create_task",
                      {"workspace_id": WS_HO, "title": "forged-branch", "branch_id": KHI}, email=HINA_EMAIL)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decision"] == "BLOCK" and body["execution_status"] == "NOT_EXECUTED", body
    assert "BRANCH_ISOLATION_VIOLATION" in body["reason_codes"]
    assert _evidence(db_url, body["proposal_id"])["execution"] == []
    assert _q(db_url, "SELECT id FROM company_tasks WHERE title = 'forged-branch'") == []


def test_agent_cannot_reach_other_branch_resources(client, db_url):
    res, _ = _propose(client, BRANCH_AGENT, "read_file", {"file_id": FILE_HO})
    body = _assert_adapter_refused(res, db_url, 403, "AGENT_RESOURCE_SCOPE_DENIED")
    assert "content" not in json.dumps(body["result"])

    res, _ = _propose(client, BRANCH_AGENT, "create_task", {"workspace_id": WS_HO, "title": "cross-branch"})
    _assert_adapter_refused(res, db_url, 403, "AGENT_RESOURCE_SCOPE_DENIED")
    assert _q(db_url, "SELECT id FROM company_tasks WHERE title = 'cross-branch'") == []


def test_agent_scope_must_cover_acting_employee_branch(client, db_url):
    # Head Office agent acting for a Karachi employee.
    res, _ = _propose(client, COORD_AGENT, "create_task", {"workspace_id": WS_KHI, "title": "wrong-agent"})
    _assert_adapter_refused(res, db_url, 403, "AGENT_BRANCH_SCOPE_DENIED")
    # Karachi agent acting for a Head Office employee.
    res, _ = _propose(client, BRANCH_AGENT, "list_files", {"workspace_id": WS_HO}, email=HINA_EMAIL)
    _assert_adapter_refused(res, db_url, 403, "AGENT_BRANCH_SCOPE_DENIED")
    assert _q(db_url, "SELECT id FROM company_tasks WHERE title = 'wrong-agent'") == []


def test_head_office_agent_works_for_head_office_employee(client, db_url):
    res, payload = _propose(client, COORD_AGENT, "list_files", {"workspace_id": WS_HO}, email=HINA_EMAIL)
    result, _ = _assert_executed(res, payload, db_url)
    assert FILE_HO in {f["id"] for f in result}


def test_cross_tenant_agent_is_rejected(client, db_url):
    res, _ = _propose(client, TB_AGENT, "read_file", {"file_id": FILE_TB})
    assert res.status_code == 404, res.text
    assert _q(db_url, "SELECT id FROM tool_proposals WHERE agent_id = :a", a=TB_AGENT) == []


def test_cross_tenant_resource_is_not_found_and_not_leaked(client, db_url):
    res, _ = _propose(client, BRANCH_AGENT, "read_file", {"file_id": FILE_TB})
    body = _assert_adapter_refused(res, db_url, 404)
    assert "TENANT-B-SECRET" not in json.dumps(body)


def test_recipient_outside_branch_is_refused(client, db_url):
    res, _ = _propose(client, BRANCH_AGENT, "send_message", {"recipient_user_id": HINA, "body": "hello HO"})
    _assert_adapter_refused(res, db_url, 403, "AGENT_RESOURCE_SCOPE_DENIED")
    assert _q(db_url, "SELECT id FROM company_messages WHERE body = 'hello HO'") == []


# ----------------------------------------------------------------------------
# Agent runtimes over the real gateway (no LLM call: the tool an LLM would
# invoke is executed directly, so every decision below is the server's).
# ----------------------------------------------------------------------------

def _agent_client(app):
    from crewai_service.tools.amsc_client import ChronoCogniSecClient

    client = ChronoCogniSecClient(app=app, tenant_id=T_A, email=DAVE_EMAIL, password=PASSWORD,
                                  tenant_slug="alphacorp")
    assert client.authenticate() is True
    return client


def test_crewai_branch_agent_tools_execute_through_gateway(app, db_url):
    from crewai_service.agents.branch_operations import build_branch_operations_agent

    agent = build_branch_operations_agent(llm=object(), client=_agent_client(app))
    tools = {t.name: t for t in agent.tools}

    created = json.loads(tools["company_create_task"].run(
        workspace_id=WS_KHI, title="CrewAI: reconcile berth log", priority="NORMAL"))
    assert created["completed"] is True and created["decision"] == "ALLOW", created
    task_id = created["result"]["id"]
    row = _q(db_url, "SELECT * FROM company_tasks WHERE id = :t", t=task_id)[0]
    assert row["created_by_user_id"] == DAVE and row["branch_id"] == KHI
    prop = _q(db_url, "SELECT agent_id, tool_name, operation FROM tool_proposals WHERE id = :p",
              p=created["proposal_id"])[0]
    assert prop == {"agent_id": BRANCH_AGENT, "tool_name": TOOL, "operation": "create_task"}

    pending = json.loads(tools["company_transfer_file"].run(file_id=FILE_KHI, recipient_user_id=KAMRAN))
    assert pending["completed"] is False and pending["decision"] == "REQUIRES_APPROVAL"

    denied = json.loads(tools["company_read_file"].run(file_id=FILE_HO))
    assert denied["completed"] is False and denied["error_code"] == "AGENT_RESOURCE_SCOPE_DENIED"


def test_langgraph_contract_executes_through_gateway(app, db_url):
    contract = LangGraphAdapterContract()
    proposal = ActionProposal(
        action_id=f"act-lg-{uuid.uuid4().hex[:10]}", agent_id=BRANCH_AGENT, tool_name=TOOL,
        operation="send_message",
        parameters={"recipient_user_id": KAMRAN, "subject": "LangGraph", "body": "Shift handover complete."},
        idempotency_key=f"idem-lg-{uuid.uuid4().hex}", trace_id=f"trace-lg-{uuid.uuid4().hex[:16]}",
    )
    receipt = asyncio.run(contract.propose_action(proposal, _agent_client(app)))
    assert receipt.decision == "ALLOW" and receipt.execution_status == "EXECUTED", receipt
    msg_id = receipt.result["result"]["id"]
    row = _q(db_url, "SELECT * FROM company_messages WHERE id = :m", m=msg_id)[0]
    assert row["sender_user_id"] == DAVE and row["body"] == "Shift handover complete."
    assert _q(db_url, "SELECT agent_id FROM tool_proposals WHERE id = :p", p=receipt.proposal_id)[0]["agent_id"] \
        == BRANCH_AGENT


def test_company_tables_unchanged_by_refused_operations(db_url):
    """Nothing outside the executed proposals reached company storage."""
    for marker in ("forged.txt", "x.txt", "coord.txt", "suspended.txt"):
        assert _q(db_url, "SELECT id FROM company_files WHERE name = :n", n=marker) == []
    assert _q(db_url, "SELECT id FROM company_files WHERE tenant_id = :t", t=T_B) == [{"id": FILE_TB}]
