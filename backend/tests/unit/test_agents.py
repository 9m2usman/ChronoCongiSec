"""Unit and Integration Tests for Agent Registry API Endpoints.

Module: backend.tests.unit.test_agents
Owner: M1 — Platform Backend & API Integration Lead

Verifies:
1. API Functionality:
   - Authenticated user can list authorized agents.
   - AI_DEVELOPER can register an agent.
   - Successful registration returns HTTP 201 with AgentSummaryResponse.
   - Registration creates Agent entity and matching AgentVersion snapshot (v1.0.0).
   - Agent detail returns correct record and tool permissions.
   - Bounded pagination (limit, offset, has_more).
   - Status filtering (ACTIVE, ISOLATED, DEPRECATED).
   - Empty registry returns valid envelope with empty items list.
2. Authentication & Authorization:
   - Missing token returns 401.
   - Invalid / expired token returns 401.
   - Non-AI_DEVELOPER (e.g. SECURITY_ANALYST) cannot register agent (returns 403 Forbidden).
   - Client-supplied tenant_id or extra fields in request rejected (422).
   - Inactive / revoked membership denied access.
3. Multi-Tenant Isolation:
   - Tenant A lists only Tenant A agents; Tenant B lists only Tenant B agents.
   - Tenant A cannot retrieve Tenant B agent by ID (returns 404, never disclosing cross-tenant existence).
   - Forged X-Tenant-ID headers do not compromise tenant boundary.
4. Transaction Atomicity:
   - Simulated failure during AgentVersion insertion rolls back Agent.
   - No partial registration state remains.
   - Safe error returned to client (500).
5. System Prompt Confidentiality:
   - system_prompt is strictly excluded from list responses.
   - system_prompt is strictly excluded from detail responses.
   - system_prompt is strictly excluded from registration responses.
   - Persisted snapshot retains system_prompt for runtime execution.
6. Input Validation:
   - Rejection of invalid runtime, missing name, whitespace-only fields, oversized fields.
   - Rejection of negative or excessive pagination parameters.
   - Rejection of invalid status filters.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import pytest
import httpx

from backend.app.api.agents import (
    AgentEntity,
    AgentRepositoryProtocol,
    AgentVersionEntity,
    InMemoryAgentRepository,
    get_default_agent_repository,
)
from backend.app.core.config import Settings
from backend.app.core.security import create_access_token
from backend.app.main import create_app


@pytest.fixture
def test_settings() -> Settings:
    """Standard test settings fixture."""
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )


@pytest.fixture
def isolated_agent_repo() -> InMemoryAgentRepository:
    """Isolated in-memory repository for each test."""
    return InMemoryAgentRepository()


@pytest.fixture
def client(test_settings: Settings, isolated_agent_repo: InMemoryAgentRepository):
    """Async test client with isolated agent repository."""
    app = create_app(settings=test_settings)
    app.state.agent_repo = isolated_agent_repo
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def create_token_for(
    user_id: str,
    email: str,
    tenant_id: str,
    role: str,
    settings: Settings,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Helper to generate signed JWT for test scenarios."""
    return create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        expires_delta=expires_delta,
        settings=settings,
        additional_claims={"email": email},
    )


# Canonical test accounts from context.py seed
TENANT_A_ID = "tenant-a-uuid-001"
TENANT_B_ID = "tenant-b-uuid-002"
USER_A_DEV_ID = "user-a-dev-009"
USER_A_ANALYST_ID = "user-a-analyst-001"
USER_B_DEV_ID = "user-b-dev-010"


# ============================================================================
# 1. API Functionality Tests
# ============================================================================

@pytest.mark.asyncio
async def test_empty_agent_registry_returns_valid_envelope(client: httpx.AsyncClient, test_settings: Settings):
    """Verify empty registry returns HTTP 200 with items=[], limit, offset, and has_more=False."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    async with client as c:
        response = await c.get("/api/v1/agents", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0
        assert data["has_more"] is False


@pytest.mark.asyncio
async def test_ai_developer_can_register_agent_success(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify AI_DEVELOPER can register an agent and initial configuration version is created."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "Financial Risk Analyzer",
        "runtime": "LANGCHAIN",
        "model": "gpt-4o",
        "system_prompt": "You are a specialized risk analyst with strict compliance instructions.",
    }

    async with client as c:
        response = await c.post("/api/v1/agents", headers=headers, json=payload)
        assert response.status_code == 201
        data = response.json()

        agent_id = data["id"]
        assert data["tenant_id"] == TENANT_A_ID
        assert data["name"] == "Financial Risk Analyzer"
        assert data["runtime"] == "LANGCHAIN"
        assert data["model"] == "gpt-4o"
        assert data["status"] == "ACTIVE"
        assert data["config_version"] == "v1.0.0"
        assert "created_at" in data
        assert "updated_at" in data

        # Verify underlying persistence in repository
        agent_in_db = await isolated_agent_repo.get_agent_by_id(agent_id, TENANT_A_ID)
        assert agent_in_db is not None
        assert agent_in_db.name == "Financial Risk Analyzer"
        assert agent_in_db.system_prompt == payload["system_prompt"]

        # Verify matching AgentVersion row exists
        version_in_db = await isolated_agent_repo.get_agent_version(agent_id, "v1.0.0", TENANT_A_ID)
        assert version_in_db is not None
        assert version_in_db.version == "v1.0.0"
        assert version_in_db.config_payload["system_prompt"] == payload["system_prompt"]
        assert version_in_db.config_payload["registered_by"] == USER_A_DEV_ID


@pytest.mark.asyncio
async def test_agent_detail_returns_correct_record_and_permissions(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify GET /agents/{id} returns agent details with tool_permissions list."""
    token = create_token_for(USER_A_ANALYST_ID, "analyst@company-a.com", TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    agent = AgentEntity(
        id="agent-001",
        tenant_id=TENANT_A_ID,
        name="Compliance Agent",
        runtime="CREWAI",
        model="claude-3-5-sonnet",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Internal guidelines",
        created_at=now,
        updated_at=now,
    )
    version = AgentVersionEntity(
        id="ver-001",
        tenant_id=TENANT_A_ID,
        agent_id="agent-001",
        version="v1.0.0",
        config_payload={"name": "Compliance Agent"},
        created_at=now,
    )
    await isolated_agent_repo.create_agent_atomic(agent, version)

    async with client as c:
        response = await c.get("/api/v1/agents/agent-001", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "agent-001"
        assert data["name"] == "Compliance Agent"
        assert data["runtime"] == "CREWAI"
        assert data["model"] == "claude-3-5-sonnet"
        assert data["tool_permissions"] == []


@pytest.mark.asyncio
async def test_agent_list_pagination_and_deterministic_ordering(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify limit, offset, and has_more behavior with deterministic ordering."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Seed 5 agents
    for i in range(5):
        now = datetime.now(timezone.utc)
        a = AgentEntity(
            id=f"agent-{i:03d}",
            tenant_id=TENANT_A_ID,
            name=f"Agent Number {i}",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Prompt instructions",
            created_at=now,
            updated_at=now,
        )
        v = AgentVersionEntity(
            id=f"ver-{i:03d}",
            tenant_id=TENANT_A_ID,
            agent_id=f"agent-{i:03d}",
            version="v1.0.0",
            config_payload={},
            created_at=now,
        )
        await isolated_agent_repo.create_agent_atomic(a, v)

    async with client as c:
        # Request page 1: limit 2, offset 0
        r1 = await c.get("/api/v1/agents?limit=2&offset=0", headers=headers)
        assert r1.status_code == 200
        d1 = r1.json()
        assert len(d1["items"]) == 2
        assert d1["limit"] == 2
        assert d1["offset"] == 0
        assert d1["has_more"] is True

        # Request page 2: limit 2, offset 2
        r2 = await c.get("/api/v1/agents?limit=2&offset=2", headers=headers)
        assert r2.status_code == 200
        d2 = r2.json()
        assert len(d2["items"]) == 2
        assert d2["has_more"] is True

        # Request page 3: limit 2, offset 4
        r3 = await c.get("/api/v1/agents?limit=2&offset=4", headers=headers)
        assert r3.status_code == 200
        d3 = r3.json()
        assert len(d3["items"]) == 1
        assert d3["has_more"] is False


@pytest.mark.asyncio
async def test_agent_status_filtering(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify filtering by ACTIVE, ISOLATED, DEPRECATED."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    statuses = ["ACTIVE", "ISOLATED", "DEPRECATED"]
    for s in statuses:
        now = datetime.now(timezone.utc)
        a = AgentEntity(
            id=f"agent-{s.lower()}",
            tenant_id=TENANT_A_ID,
            name=f"{s} Agent",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status=s,
            config_version="v1.0.0",
            system_prompt="...",
            created_at=now,
            updated_at=now,
        )
        v = AgentVersionEntity(
            id=f"ver-{s.lower()}",
            tenant_id=TENANT_A_ID,
            agent_id=f"agent-{s.lower()}",
            version="v1.0.0",
            config_payload={},
            created_at=now,
        )
        await isolated_agent_repo.create_agent_atomic(a, v)

    async with client as c:
        # Filter by ISOLATED
        r_iso = await c.get("/api/v1/agents?status=ISOLATED", headers=headers)
        assert r_iso.status_code == 200
        d_iso = r_iso.json()
        assert len(d_iso["items"]) == 1
        assert d_iso["items"][0]["status"] == "ISOLATED"

        # Filter by DEPRECATED (lowercase query parameter works case-insensitively)
        r_dep = await c.get("/api/v1/agents?status=deprecated", headers=headers)
        assert r_dep.status_code == 200
        d_dep = r_dep.json()
        assert len(d_dep["items"]) == 1
        assert d_dep["items"][0]["status"] == "DEPRECATED"


# ============================================================================
# 2. Authentication & Authorization Tests
# ============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_request_rejected_with_401(client: httpx.AsyncClient):
    """Verify requests without Authorization header return HTTP 401."""
    async with client as c:
        r1 = await c.get("/api/v1/agents")
        assert r1.status_code == 401
        r2 = await c.post("/api/v1/agents", json={})
        assert r2.status_code == 401
        r3 = await c.get("/api/v1/agents/some-id")
        assert r3.status_code == 401


@pytest.mark.asyncio
async def test_invalid_and_expired_token_rejected_with_401(client: httpx.AsyncClient, test_settings: Settings):
    """Verify tampered or expired JWTs are rejected with HTTP 401."""
    expired_token = create_token_for(
        USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings, expires_delta=timedelta(minutes=-10)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}

    async with client as c:
        r_exp = await c.get("/api/v1/agents", headers=headers)
        assert r_exp.status_code == 401

        r_bad = await c.get("/api/v1/agents", headers={"Authorization": "Bearer not-a-valid-token"})
        assert r_bad.status_code == 401


@pytest.mark.asyncio
async def test_non_ai_developer_cannot_register_agent(client: httpx.AsyncClient, test_settings: Settings):
    """Verify SECURITY_ANALYST cannot register an agent (returns 403 Forbidden)."""
    token = create_token_for(USER_A_ANALYST_ID, "analyst@company-a.com", TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "Unauthorized Agent",
        "runtime": "LANGCHAIN",
        "model": "gpt-4o",
        "system_prompt": "Instructions",
    }

    async with client as c:
        response = await c.post("/api/v1/agents", headers=headers, json=payload)
        assert response.status_code == 403
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "FORBIDDEN_ACTION"


@pytest.mark.asyncio
async def test_client_supplied_tenant_id_in_body_is_rejected(client: httpx.AsyncClient, test_settings: Settings):
    """Verify extra forbidden field 'tenant_id' in registration payload returns 400 validation error."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "Spoofed Tenant Agent",
        "runtime": "LANGCHAIN",
        "model": "gpt-4o",
        "system_prompt": "Instructions",
        "tenant_id": TENANT_B_ID,  # Attacker attempts to forge tenant_id
    }

    async with client as c:
        response = await c.post("/api/v1/agents", headers=headers, json=payload)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# ============================================================================
# 3. Multi-Tenant Isolation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_tenant_isolation_list_and_detail(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify Tenant A sees only Tenant A agents, and cannot access Tenant B agents."""
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    token_b = create_token_for(USER_B_DEV_ID, "developer@company-b.com", TENANT_B_ID, "AI_DEVELOPER", test_settings)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    now = datetime.now(timezone.utc)
    agent_a = AgentEntity(
        id="agent-company-a-001",
        tenant_id=TENANT_A_ID,
        name="Company A Secret Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Secret Company A Prompt",
        created_at=now,
        updated_at=now,
    )
    ver_a = AgentVersionEntity(
        id="ver-a-001",
        tenant_id=TENANT_A_ID,
        agent_id="agent-company-a-001",
        version="v1.0.0",
        config_payload={},
        created_at=now,
    )
    await isolated_agent_repo.create_agent_atomic(agent_a, ver_a)

    agent_b = AgentEntity(
        id="agent-company-b-002",
        tenant_id=TENANT_B_ID,
        name="Company B Public Agent",
        runtime="CREWAI",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Public Company B Prompt",
        created_at=now,
        updated_at=now,
    )
    ver_b = AgentVersionEntity(
        id="ver-b-002",
        tenant_id=TENANT_B_ID,
        agent_id="agent-company-b-002",
        version="v1.0.0",
        config_payload={},
        created_at=now,
    )
    await isolated_agent_repo.create_agent_atomic(agent_b, ver_b)

    async with client as c:
        # Tenant A lists agents: sees ONLY Company A's agent
        res_a = await c.get("/api/v1/agents", headers=headers_a)
        assert res_a.status_code == 200
        items_a = res_a.json()["items"]
        assert len(items_a) == 1
        assert items_a[0]["id"] == "agent-company-a-001"

        # Tenant B lists agents: sees ONLY Company B's agent
        res_b = await c.get("/api/v1/agents", headers=headers_b)
        assert res_b.status_code == 200
        items_b = res_b.json()["items"]
        assert len(items_b) == 1
        assert items_b[0]["id"] == "agent-company-b-002"

        # Tenant A attempts to fetch Tenant B's agent directly by ID -> returns 404 (IDOR protection)
        res_cross = await c.get("/api/v1/agents/agent-company-b-002", headers=headers_a)
        assert res_cross.status_code == 404
        assert res_cross.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

        # Forged X-Tenant-ID header that does not match JWT tenant is immediately rejected with 403 Forbidden
        headers_forged = {
            "Authorization": f"Bearer {token_a}",
            "X-Tenant-ID": TENANT_B_ID,
        }
        res_forged = await c.get("/api/v1/agents", headers=headers_forged)
        assert res_forged.status_code == 403
        assert res_forged.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


# ============================================================================
# 4. System Prompt Confidentiality Tests (GAP-010)
# ============================================================================

@pytest.mark.asyncio
async def test_system_prompt_never_exposed_in_responses(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify system_prompt is excluded from list, detail, and registration API responses."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    super_secret_prompt = "CONFIDENTIAL_OPERATIONAL_INSTRUCTIONS_DO_NOT_LEAK_999"
    payload = {
        "name": "Classified Workflow Agent",
        "runtime": "AUTOGEN",
        "model": "gpt-4o",
        "system_prompt": super_secret_prompt,
    }

    async with client as c:
        # 1. Registration response check
        reg_res = await c.post("/api/v1/agents", headers=headers, json=payload)
        assert reg_res.status_code == 201
        reg_data = reg_res.json()
        assert "system_prompt" not in reg_data
        assert super_secret_prompt not in str(reg_data)
        agent_id = reg_data["id"]

        # 2. List response check
        list_res = await c.get("/api/v1/agents", headers=headers)
        assert list_res.status_code == 200
        list_data = list_res.json()
        assert "system_prompt" not in list_data["items"][0]
        assert super_secret_prompt not in str(list_data)

        # 3. Detail response check
        detail_res = await c.get(f"/api/v1/agents/{agent_id}", headers=headers)
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        assert "system_prompt" not in detail_data
        assert super_secret_prompt not in str(detail_data)

        # 4. Verify prompt IS persisted in snapshot for runtime execution
        version = await isolated_agent_repo.get_agent_version(agent_id, "v1.0.0", TENANT_A_ID)
        assert version is not None
        assert version.config_payload["system_prompt"] == super_secret_prompt


# ============================================================================
# 5. Transaction Atomicity & Rollback Tests
# ============================================================================

@pytest.mark.asyncio
async def test_transaction_rollback_when_version_creation_fails(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify that if version insertion fails, agent is rolled back and not persisted."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Inject failure into version insert
    isolated_agent_repo.fail_version_insert = True

    payload = {
        "name": "Failed Transaction Agent",
        "runtime": "LANGCHAIN",
        "model": "gpt-4o",
        "system_prompt": "Instructions",
    }

    async with client as c:
        response = await c.post("/api/v1/agents", headers=headers, json=payload)
        # Must return error (500)
        assert response.status_code == 500

        # Verify zero agents exist in repository (clean rollback)
        agents, _ = await isolated_agent_repo.list_agents(TENANT_A_ID)
        assert len(agents) == 0


# ============================================================================
# 6. Input Validation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_input_validation_rejections(client: httpx.AsyncClient, test_settings: Settings):
    """Verify schema constraints on registration fields."""
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    async with client as c:
        # 1. Invalid runtime
        r1 = await c.post("/api/v1/agents", headers=headers, json={
            "name": "Test", "runtime": "UNSUPPORTED_RUNTIME", "model": "gpt-4o", "system_prompt": "Instructions"
        })
        assert r1.status_code == 400

        # 2. Missing name
        r2 = await c.post("/api/v1/agents", headers=headers, json={
            "runtime": "LANGCHAIN", "model": "gpt-4o", "system_prompt": "Instructions"
        })
        assert r2.status_code == 400

        # 3. Whitespace-only name
        r3 = await c.post("/api/v1/agents", headers=headers, json={
            "name": "   ", "runtime": "LANGCHAIN", "model": "gpt-4o", "system_prompt": "Instructions"
        })
        assert r3.status_code == 400

        # 4. Oversized name (> 255 chars)
        r4 = await c.post("/api/v1/agents", headers=headers, json={
            "name": "A" * 256, "runtime": "LANGCHAIN", "model": "gpt-4o", "system_prompt": "Instructions"
        })
        assert r4.status_code == 400

        # 5. Oversized model (> 64 chars)
        r5 = await c.post("/api/v1/agents", headers=headers, json={
            "name": "Test", "runtime": "LANGCHAIN", "model": "M" * 65, "system_prompt": "Instructions"
        })
        assert r5.status_code == 400

        # 6. Unexpected extra fields (extra="forbid")
        r6 = await c.post("/api/v1/agents", headers=headers, json={
            "name": "Test", "runtime": "LANGCHAIN", "model": "gpt-4o", "system_prompt": "Instructions", "hacker_field": True
        })
        assert r6.status_code == 400

        # 7. Invalid pagination values
        r7 = await c.get("/api/v1/agents?limit=0", headers=headers)
        assert r7.status_code == 400
        r8 = await c.get("/api/v1/agents?limit=101", headers=headers)
        assert r8.status_code == 400
        r9 = await c.get("/api/v1/agents?offset=-1", headers=headers)
        assert r9.status_code == 400

        # 8. Invalid status filter
        r10 = await c.get("/api/v1/agents?status=UNKNOWN_STATUS", headers=headers)
        assert r10.status_code == 400


# ============================================================================
# 7. Additional Security, Branch Authorization & Production Guardrail Tests
# ============================================================================

@pytest.mark.asyncio
async def test_revoked_and_suspended_membership_cannot_access_agents(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify users with REVOKED or SUSPENDED membership are rejected with 403 Forbidden."""
    # From context.py seed: user-revoked-mem-006 has REVOKED membership in Tenant A
    revoked_token = create_token_for(
        "user-revoked-mem-006", "revoked-mem@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings
    )
    headers_revoked = {"Authorization": f"Bearer {revoked_token}"}

    # user-suspended-mem-007 has SUSPENDED membership in Tenant A
    suspended_token = create_token_for(
        "user-suspended-mem-007", "suspended-mem@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings
    )
    headers_suspended = {"Authorization": f"Bearer {suspended_token}"}

    async with client as c:
        r_rev = await c.get("/api/v1/agents", headers=headers_revoked)
        assert r_rev.status_code == 403
        assert r_rev.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"

        r_susp = await c.get("/api/v1/agents", headers=headers_suspended)
        assert r_susp.status_code == 403
        assert r_susp.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_inactive_user_token_rejected_on_agent_routes(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify deactivated/inactive user account is denied access with 401 Unauthorized."""
    # user-inactive-005 has status='INACTIVE'
    inactive_token = create_token_for(
        "user-inactive-005", "inactive@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings
    )
    headers = {"Authorization": f"Bearer {inactive_token}"}

    async with client as c:
        r = await c.get("/api/v1/agents", headers=headers)
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_branch_scoping_isolation_and_rejection(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify branch scoping: a branch-restricted caller cannot see or retrieve other branch agents."""
    from backend.app.tenancy.context import TenantContext

    now = datetime.now(timezone.utc)
    # Seed Branch Karachi agent
    agent_karachi = AgentEntity(
        id="agent-karachi-001",
        tenant_id=TENANT_A_ID,
        name="Karachi Ops Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Karachi Prompt",
        branch_id="branch-karachi-99",
        created_at=now,
        updated_at=now,
    )
    ver_karachi = AgentVersionEntity(
        id="ver-karachi-001",
        tenant_id=TENANT_A_ID,
        agent_id="agent-karachi-001",
        version="v1.0.0",
        config_payload={},
        created_at=now,
    )
    await isolated_agent_repo.create_agent_atomic(agent_karachi, ver_karachi)

    # Seed Branch Lahore agent
    agent_lahore = AgentEntity(
        id="agent-lahore-002",
        tenant_id=TENANT_A_ID,
        name="Lahore Ops Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Lahore Prompt",
        branch_id="branch-lahore-88",
        created_at=now,
        updated_at=now,
    )
    ver_lahore = AgentVersionEntity(
        id="ver-lahore-002",
        tenant_id=TENANT_A_ID,
        agent_id="agent-lahore-002",
        version="v1.0.0",
        config_payload={},
        created_at=now,
    )
    await isolated_agent_repo.create_agent_atomic(agent_lahore, ver_lahore)

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate caller context with Branch Karachi restriction
    branch_karachi_context = TenantContext(
        tenant_id=TENANT_A_ID,
        tenant_slug="company-a",
        tenant_name="Company A",
        user_id=USER_A_DEV_ID,
        role="AI_DEVELOPER",
        is_active=True,
    )
    # Dynamically inject branch_id onto the context (M4 integration contract)
    object.__setattr__(branch_karachi_context, "branch_id", "branch-karachi-99")

    from backend.app.core.dependencies import get_tenant_context
    app = client._transport.app  # type: ignore
    app.dependency_overrides[get_tenant_context] = lambda: branch_karachi_context

    try:
        async with client as c:
            # 1. Listing with branch restriction returns ONLY Branch Karachi agents
            r_list = await c.get("/api/v1/agents", headers=headers)
            assert r_list.status_code == 200
            items = r_list.json()["items"]
            assert len(items) == 1
            assert items[0]["id"] == "agent-karachi-001"

            # 2. Accessing Lahore agent by ID returns 404 (cross-branch denied)
            r_cross = await c.get("/api/v1/agents/agent-lahore-002", headers=headers)
            assert r_cross.status_code == 404
            assert r_cross.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

            # 3. Accessing Karachi agent by ID succeeds
            r_ok = await c.get("/api/v1/agents/agent-karachi-001", headers=headers)
            assert r_ok.status_code == 200
            assert r_ok.json()["id"] == "agent-karachi-001"
    finally:
        app.dependency_overrides.pop(get_tenant_context, None)


@pytest.mark.asyncio
async def test_production_mode_fails_closed_without_persistent_repository(test_settings: Settings):
    """Verify that in production (APP_ENV=production), endpoint fails closed if persistent repo is not configured."""
    from backend.app.tenancy.context import MembershipRecord, TenantRecord, UserRecord

    class MockPersistentAuthRepo:
        is_demo = False
        is_persistent = True
        is_in_memory = False

        async def get_user_by_id(self, uid):
            return UserRecord(id=uid, email="developer@company-a.com", hashed_password="hash", full_name="Dave", status="ACTIVE")

        async def get_tenant_by_id(self, tid):
            return TenantRecord(id=tid, name="Company A", slug="company-a", status="ACTIVE")

        async def get_membership(self, uid, tid):
            return MembershipRecord(id="mem-001", tenant_id=tid, user_id=uid, role="AI_DEVELOPER", status="ACTIVE")

    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="super-secure-production-jwt-secret-with-more-than-32-chars",
        CORS_ORIGINS=["https://app.company-a.com"],
        DATABASE_URL="postgresql+asyncpg://user:pass@db.prod.internal:5432/amsc",
        REDIS_URL="redis://redis.prod.internal:6379/0",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
    )
    prod_app = create_app(settings=prod_settings)
    # Attach persistent mocks for auth, memory, and rate_limiter so lifespan succeeds
    prod_app.state.auth_repo = MockPersistentAuthRepo()
    prod_app.state.rate_limiter = object()
    from backend.app.memory.tests.test_service import MockPersistentMemoryRepository
    prod_app.state.memory_repo = MockPersistentMemoryRepository()
    # agent_repo remains None (unconfigured persistent M6 database repo)
    prod_app.state.agent_repo = None

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", prod_settings)
    headers = {"Authorization": f"Bearer {token}"}

    transport = httpx.ASGITransport(app=prod_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/api/v1/agents", headers=headers)
        # Must fail closed with 503 SECURITY_DEPENDENCY_UNAVAILABLE
        assert response.status_code == 503
        data = response.json()
        assert data["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"
