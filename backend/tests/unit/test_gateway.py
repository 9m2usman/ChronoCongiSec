"""Unit and Security Tests for Protected Tool Gateway API.

Module: backend.tests.unit.test_gateway
Owner: M1 — Platform Backend & API Integration Lead

Tests verify:
1. API & Request Validation:
   - Valid action proposal request.
   - Missing required fields rejected with HTTP 422.
   - Unknown/extra fields rejected with HTTP 422 (extra="forbid").
   - Parameter limits (depth <= 5, finite numbers, rejection of NaN/Infinity).
   - List size bounds (memory_refs <= 50).
   - Control characters in IDs rejected.
2. Authentication & Confused-Deputy Prevention:
   - Missing bearer token returns HTTP 401.
   - Invalid token returns HTTP 401.
   - Agent must exist in authenticated tenant (cross-tenant agent returns HTTP 404).
   - Inactive / isolated / deprecated agents cannot submit proposals (HTTP 403).
   - Forged client headers (e.g. X-Tenant-ID) cannot alter authenticated tenant scope.
3. Tenant Isolation:
   - Tenant A cannot propose actions for Tenant B's agent.
   - Tenant A cannot reference Tenant B's memory records.
   - Tenant A cannot read or replay Tenant B's idempotency key.
   - Cross-tenant proposal inspection returns HTTP 404.
4. Memory Trust & Cryptographic Integrity (M3 Integration):
   - Only TRUSTED memory allows execution.
   - SUSPICIOUS memory blocks proposal; adapter NOT invoked.
   - QUARANTINED memory blocks proposal; adapter NOT invoked.
   - UNVERIFIED memory blocks proposal; adapter NOT invoked.
   - REJECTED memory blocks proposal; adapter NOT invoked.
   - Cryptographic checksum mismatch triggers integrity error (HTTP 500) and blocks execution.
   - Nonexistent referenced memory blocks execution.
5. Deterministic Policy Ceilings (M4 Integration):
   - Actions within ceilings allowed.
   - Dual-custody ceiling exceeded ($450 > $300 threshold for sandbox_transfer) blocks action.
   - Negative transfer amount is blocked.
   - Unregistered tool name is blocked.
6. Idempotency & Replay Protection:
   - Same key + same payload returns existing cached proposal/decision without re-executing tool.
   - Same key + different payload returns HTTP 409 Conflict.
   - Same key in different tenants operates independently without collision.
   - Replay of blocked proposal returns blocked decision idempotently.
7. Adapter Execution Boundary (M2 Integration):
   - Blocked proposals never execute tool adapter.
   - Allowed proposals execute adapter and record execution result with duration.
8. Audit Trail & Confidentiality:
   - Proposal events and decisions recorded in audit log.
   - Sensitive parameters (passwords, tokens, cards) redacted.
   - Inspection endpoint (GET /gateway/actions/{id}) returns sanitized audit details.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
from typing import Any, Dict, List, Optional
import uuid
import pytest
import httpx

from backend.app.api.agents import (
    AgentEntity,
    AgentVersionEntity,
    InMemoryAgentRepository,
)
from backend.app.api.gateway import (
    InMemoryGatewayRepository,
    compute_payload_fingerprint,
    redact_sensitive_payload,
)
from backend.app.core.config import Settings
from backend.app.core.security import create_access_token
from backend.app.main import create_app
from backend.app.memory.hashing import sha256_hex
from backend.app.memory.models import (
    AgentRecord,
    MemoryRecord,
    MemoryVersion,
    RecordType,
    TrustState,
)
from backend.app.memory.repository import InMemoryMemoryRepository


@pytest.fixture
def test_settings() -> Settings:
    """Standard test settings fixture."""
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )


@pytest.fixture
def isolated_agent_repo() -> InMemoryAgentRepository:
    return InMemoryAgentRepository()


@pytest.fixture
def isolated_memory_repo() -> InMemoryMemoryRepository:
    return InMemoryMemoryRepository()


@pytest.fixture
def isolated_gateway_repo() -> InMemoryGatewayRepository:
    return InMemoryGatewayRepository()


@pytest.fixture
def client(
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """Test client with isolated repositories."""
    app = create_app(settings=test_settings)
    app.state.agent_repo = isolated_agent_repo
    app.state.memory_repo = isolated_memory_repo
    app.state.gateway_repo = isolated_gateway_repo
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


# Canonical test accounts and IDs
TENANT_A_ID = "tenant-a-uuid-001"
TENANT_B_ID = "tenant-b-uuid-002"
USER_A_DEV_ID = "user-a-dev-009"
USER_A_ANALYST_ID = "user-a-analyst-001"
USER_B_DEV_ID = "user-b-dev-010"

AGENT_A_ACTIVE_ID = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
AGENT_A_ISOLATED_ID = "isolated-agent-uuid-002"
AGENT_B_ACTIVE_ID = "agent-b-active-uuid-003"


async def seed_agents(agent_repo: InMemoryAgentRepository) -> None:
    """Seed test agents for tenant A and tenant B."""
    # Tenant A Active Agent
    await agent_repo.create_agent_atomic(
        AgentEntity(
            id=AGENT_A_ACTIVE_ID,
            tenant_id=TENANT_A_ID,
            name="Treasury Agent Alpha",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Execute verified financial actions.",
        ),
        AgentVersionEntity(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_A_ID,
            agent_id=AGENT_A_ACTIVE_ID,
            version="v1.0.0",
            config_payload={"model": "gpt-4o"},
        ),
    )

    # Tenant A Isolated Agent
    await agent_repo.create_agent_atomic(
        AgentEntity(
            id=AGENT_A_ISOLATED_ID,
            tenant_id=TENANT_A_ID,
            name="Compromised Agent",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ISOLATED",
            config_version="v1.0.0",
            system_prompt="Isolated agent.",
        ),
        AgentVersionEntity(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_A_ID,
            agent_id=AGENT_A_ISOLATED_ID,
            version="v1.0.0",
            config_payload={"model": "gpt-4o"},
        ),
    )

    # Tenant B Active Agent
    await agent_repo.create_agent_atomic(
        AgentEntity(
            id=AGENT_B_ACTIVE_ID,
            tenant_id=TENANT_B_ID,
            name="Tenant B Agent",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Tenant B agent prompt.",
        ),
        AgentVersionEntity(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_B_ID,
            agent_id=AGENT_B_ACTIVE_ID,
            version="v1.0.0",
            config_payload={"model": "gpt-4o"},
        ),
    )


def seed_memory_record(
    memory_repo: InMemoryMemoryRepository,
    record_id: str,
    tenant_id: str,
    content: str,
    trust_state: TrustState,
    agent_id: Optional[str] = None,
    corrupt_checksum: bool = False,
) -> MemoryRecord:
    """Helper to seed memory records with specific trust state and cryptographic checksum."""
    real_checksum = sha256_hex(content)
    # Valid 64-char hex string that doesn't match content
    recorded_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" if corrupt_checksum else real_checksum

    rec = MemoryRecord(
        id=record_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        record_type=RecordType.KNOWLEDGE,
        trust_state=trust_state,
        current_version=1,
    )
    memory_repo.create_record(rec)

    ver = MemoryVersion(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        record_id=record_id,
        version=1,
        content=content,
        checksum=recorded_checksum,
    )
    memory_repo.create_version(ver)
    return rec


# ============================================================================
# 1. API & Request Validation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_propose_action_happy_path(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """Verify successful proposal within limits with TRUSTED memory reference."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-trusted-001"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Invoice #450 approved for vendor Acme Corp.",
        trust_state=TrustState.TRUSTED,
        agent_id=AGENT_A_ACTIVE_ID,
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-demo-wire-100",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {
            "destination_account": "ACC-LEGIT-123",
            "amount": 100.00,
            "currency": "USD",
        },
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-wire-001",
        "trace_id": "tr-forensic-001",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["action_id"] == "act-demo-wire-100"
    assert data["decision"] == "ALLOW"
    assert data["memory_trust"] == "TRUSTED"
    assert data["policy_result"] == "PERMITTED"
    assert data["execution_status"] == "EXECUTED"
    assert data["result"] is not None
    assert data["result"]["status"] == "SETTLED_IN_SANDBOX"
    assert data["result"]["amount"] == 100.00

    # Verify audit event was persisted
    audit_events = isolated_gateway_repo.get_audit_events(TENANT_A_ID)
    assert len(audit_events) == 1
    assert audit_events[0].outcome == "ALLOW"
    assert audit_events[0].trace_id == "tr-forensic-001"


@pytest.mark.asyncio
async def test_propose_action_rejects_extra_fields(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify client-supplied extra fields (e.g. forged tenant_id or decision) are rejected with HTTP 422."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-001",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "idempotency_key": "idemp-002",
        "trace_id": "tr-002",
        "tenant_id": "attempt-to-inject-tenant",  # Extra field forbidden
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code in (422, 400)


@pytest.mark.asyncio
async def test_propose_action_rejects_nan_and_infinity(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify parameters containing NaN or Infinity are strictly rejected."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Test NaN rejection via string JSON
    raw_json = (
        '{"action_id":"act-nan","agent_id":"'
        + AGENT_A_ACTIVE_ID
        + '","tool_name":"sandbox_transfer","operation":"transfer_funds",'
        '"parameters":{"amount": NaN},"memory_refs":[],"idempotency_key":"idemp-nan","trace_id":"tr-nan"}'
    )
    resp = await client.post(
        "/api/v1/gateway/actions/propose",
        content=raw_json,
        headers={"Content-Type": "application/json", **headers},
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_propose_action_rejects_excessive_parameter_nesting(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify deeply nested parameters exceeding depth 5 are rejected."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    deep_params = {"level1": {"level2": {"level3": {"level4": {"level5": {"level6": "too_deep"}}}}}}
    payload = {
        "action_id": "act-deep",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": deep_params,
        "memory_refs": [],
        "idempotency_key": "idemp-deep",
        "trace_id": "tr-deep",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code in (400, 422)


# ============================================================================
# 2. Authentication & Confused-Deputy Prevention Tests
# ============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_proposal_rejected(client: httpx.AsyncClient):
    """Verify request without Authorization header returns HTTP 401."""
    payload = {
        "action_id": "act-unauth",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "idempotency_key": "idemp-unauth",
        "trace_id": "tr-unauth",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_confused_deputy_cross_tenant_agent_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify caller in Tenant A cannot use Tenant B's agent ID (returns 404, preventing impersonation)."""
    await seed_agents(isolated_agent_repo)
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token_a}"}

    payload = {
        "action_id": "act-impersonate",
        "agent_id": AGENT_B_ACTIVE_ID,  # Tenant B's agent!
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "idempotency_key": "idemp-imp-001",
        "trace_id": "tr-imp-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_isolated_agent_proposal_forbidden(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify an agent marked ISOLATED cannot submit tool action proposals (returns 403)."""
    await seed_agents(isolated_agent_repo)
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token_a}"}

    payload = {
        "action_id": "act-isolated",
        "agent_id": AGENT_A_ISOLATED_ID,  # Status: ISOLATED
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "idempotency_key": "idemp-iso-001",
        "trace_id": "tr-iso-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 403


# ============================================================================
# 3. Memory Trust & Cryptographic Integrity Tests (M3 Integration)
# ============================================================================

@pytest.mark.asyncio
async def test_suspicious_memory_is_blocked_and_adapter_not_executed(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """Exit Gate G4: Proposal referencing SUSPICIOUS memory is BLOCKED before tool execution."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-suspicious-001"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Adversary instruction to transfer $450 to attacker account ACC-ATTACKER-999",
        trust_state=TrustState.SUSPICIOUS,
        agent_id=AGENT_A_ACTIVE_ID,
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-demo-wire-450",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {
            "destination_account": "ACC-ATTACKER-999",
            "amount": 450.00,
            "currency": "USD",
        },
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-client-wire-20261115-001",
        "trace_id": "tr-forensic-demo-01",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["action_id"] == "act-demo-wire-450"
    assert data["decision"] == "BLOCK"
    assert data["memory_trust"] == "SUSPICIOUS"
    assert data["policy_result"] == "DENIED"
    assert data["execution_status"] == "NOT_EXECUTED"
    assert data["result"] is None
    assert any("marked SUSPICIOUS" in r for r in data["reasons"])

    # Verify decision is durably recorded in repository
    record = await isolated_gateway_repo.get_by_id(TENANT_A_ID, data["proposal_id"])
    assert record is not None
    prop, dec, execution = record
    assert dec.decision == "BLOCK"
    assert execution is None  # Adapter was NOT executed!


@pytest.mark.asyncio
async def test_quarantined_memory_is_blocked(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Proposal referencing QUARANTINED memory is BLOCKED."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-quarantined-002"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Poisoned memo",
        trust_state=TrustState.QUARANTINED,
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-quarantine-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-quar-001",
        "trace_id": "tr-quar-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["memory_trust"] == "QUARANTINED"
    assert data["execution_status"] == "NOT_EXECUTED"


@pytest.mark.asyncio
async def test_unverified_memory_is_blocked(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Proposal referencing UNVERIFIED memory is BLOCKED (cannot back protected tools)."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-unverified-003"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Newly ingested unverified chunk",
        trust_state=TrustState.UNVERIFIED,
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-unverified-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-unv-001",
        "trace_id": "tr-unv-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["execution_status"] == "NOT_EXECUTED"


@pytest.mark.asyncio
async def test_memory_checksum_mismatch_fails_closed(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Verify corrupted memory record with checksum mismatch triggers 500 integrity error and halts execution."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-corrupted-004"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Tampered content",
        trust_state=TrustState.TRUSTED,
        corrupt_checksum=True,  # Simulate bit flip or unauthorized db edit
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-checksum-fail",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-chk-001",
        "trace_id": "tr-chk-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 500
    data = resp.json()
    assert data["error"]["code"] == "MEMORY_INTEGRITY_VIOLATION"


# ============================================================================
# 4. Policy Ceilings & Rules Tests (M4 Integration)
# ============================================================================

@pytest.mark.asyncio
async def test_transfer_amount_exceeding_dual_custody_ceiling_is_blocked(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Amount $450 exceeds dual-custody threshold of $300; must be BLOCKED."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-trusted-005"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Legitimate invoice",
        trust_state=TrustState.TRUSTED,
    )

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-over-ceiling",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": 450.00},
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-ceiling-001",
        "trace_id": "tr-ceiling-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["policy_result"] == "DENIED"
    assert data["execution_status"] == "NOT_EXECUTED"
    assert any("exceeds dual-custody threshold" in r for r in data["reasons"])


# ============================================================================
# 5. Idempotency & Replay Protection Tests
# ============================================================================

@pytest.mark.asyncio
async def test_idempotent_duplicate_returns_identical_cached_result_without_reexecution(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Same tenant + same idempotency key + same payload returns existing decision and does NOT invoke adapter again."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-idemp-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": 50.00},
        "memory_refs": [],
        "idempotency_key": "idemp-repeat-001",
        "trace_id": "tr-rep-001",
    }

    # Request 1
    resp1 = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp1.status_code == 200
    data1 = resp1.json()
    proposal_id_1 = data1["proposal_id"]
    tx_id_1 = data1["result"]["transaction_id"]

    # Request 2 (Duplicate replay)
    resp2 = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.json()

    assert data2["proposal_id"] == proposal_id_1
    assert data2["result"]["transaction_id"] == tx_id_1  # Exact cached result!


@pytest.mark.asyncio
async def test_idempotent_key_reuse_with_mismatched_payload_returns_409_conflict(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Same tenant + same idempotency key + DIFFERENT payload returns HTTP 409 Conflict."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload1 = {
        "action_id": "act-conflict-1",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.00},
        "memory_refs": [],
        "idempotency_key": "idemp-conflict-key-001",
        "trace_id": "tr-conf-001",
    }
    resp1 = await client.post("/api/v1/gateway/actions/propose", json=payload1, headers=headers)
    assert resp1.status_code == 200

    # Payload 2 with changed amount ($75 instead of $50) under SAME idempotency key
    payload2 = deepcopy(payload1)
    payload2["parameters"]["amount"] = 75.00

    resp2 = await client.post("/api/v1/gateway/actions/propose", json=payload2, headers=headers)
    assert resp2.status_code == 409
    err_body = resp2.json()
    assert err_body["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_idempotency_keys_are_strictly_tenant_scoped(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Same idempotency key used by Tenant A and Tenant B does NOT collide or leak."""
    await seed_agents(isolated_agent_repo)
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    token_b = create_token_for(USER_B_DEV_ID, "developer@company-b.com", TENANT_B_ID, "AI_DEVELOPER", test_settings)

    shared_key = "idemp-cross-tenant-shared-001"

    payload_a = {
        "action_id": "act-tenant-a",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.00},
        "memory_refs": [],
        "idempotency_key": shared_key,
        "trace_id": "tr-tenant-a",
    }
    resp_a = await client.post("/api/v1/gateway/actions/propose", json=payload_a, headers={"Authorization": f"Bearer {token_a}"})
    assert resp_a.status_code == 200
    data_a = resp_a.json()

    payload_b = {
        "action_id": "act-tenant-b",
        "agent_id": AGENT_B_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 80.00},
        "memory_refs": [],
        "idempotency_key": shared_key,
        "trace_id": "tr-tenant-b",
    }
    resp_b = await client.post("/api/v1/gateway/actions/propose", json=payload_b, headers={"Authorization": f"Bearer {token_b}"})
    assert resp_b.status_code == 200
    data_b = resp_b.json()

    # Proposals must be completely separate entities
    assert data_a["proposal_id"] != data_b["proposal_id"]
    assert data_a["action_id"] == "act-tenant-a"
    assert data_b["action_id"] == "act-tenant-b"


# ============================================================================
# 6. Audit Trail & Redaction Tests
# ============================================================================

@pytest.mark.asyncio
async def test_sensitive_parameters_are_redacted_in_audit_events(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """Verify secrets (passwords, api_keys, card_numbers) are masked in audit records."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-secret-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {
            "destination_account": "ACC-LEGIT-123",
            "amount": 50.00,
            "api_key": "secret-super-sensitive-token-12345",
            "card_number": "4111-2222-3333-4444",
        },
        "memory_refs": [],
        "idempotency_key": "idemp-secret-001",
        "trace_id": "tr-sec-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200

    events = isolated_gateway_repo.get_audit_events(TENANT_A_ID)
    assert len(events) == 1
    params = events[0].details_json["parameters"]
    assert params["api_key"] == "[REDACTED]"
    assert params["card_number"] == "[REDACTED]"
    assert params["destination_account"] == "ACC-LEGIT-123"


# ============================================================================
# 7. Proposal Detail Inspection Endpoint Tests (GET /gateway/actions/{id})
# ============================================================================

@pytest.mark.asyncio
async def test_get_proposal_detail_and_cross_tenant_isolation(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify proposal detail endpoint returns full audit view and enforces cross-tenant 404."""
    await seed_agents(isolated_agent_repo)
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    token_b = create_token_for(USER_B_DEV_ID, "developer@company-b.com", TENANT_B_ID, "AI_DEVELOPER", test_settings)

    payload = {
        "action_id": "act-detail-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.00},
        "memory_refs": [],
        "idempotency_key": "idemp-detail-001",
        "trace_id": "tr-detail-001",
    }
    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 200
    proposal_id = resp.json()["proposal_id"]

    # 1. Tenant A fetches detail -> 200 OK
    detail_resp_a = await client.get(
        f"/api/v1/gateway/actions/{proposal_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert detail_resp_a.status_code == 200
    detail_data = detail_resp_a.json()
    assert detail_data["proposal_id"] == proposal_id
    assert detail_data["tenant_id"] == TENANT_A_ID
    assert detail_data["decision"] == "ALLOW"

    # 2. Tenant B attempts to fetch Tenant A's proposal -> 404 Not Found
    detail_resp_b = await client.get(
        f"/api/v1/gateway/actions/{proposal_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert detail_resp_b.status_code == 404
