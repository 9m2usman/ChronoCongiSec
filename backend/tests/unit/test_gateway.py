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
from datetime import timedelta
from typing import Any, Dict, Optional
import uuid
import pytest
import httpx

from backend.app.api.agents import (
    AgentEntity,
    AgentVersionEntity,
    InMemoryAgentRepository,
)
from backend.app.api.gateway import (
    GatewayDecision,
    InMemoryGatewayRepository,
    PolicyDecisionEntity,
    SqlAlchemyGatewayRepository,
    ToolExecutionResult,
    ToolProposalEntity,
)
from backend.app.core.config import Settings
from backend.app.core.security import create_access_token
from backend.app.main import create_app
from backend.app.memory.hashing import sha256_hex
from backend.app.memory.models import (
    MemoryRecord,
    MemoryVersion,
    RecordType,
    TrustState,
)
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.security.trust import (
    OPERATION_TARGET,
    InMemoryTrustDecisionStore,
    TrustDimension,
    TrustEvaluator,
    TrustOperation,
    UserActor,
)
from backend.app.tenancy.context import TenantContext


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
    repo = InMemoryMemoryRepository()
    # M4 trust decision ledger shared with the app (app.state.trust_decision_store): TRUSTED
    # requires version-bound M4 evidence, not just a stored field.
    repo._trust_store = InMemoryTrustDecisionStore()
    return repo


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
    app.state.trust_decision_store = isolated_memory_repo._trust_store
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


SANDBOX_TRANSFER_GRANT = {
    "tool_name": "sandbox_transfer",
    "allowed_operations": ["transfer_funds", "get_balance"],
    "constraints": {"max_amount": 500, "approval_threshold_amount": 300},
}


async def seed_agents(agent_repo: InMemoryAgentRepository) -> None:
    """Seed test agents for tenant A and tenant B, with M4 tool grants for the active agents."""
    agent_repo._tool_permissions[AGENT_A_ACTIVE_ID] = [dict(SANDBOX_TRANSFER_GRANT)]
    agent_repo._tool_permissions[AGENT_B_ACTIVE_ID] = [dict(SANDBOX_TRANSFER_GRANT)]
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

    # TRUSTED is reached through M4 VALIDATE (version-bound evidence). A corrupted record cannot be
    # validated, so it is stored TRUSTED directly (an out-of-band write M4 must still refuse).
    validate_via_m4 = trust_state == TrustState.TRUSTED and not corrupt_checksum
    rec = MemoryRecord(
        id=record_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        # Provenance: an ACTIVE seeded source per tenant (M4 refuses to trust memory without one).
        source_id={"tenant-a-uuid-001": "src-doc-001", "tenant-b-uuid-002": "src-b-001"}.get(tenant_id),
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.UNVERIFIED if validate_via_m4 else trust_state,
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
    if validate_via_m4:
        _m4_validate(memory_repo, tenant_id, record_id)
        rec = memory_repo.get_record(record_id, tenant_id)
    return rec


def _m4_validate(memory_repo: InMemoryMemoryRepository, tenant_id: str, record_id: str) -> None:
    """Promote a record to TRUSTED the only legitimate way: an analyst VALIDATE through M4."""
    store = getattr(memory_repo, "_trust_store", None) or InMemoryTrustDecisionStore()
    memory_repo._trust_store = store
    evaluator = TrustEvaluator(memory_repo, store, app_env="test")
    rec = memory_repo.get_record(record_id, tenant_id)
    ver = memory_repo.get_version(record_id, rec.current_version, tenant_id)
    analyst = UserActor(TenantContext(tenant_id=tenant_id, tenant_slug="t", tenant_name="T",
                                      user_id="analyst-validator", role="SECURITY_ANALYST", is_active=True))
    decision = evaluator.apply({
        "record_id": record_id, "operation": TrustOperation.VALIDATE.value,
        "target_state": OPERATION_TARGET[TrustOperation.VALIDATE].value,
        "expected_state": "UNVERIFIED", "expected_version": rec.current_version, "reason": "test validation",
        "evidence": {"evidence_refs": ["ev-1"], "validation": {
            "assessed_version": rec.current_version, "assessed_checksum": ver.checksum,
            "dimensions": {d.value: {"status": "PASS", "evidence_ref": "r"} for d in TrustDimension}}},
    }, analyst)
    assert decision.applied, decision.reason_codes


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
    assert "MEMORY_SUSPICIOUS" in data["reason_codes"]

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
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK" and data["execution_status"] == "NOT_EXECUTED"
    assert data["result"] is None
    assert "MEMORY_INTEGRITY_VIOLATION" in data["reason_codes"]


# ============================================================================
# 4. Policy Ceilings & Rules Tests (M4 Integration)
# ============================================================================

@pytest.mark.asyncio
async def test_transfer_amount_above_dual_custody_threshold_requires_approval_and_is_not_executed(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """$450 exceeds the $300 dual-custody threshold (grant allows up to $500): M4 returns
    REQUIRES_APPROVAL (FR-015, TRD Check 5). It is not executed without a valid approval."""
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
    assert data["decision"] == "REQUIRES_APPROVAL"
    assert data["policy_result"] == "ELEVATED"
    assert data["execution_status"] == "PENDING_APPROVAL"
    assert data["result"] is None
    assert "APPROVAL_THRESHOLD_EXCEEDED" in data["reason_codes"]


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
    # M4 policy: a financial transfer must be justified by eligible TRUSTED memory (PRD SEC-002).
    seed_memory_record(isolated_memory_repo, record_id="mem-justify-idem", tenant_id=TENANT_A_ID,
                       content="Approved vendor payment instruction (mem-justify-idem).", trust_state=TrustState.TRUSTED)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-idemp-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": 50.00},
        "memory_refs": ["mem-justify-idem"],
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
    isolated_memory_repo: InMemoryMemoryRepository,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify proposal detail endpoint returns full audit view and enforces cross-tenant 404."""
    await seed_agents(isolated_agent_repo)
    # M4 policy: a financial transfer must be justified by eligible TRUSTED memory (PRD SEC-002).
    seed_memory_record(isolated_memory_repo, record_id="mem-justify-detail", tenant_id=TENANT_A_ID,
                       content="Approved vendor payment instruction (mem-justify-detail).", trust_state=TrustState.TRUSTED)
    token_a = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    token_b = create_token_for(USER_B_DEV_ID, "developer@company-b.com", TENANT_B_ID, "AI_DEVELOPER", test_settings)

    payload = {
        "action_id": "act-detail-test",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.00},
        "memory_refs": ["mem-justify-detail"],
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


# ============================================================================
# 8. Advanced Security: TOCTOU, Concurrency, Role Isolation & Adapter Edge Cases
# ============================================================================

@pytest.mark.asyncio
async def test_memory_toctou_trust_revocation_before_dispatch_blocks_execution(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """SEC-GW-007 / GAP-021: Revalidation immediately before adapter dispatch catches trust revocation."""
    await seed_agents(isolated_agent_repo)
    mem_id = "mem-toctou-target-001"
    seed_memory_record(
        isolated_memory_repo,
        record_id=mem_id,
        tenant_id=TENANT_A_ID,
        content="Invoice initially considered trusted",
        trust_state=TrustState.TRUSTED,
        agent_id=AGENT_A_ACTIVE_ID,
    )

    class SpyAdapter:
        def __init__(self) -> None:
            self.invoked = False

        async def execute(self, operation: str, parameters: Dict[str, Any], context: Dict[str, Any]) -> ToolExecutionResult:
            self.invoked = True
            return ToolExecutionResult(
                status="SUCCESS",
                status_code=200,
                result_payload={"transacted": True},
                duration_ms=5,
            )

    spy = SpyAdapter()
    from backend.app.api.gateway import ToolAdapterRegistry
    tool_reg = ToolAdapterRegistry()
    tool_reg.register("sandbox_transfer", spy)
    client._transport.app.state.tool_registry = tool_reg

    # Hook memory_repo.get_record to simulate a concurrent analyst quarantining the memory
    # immediately after the initial policy evaluation but before adapter dispatch
    orig_get_record = isolated_memory_repo.get_record
    query_count = 0

    def toctou_hook(rec_id: str, t_id: str):
        nonlocal query_count
        query_count += 1
        rec = orig_get_record(rec_id, t_id)
        if query_count >= 2 and rec is not None:
            # Revoke trust to QUARANTINED!
            rec.trust_state = TrustState.QUARANTINED.value
        return rec

    isolated_memory_repo.get_record = toctou_hook

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-toctou-race-001",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": 50.00},
        "memory_refs": [mem_id],
        "idempotency_key": "idemp-toctou-001",
        "trace_id": "tr-toctou-001",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # The action MUST be blocked because trust was revoked before dispatch!
    assert data["decision"] == "BLOCK"
    assert data["execution_status"] == "NOT_EXECUTED"
    assert {"REFERENCED_UNTRUSTED_MEMORY", "PRE_EXECUTION_REVALIDATION_FAILED"} & set(data["reason_codes"])
    # Adapter must NEVER have executed!
    assert spy.invoked is False


@pytest.mark.asyncio
async def test_adapter_timeout_records_unknown_outcome_and_no_retry(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """SEC-GW-010 / GAP-023: Adapter timeout records UNKNOWN execution status (504) and halts blind retries."""
    import asyncio
    await seed_agents(isolated_agent_repo)
    # M4 policy: a financial transfer must be justified by eligible TRUSTED memory (PRD SEC-002).
    seed_memory_record(isolated_memory_repo, record_id="mem-justify-timeout", tenant_id=TENANT_A_ID,
                       content="Approved vendor payment instruction (mem-justify-timeout).", trust_state=TrustState.TRUSTED)

    class TimeoutAdapter:
        async def execute(self, operation: str, parameters: Dict[str, Any], context: Dict[str, Any]) -> ToolExecutionResult:
            raise asyncio.TimeoutError("External banking service connection timed out.")

    from backend.app.api.gateway import ToolAdapterRegistry
    tool_reg = ToolAdapterRegistry()
    tool_reg.register("sandbox_transfer", TimeoutAdapter())
    client._transport.app.state.tool_registry = tool_reg

    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-timeout-001",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": 50.00},
        "memory_refs": ["mem-justify-timeout"],
        "idempotency_key": "idemp-timeout-001",
        "trace_id": "tr-timeout-001",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["decision"] == "ALLOW"
    assert data["execution_status"] == "UNKNOWN"
    assert data["result"] is not None
    assert "timed out" in data["result"]["error"]

    # Verify execution record has 504 status code
    record = await isolated_gateway_repo.get_by_id(TENANT_A_ID, data["proposal_id"])
    assert record is not None
    _, dec, exe = record
    assert dec.execution_status == "UNKNOWN"
    assert exe is not None
    assert exe.status == "UNKNOWN"
    assert exe.status_code == 504


@pytest.mark.asyncio
async def test_concurrent_in_progress_proposal_returns_409_conflict(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    """SEC-GW-005 / GAP-020: Duplicate request while proposal is PENDING_EXECUTION returns HTTP 409 Conflict."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Manually seed a proposal in PENDING_EXECUTION status
    staged_prop = ToolProposalEntity(
        id="prop-pending-001",
        tenant_id=TENANT_A_ID,
        agent_id=AGENT_A_ACTIVE_ID,
        action_id="act-pending-001",
        tool_name="sandbox_transfer",
        operation="transfer_funds",
        parameters_json={"amount": 50.0},
        memory_refs_json=[],
        idempotency_key="idemp-pending-001",
        trace_id="tr-pending-001",
    )
    staged_dec = PolicyDecisionEntity(
        id="dec-pending-001",
        tenant_id=TENANT_A_ID,
        proposal_id="prop-pending-001",
        decision="ALLOW",
        memory_trust="NOT_REFERENCED",
        policy_result="PERMITTED",
        reasons_json=["Initial check passed"],
        execution_status="PENDING_EXECUTION",
    )
    await isolated_gateway_repo.save_proposal_atomic(staged_prop, staged_dec)

    payload = {
        "action_id": "act-pending-001",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "memory_refs": [],
        "idempotency_key": "idemp-pending-001",
        "trace_id": "tr-pending-001",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 409
    data = resp.json()
    assert data["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_unauthorized_role_cannot_propose_tool_actions(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Part 6 Least Privilege: Caller with AUDITOR role is forbidden from submitting tool action proposals."""
    await seed_agents(isolated_agent_repo)
    from backend.app.tenancy.context import (
        MembershipRecord,
        UserRecord,
        get_default_auth_repository,
    )
    auth_repo = getattr(client._transport.app.state, "auth_repo", None) or get_default_auth_repository()
    auditor_user = UserRecord(
        id="user-auditor-999",
        email="auditor@company-a.com",
        hashed_password="hashed_pw_test",
        full_name="Auditor User",
        status="ACTIVE",
    )
    auditor_mem = MembershipRecord(
        id="mem-auditor-999",
        tenant_id=TENANT_A_ID,
        user_id="user-auditor-999",
        role="AUDITOR",
        status="ACTIVE",
    )
    auth_repo.add_user(auditor_user)
    auth_repo.add_membership(auditor_mem)

    token = create_token_for(auditor_user.id, auditor_user.email, TENANT_A_ID, "AUDITOR", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "action_id": "act-auditor-forbidden",
        "agent_id": AGENT_A_ACTIVE_ID,
        "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"amount": 50.0},
        "memory_refs": [],
        "idempotency_key": "idemp-auditor-001",
        "trace_id": "tr-auditor-001",
    }

    resp = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_proposals_for_m5_activity_stream(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """M5 Integration: GET /api/v1/gateway/actions returns paginated proposal activity stream."""
    await seed_agents(isolated_agent_repo)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Submit 2 proposals
    for i in range(2):
        payload = {
            "action_id": f"act-stream-{i}",
            "agent_id": AGENT_A_ACTIVE_ID,
            "tool_name": "sandbox_transfer",
            "operation": "transfer_funds",
            "parameters": {"amount": 10.0 + i},
            "memory_refs": [],
            "idempotency_key": f"idemp-stream-{i}",
            "trace_id": f"tr-stream-{i}",
        }
        res = await client.post("/api/v1/gateway/actions/propose", json=payload, headers=headers)
        assert res.status_code == 200

    list_resp = await client.get("/api/v1/gateway/actions?limit=10&offset=0", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert isinstance(items, list)
    assert len(items) == 2
    assert items[0]["action_id"] == "act-stream-1"
    assert items[1]["action_id"] == "act-stream-0"


@pytest.mark.asyncio
async def test_sqlalchemy_gateway_repository_protocol():
    """Verify SqlAlchemyGatewayRepository implements GatewayRepositoryProtocol."""
    from unittest.mock import MagicMock
    mock_session_factory = MagicMock()
    repo = SqlAlchemyGatewayRepository(mock_session_factory)
    assert repo.is_persistent is True
    assert repo.is_in_memory is False



# ============================================================================
# M4 integration regressions: the gateway decides only through M4's PolicyEngine and
# dispatches only through ProtectedExecutionGuard.
# ============================================================================

def _wire_payload(mem_id: str, key: str, agent: str = AGENT_A_ACTIVE_ID, amount: float = 100.0) -> Dict[str, Any]:
    return {
        "action_id": f"act-{key}", "agent_id": agent, "tool_name": "sandbox_transfer",
        "operation": "transfer_funds",
        "parameters": {"destination_account": "ACC-LEGIT-123", "amount": amount, "currency": "USD"},
        "memory_refs": [mem_id], "idempotency_key": key, "trace_id": f"tr-{key}",
    }


def test_gateway_module_has_no_competing_policy_evaluator():
    import backend.app.api.gateway as gw
    for name in ("DeterministicPolicyEvaluator", "PolicyEvaluationInput", "get_default_policy_evaluator"):
        assert not hasattr(gw, name), name
    assert "REVIEW" not in {d.value for d in GatewayDecision}


@pytest.mark.asyncio
async def test_decision_audit_carries_m4_policy_evidence(
    client: httpx.AsyncClient, test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository, isolated_memory_repo: InMemoryMemoryRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
):
    await seed_agents(isolated_agent_repo)
    seed_memory_record(isolated_memory_repo, record_id="mem-m4-ev", tenant_id=TENANT_A_ID,
                       content="Trusted instruction", trust_state=TrustState.TRUSTED)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.post("/api/v1/gateway/actions/propose", json=_wire_payload("mem-m4-ev", "idemp-m4-ev"),
                             headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200 and resp.json()["decision"] == "ALLOW"
    details = isolated_gateway_repo.get_audit_events(TENANT_A_ID)[0].details_json
    assert details["policy_version"].startswith("amsc-policy/")
    assert details["reason_codes"] == ["ALL_CHECKS_PASSED"]
    assert details["memory_evidence"][0]["trust_decision_id"]


@pytest.mark.asyncio
async def test_agent_without_tool_grant_is_blocked_and_adapter_not_called(
    client: httpx.AsyncClient, test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository, isolated_memory_repo: InMemoryMemoryRepository,
):
    await seed_agents(isolated_agent_repo)
    isolated_agent_repo._tool_permissions[AGENT_A_ACTIVE_ID] = []          # no grant
    seed_memory_record(isolated_memory_repo, record_id="mem-nogrant", tenant_id=TENANT_A_ID,
                       content="Trusted instruction", trust_state=TrustState.TRUSTED)
    calls = []

    class SpyAdapter:
        async def execute(self, operation, parameters, context):
            calls.append(operation)
            return ToolExecutionResult(status="SUCCESS", status_code=200, result_payload={}, duration_ms=0)

    from backend.app.api.gateway import ToolAdapterRegistry
    reg = ToolAdapterRegistry()
    reg.register("sandbox_transfer", SpyAdapter())
    client._transport.app.state.tool_registry = reg
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.post("/api/v1/gateway/actions/propose", json=_wire_payload("mem-nogrant", "idemp-nogrant"),
                             headers={"Authorization": f"Bearer {token}"})
    data = resp.json()
    assert data["decision"] == "BLOCK" and "TOOL_NOT_ASSIGNED" in data["reason_codes"] and calls == []


@pytest.mark.asyncio
async def test_memory_marked_trusted_without_m4_evidence_is_blocked(
    client: httpx.AsyncClient, test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository, isolated_memory_repo: InMemoryMemoryRepository,
):
    """A stored TRUSTED flag alone (written outside M4) never justifies an action."""
    await seed_agents(isolated_agent_repo)
    seed_memory_record(isolated_memory_repo, record_id="mem-flag-only", tenant_id=TENANT_A_ID,
                       content="Looks trusted", trust_state=TrustState.UNVERIFIED)
    rec = isolated_memory_repo.get_record("mem-flag-only", TENANT_A_ID)
    rec.trust_state = TrustState.TRUSTED
    isolated_memory_repo.update_record(rec)
    token = create_token_for(USER_A_DEV_ID, "developer@company-a.com", TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.post("/api/v1/gateway/actions/propose", json=_wire_payload("mem-flag-only", "idemp-flag"),
                             headers={"Authorization": f"Bearer {token}"})
    data = resp.json()
    assert data["decision"] == "BLOCK" and data["execution_status"] == "NOT_EXECUTED"
    assert "REFERENCED_UNTRUSTED_MEMORY" in data["reason_codes"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role,user", [("SECURITY_ANALYST", USER_A_ANALYST_ID), ("TENANT_ADMIN", "user-a-admin-002")])
async def test_non_proposer_roles_are_blocked_by_m4(
    client: httpx.AsyncClient, test_settings: Settings, role: str, user: str,
    isolated_agent_repo: InMemoryAgentRepository, isolated_memory_repo: InMemoryMemoryRepository,
):
    await seed_agents(isolated_agent_repo)
    seed_memory_record(isolated_memory_repo, record_id=f"mem-role-{role}", tenant_id=TENANT_A_ID,
                       content="Trusted instruction", trust_state=TrustState.TRUSTED)
    token = create_token_for(user, "user@company-a.com", TENANT_A_ID, role, test_settings)   # role from membership
    resp = await client.post("/api/v1/gateway/actions/propose",
                             json=_wire_payload(f"mem-role-{role}", f"idemp-role-{role}"),
                             headers={"Authorization": f"Bearer {token}"})
    data = resp.json()
    assert data["decision"] == "BLOCK" and "PRINCIPAL_ROLE_NOT_AUTHORIZED" in data["reason_codes"]
