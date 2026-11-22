"""Unit and Security Tests for Incident Management, Evidence & Quarantine APIs.

Module: backend.tests.unit.test_incident_management
Owner: M1 — Platform Backend & API Integration Lead

Canonical References:
- AMSC-DOC-002 Section 5: Security Architecture & Dynamic Trust Quarantine
- AMSC-DOC-005 Section 3.5: Incidents, Quarantines & Recovery (Tables 20-22)
- AMSC-DOC-005 Section 5.1 & 6.2: Route Catalog and Schemas
- AMSC-DOC-006 Day 5: Milestone G5 Exit Gate
- AMSC-DOC-008: GAP-018/029, GAP-019/030, GAP-020/031, GAP-021/032
"""

from datetime import datetime, timezone
import pytest
import httpx

from backend.app.api.agents import (
    AgentEntity,
    InMemoryAgentRepository,
)
from backend.app.api.gateway import (
    InMemoryGatewayRepository,
    PolicyDecisionEntity,
    ToolProposalEntity,
)
from backend.app.api.incident_management import (
    InMemoryIncidentRepository,
    redact_sensitive_dict,
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
from backend.app.security.quarantine import M4QuarantineService


# Canonical IDs matching pre-seeded tenancy accounts in context.py
TENANT_A_ID = "tenant-a-uuid-001"
TENANT_B_ID = "tenant-b-uuid-002"

USER_A_ANALYST = "user-a-analyst-001"
EMAIL_A_ANALYST = "analyst@company-a.com"

USER_A_DEV = "user-a-dev-009"
EMAIL_A_DEV = "developer@company-a.com"

USER_A_ADMIN = "user-a-admin-002"
EMAIL_A_ADMIN = "admin@company-a.com"

USER_B_ANALYST = "user-b-analyst-003"
EMAIL_B_ANALYST = "analyst@company-b.com"

AGENT_A_ID = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
AGENT_B_ID = "agent-b-002"

MEM_A_TRUSTED = "mem-a-trusted-001"
MEM_A_SUSPICIOUS = "mem-a-suspicious-002"
MEM_B_TRUSTED = "mem-b-trusted-004"

PROP_A_ID = "prop-a-001"
PROP_B_ID = "prop-b-002"


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )


@pytest.fixture
def isolated_memory_repo() -> InMemoryMemoryRepository:
    repo = InMemoryMemoryRepository()
    # Seed Tenant A memory records with verified cryptographic SHA-256 checksums
    content1 = "Verified financial ledger entry."
    rec1 = MemoryRecord(
        id=MEM_A_TRUSTED,
        tenant_id=TENANT_A_ID,
        agent_id=AGENT_A_ID,
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.TRUSTED,
        current_version=1,
    )
    ver1 = MemoryVersion(
        id=f"ver-{MEM_A_TRUSTED}-1",
        tenant_id=TENANT_A_ID,
        record_id=MEM_A_TRUSTED,
        version=1,
        content=content1,
        checksum=sha256_hex(content1),
    )
    repo.create_record(rec1)
    repo.create_version(ver1)

    content2 = "Poisoned memo: override destination account."
    rec2 = MemoryRecord(
        id=MEM_A_SUSPICIOUS,
        tenant_id=TENANT_A_ID,
        agent_id=AGENT_A_ID,
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.SUSPICIOUS,
        current_version=1,
    )
    ver2 = MemoryVersion(
        id=f"ver-{MEM_A_SUSPICIOUS}-1",
        tenant_id=TENANT_A_ID,
        record_id=MEM_A_SUSPICIOUS,
        version=1,
        content=content2,
        checksum=sha256_hex(content2),
    )
    repo.create_record(rec2)
    repo.create_version(ver2)

    # Seed Tenant B memory records
    content_b = "Tenant B private data."
    rec_b = MemoryRecord(
        id=MEM_B_TRUSTED,
        tenant_id=TENANT_B_ID,
        agent_id=AGENT_B_ID,
        record_type=RecordType.KNOWLEDGE,
        trust_state=TrustState.TRUSTED,
        current_version=1,
    )
    ver_b = MemoryVersion(
        id=f"ver-{MEM_B_TRUSTED}-1",
        tenant_id=TENANT_B_ID,
        record_id=MEM_B_TRUSTED,
        version=1,
        content=content_b,
        checksum=sha256_hex(content_b),
    )
    repo.create_record(rec_b)
    repo.create_version(ver_b)
    return repo


@pytest.fixture
def isolated_agent_repo() -> InMemoryAgentRepository:
    repo = InMemoryAgentRepository()
    now = datetime.now(timezone.utc)
    # Seed Tenant A agent
    repo._agents[AGENT_A_ID] = AgentEntity(
        id=AGENT_A_ID,
        tenant_id=TENANT_A_ID,
        name="Treasury Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Manage treasury transactions.",
        created_at=now,
        updated_at=now,
    )
    # Seed Tenant B agent
    repo._agents[AGENT_B_ID] = AgentEntity(
        id=AGENT_B_ID,
        tenant_id=TENANT_B_ID,
        name="Tenant B Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Private operations.",
        created_at=now,
        updated_at=now,
    )
    return repo


@pytest.fixture
def isolated_gateway_repo() -> InMemoryGatewayRepository:
    repo = InMemoryGatewayRepository()
    now = datetime.now(timezone.utc)
    # Seed Tenant A proposal
    repo._proposals[PROP_A_ID] = ToolProposalEntity(
        id=PROP_A_ID,
        tenant_id=TENANT_A_ID,
        agent_id=AGENT_A_ID,
        action_id="act-001",
        tool_name="sandbox_transfer",
        operation="transfer_funds",
        parameters_json={"amount": 100},
        memory_refs_json=[MEM_A_TRUSTED],
        idempotency_key="idemp-001",
        trace_id="tr-001",
        created_at=now,
    )
    repo._decisions[PROP_A_ID] = PolicyDecisionEntity(
        id="dec-001",
        tenant_id=TENANT_A_ID,
        proposal_id=PROP_A_ID,
        decision="ALLOW",
        memory_trust="TRUSTED",
        policy_result="PERMITTED",
        reasons_json=[],
        incident_id=None,
        execution_status="EXECUTED",
        created_at=now,
    )
    # Seed Tenant B proposal
    repo._proposals[PROP_B_ID] = ToolProposalEntity(
        id=PROP_B_ID,
        tenant_id=TENANT_B_ID,
        agent_id=AGENT_B_ID,
        action_id="act-002",
        tool_name="sandbox_transfer",
        operation="transfer_funds",
        parameters_json={"amount": 200},
        memory_refs_json=[MEM_B_TRUSTED],
        idempotency_key="idemp-002",
        trace_id="tr-002",
        created_at=now,
    )
    return repo


@pytest.fixture
def isolated_incident_repo() -> InMemoryIncidentRepository:
    return InMemoryIncidentRepository()


@pytest.fixture
def client(
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_agent_repo: InMemoryAgentRepository,
    isolated_gateway_repo: InMemoryGatewayRepository,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    app = create_app(settings=test_settings)
    app.state.memory_repo = isolated_memory_repo
    app.state.agent_repo = isolated_agent_repo
    app.state.gateway_repo = isolated_gateway_repo
    app.state.incident_repo = isolated_incident_repo
    app.state.quarantine_service = M4QuarantineService()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def create_token_for(
    user_id: str,
    email: str,
    tenant_id: str,
    role: str,
    settings: Settings,
) -> str:
    return create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        settings=settings,
        additional_claims={"email": email},
    )


# ============================================================================
# 1. Authentication and Authorization Tests
# ============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_create_incident_rejected_401(client: httpx.AsyncClient):
    resp = await client.post(
        "/api/v1/security/incidents",
        json={
            "title": "Prompt Injection in Treasury Memory",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
        },
    )
    assert resp.status_code == 401
    data = resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_unauthenticated_quarantine_rejected_401(client: httpx.AsyncClient):
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        json={"reason": "Suspicious instruction injection"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthorized_role_cannot_create_incident_403(client: httpx.AsyncClient, test_settings: Settings):
    token = create_token_for(USER_A_DEV, EMAIL_A_DEV, TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Unauthorized attempt",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
        },
    )
    assert resp.status_code == 403
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_unauthorized_role_cannot_quarantine_memory_403(client: httpx.AsyncClient, test_settings: Settings):
    token = create_token_for(USER_A_DEV, EMAIL_A_DEV, TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Auditor isolation attempt"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_caller_cannot_impersonate_another_analyst(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # Extra fields attempting to inject actor/tenant identity are rejected by Pydantic extra="forbid" -> 400 Bad Request
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Suspicious Activity",
            "classification": "UNTRUSTED_MEMORY_ACTION",
            "severity": "HIGH",
            "actor_id": "attacker-user-999",
            "tenant_id": TENANT_B_ID,
        },
    )
    assert resp.status_code == 400


# ============================================================================
# 2. Tenant Isolation & Reference Validation (GAP-018 / GAP-029)
# ============================================================================

@pytest.mark.asyncio
async def test_same_tenant_incident_creation_succeeds_201(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Poisoned memo in vendor records",
            "classification": "PROMPT_INJECTION",
            "severity": "CRITICAL",
            "affected_record_id": MEM_A_SUSPICIOUS,
            "agent_id": AGENT_A_ID,
            "evidence": [
                {
                    "evidence_type": "MEMORY_RECORD",
                    "resource_id": MEM_A_SUSPICIOUS,
                    "metadata": {"suspicion_score": 0.95},
                },
                {
                    "evidence_type": "TOOL_PROPOSAL",
                    "resource_id": PROP_A_ID,
                    "metadata": {"action": "wire_transfer"},
                },
                {
                    "evidence_type": "TRACE_SPAN",
                    "resource_id": "span-forensic-001",
                    "metadata": {"duration_ms": 12},
                },
            ],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["tenant_id"] == TENANT_A_ID
    assert data["classification"] == "PROMPT_INJECTION"
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "OPEN"
    assert len(data["evidence"]) == 3


@pytest.mark.asyncio
async def test_cross_tenant_memory_reference_in_incident_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Cross-tenant reference attack",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
            "affected_record_id": MEM_B_TRUSTED,  # Tenant B memory!
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_cross_tenant_agent_reference_in_incident_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Cross-tenant agent attack",
            "classification": "UNAUTHORIZED_TOOL",
            "severity": "HIGH",
            "agent_id": AGENT_B_ID,  # Tenant B agent!
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_cross_tenant_evidence_reference_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Cross-tenant evidence attack",
            "classification": "UNTRUSTED_MEMORY_ACTION",
            "severity": "HIGH",
            "evidence": [
                {
                    "evidence_type": "MEMORY_RECORD",
                    "resource_id": MEM_B_TRUSTED,  # Tenant B record!
                    "metadata": {},
                }
            ],
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_nonexistent_evidence_reference_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Nonexistent evidence attack",
            "classification": "UNTRUSTED_MEMORY_ACTION",
            "severity": "HIGH",
            "evidence": [
                {
                    "evidence_type": "TOOL_PROPOSAL",
                    "resource_id": "nonexistent-proposal-id-999",
                    "metadata": {},
                }
            ],
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invalid_evidence_type_rejected_422(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Invalid evidence type",
            "classification": "UNAUTHORIZED_TOOL",
            "severity": "HIGH",
            "evidence": [
                {
                    "evidence_type": "ARBITRARY_PAYLOAD",  # Not allowlisted
                    "resource_id": "res-123",
                    "metadata": {},
                }
            ],
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cross_tenant_incident_detail_returns_404(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token_a = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    token_b = create_token_for(USER_B_ANALYST, EMAIL_B_ANALYST, TENANT_B_ID, "SECURITY_ANALYST", test_settings)

    # Tenant A creates an incident
    create_resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "title": "Tenant A Secret Incident",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
        },
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # Tenant B tries to inspect Tenant A's incident -> 404 Not Found (no existence leak)
    resp = await client.get(
        f"/api/v1/security/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404
    assert "error" in resp.json()


# ============================================================================
# 3. Evidence Attachment & Redaction Tests (GAP-021 / GAP-032)
# ============================================================================

@pytest.mark.asyncio
async def test_attach_evidence_to_existing_incident_success_201(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    create_resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Initial Incident",
            "classification": "DRIFT_DIVERGENCE",
            "severity": "MEDIUM",
        },
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    attach_resp = await client.post(
        f"/api/v1/security/incidents/{inc_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "evidence": [
                {
                    "evidence_type": "MEMORY_RECORD",
                    "resource_id": MEM_A_TRUSTED,
                    "metadata": {"note": "baseline comparison"},
                }
            ]
        },
    )
    assert attach_resp.status_code == 201
    data = attach_resp.json()
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["resource_id"] == MEM_A_TRUSTED


@pytest.mark.asyncio
async def test_evidence_sensitive_metadata_is_redacted(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Credential leakage check",
            "classification": "UNAUTHORIZED_TOOL",
            "severity": "HIGH",
            "evidence": [
                {
                    "evidence_type": "TRACE_SPAN",
                    "resource_id": "span-sec-01",
                    "metadata": {
                        "user_id": "usr-123",
                        "credentials": {
                            "password": "SuperSecretPassword123!",
                            "api_key": "amsc_live_apikey_9999",
                            "jwt_token": "eyJhbGciOi...",
                        },
                        "public_field": "safe_value",
                    },
                }
            ],
        },
    )
    assert resp.status_code == 201
    metadata = resp.json()["evidence"][0]["metadata"]
    assert metadata["credentials"]["password"] == "[REDACTED]"
    assert metadata["credentials"]["api_key"] == "[REDACTED]"
    assert metadata["credentials"]["jwt_token"] == "[REDACTED]"
    assert metadata["public_field"] == "safe_value"


@pytest.mark.asyncio
async def test_excessive_evidence_items_rejected_422(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # 21 items exceeds MAX_EVIDENCE_COUNT (20) -> 400 Bad Request
    items = [
        {"evidence_type": "TRACE_SPAN", "resource_id": f"span-{i}", "metadata": {}}
        for i in range(21)
    ]
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Evidence flood",
            "classification": "DRIFT_DIVERGENCE",
            "severity": "LOW",
            "evidence": items,
        },
    )
    assert resp.status_code == 400


# ============================================================================
# 4. Memory Quarantine Tests (GAP-019 / GAP-030)
# ============================================================================

@pytest.mark.asyncio
async def test_authorized_analyst_can_quarantine_record(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Initial state is SUSPICIOUS
    rec = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert rec.trust_state == TrustState.SUSPICIOUS

    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "reason": "Direct prompt injection attempt identified during audit",
            "analyst_notes": "Adversary memo overrides legitimate vendor account with attacker account",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == MEM_A_SUSPICIOUS
    assert data["previous_state"] == "SUSPICIOUS"
    assert data["trust_state"] == "QUARANTINED"
    assert "quarantined" in data["message"].lower()

    # Verify memory repo updated
    updated_rec = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert updated_rec.trust_state == TrustState.QUARANTINED


@pytest.mark.asyncio
async def test_quarantine_security_alias_route_works(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        f"/api/v1/security/memory/{MEM_A_TRUSTED}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Quarantine via security workstation alias"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["previous_state"] == "TRUSTED"
    assert data["trust_state"] == "QUARANTINED"


@pytest.mark.asyncio
async def test_quarantine_idempotence(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # First quarantine
    resp1 = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "First quarantine"},
    )
    assert resp1.status_code == 200

    # Second quarantine (idempotent)
    resp2 = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Second quarantine call"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["trust_state"] == "QUARANTINED"


@pytest.mark.asyncio
async def test_quarantine_with_associated_incident_updates_status(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # Create incident
    inc_resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Incident to be quarantined",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
        },
    )
    inc_id = inc_resp.json()["id"]

    # Quarantine memory linking this incident
    q_resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "reason": "Linking to incident",
            "incident_id": inc_id,
        },
    )
    assert q_resp.status_code == 200

    # Verify incident status transitioned to QUARANTINED
    get_inc = await client.get(
        f"/api/v1/security/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_inc.status_code == 200
    assert get_inc.json()["status"] == "QUARANTINED"
    assert get_inc.json()["affected_record_id"] == MEM_A_SUSPICIOUS


@pytest.mark.asyncio
async def test_quarantine_persistence_failure_fails_request_and_keeps_record_restricted(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    """Evidence persistence fails after M4 applied the transition.

    Previously the route rolled the record back to its prior state (SUSPICIOUS). M4's rule is to
    fail toward restriction: the record stays QUARANTINED (and M4's ledger agrees), and the request
    is NOT reported as success (503, reconciliation required). Relaxing a quarantine because a
    database write failed would be fail-open.
    """
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    isolated_incident_repo.fail_quarantine_persistence = True

    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Evidence write fails"},
    )
    assert resp.status_code == 503
    assert "successfully quarantined" not in resp.text.lower()
    rec_after = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert rec_after.trust_state in (TrustState.QUARANTINED, "QUARANTINED")


@pytest.mark.asyncio
async def test_quarantine_has_no_direct_trust_mutation_fallback(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
    monkeypatch,
):
    """Regression: the route used to catch M4's refusal and call M3's transition_memory_trust_state
    directly. If M4's workflow cannot run, the request must fail and the record must not change."""
    import backend.app.api.incident_management as im
    from backend.app.core.exceptions import SecurityDependencyError

    def unavailable(*_a, **_k):
        raise SecurityDependencyError("M4 unavailable")

    monkeypatch.setattr(im, "get_quarantine_workflow", unavailable)
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "M4 down"},
    )
    assert resp.status_code == 503
    rec = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert rec.trust_state in (TrustState.SUSPICIOUS, "SUSPICIOUS")


@pytest.mark.asyncio
async def test_quarantine_goes_through_m4_ledger(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """The quarantine is recorded in M4's trust decision history (not a bare state write)."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Ledger check"},
    )
    assert resp.status_code == 200
    store = client._transport.app.state.trust_decision_store
    history = store.list_for_record(TENANT_A_ID, MEM_A_SUSPICIOUS)
    assert [d.resulting_state for d in history if d.applied] == ["QUARANTINED"]


@pytest.mark.asyncio
async def test_quarantined_memory_immediately_excluded_from_normal_retrieval(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Quarantine the trusted record
    await client.post(
        f"/api/v1/memory/{MEM_A_TRUSTED}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Emergency quarantine"},
    )

    # Normal memory query (GET /api/v1/memory) strictly excludes QUARANTINED
    query_resp = await client.get(
        "/api/v1/memory",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert query_resp.status_code == 200
    records = query_resp.json()
    record_ids = [r["id"] for r in records]
    assert MEM_A_TRUSTED not in record_ids


@pytest.mark.asyncio
async def test_quarantined_memory_detail_returns_404_for_normal_access(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Quarantine
    await client.post(
        f"/api/v1/memory/{MEM_A_TRUSTED}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Quarantine test"},
    )

    # Normal detail endpoint (GET /api/v1/memory/{id}) returns 404 for non-trusted
    detail_resp = await client.get(
        f"/api/v1/memory/{MEM_A_TRUSTED}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert detail_resp.status_code == 404


@pytest.mark.asyncio
async def test_quarantined_memory_blocks_gateway_tool_proposals(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Quarantine record
    await client.post(
        f"/api/v1/memory/{MEM_A_TRUSTED}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Quarantine before tool execution"},
    )

    # Propose tool action referencing quarantined memory
    prop_resp = await client.post(
        "/api/v1/gateway/actions/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "action_id": "act-quarantine-blocked",
            "agent_id": AGENT_A_ID,
            "tool_name": "sandbox_transfer",
            "operation": "transfer_funds",
            "parameters": {"amount": 50},
            "memory_refs": [MEM_A_TRUSTED],
            "idempotency_key": "idemp-quar-001",
            "trace_id": "tr-quar-001",
        },
    )
    assert prop_resp.status_code == 200
    data = prop_resp.json()
    assert data["decision"] == "BLOCK"
    assert data["memory_trust"] == "QUARANTINED"
    assert data["execution_status"] == "NOT_EXECUTED"


# ============================================================================
# 5. Forensic Memory Access Tests (GAP-020 / GAP-031)
# ============================================================================

@pytest.mark.asyncio
async def test_forensic_memory_access_by_analyst_succeeds(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Quarantine record
    await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Prepare forensic test"},
    )

    # Normal GET /memory/{id} returns 404
    normal_resp = await client.get(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert normal_resp.status_code == 404

    # Dedicated forensic route returns full detail
    forensic_resp = await client.get(
        f"/api/v1/security/memory/{MEM_A_SUSPICIOUS}",
        headers={"Authorization": f"Bearer {token}"},
        params={"reason": "Forensic root-cause analysis for Incident inc-001"},
    )
    assert forensic_resp.status_code == 200
    data = forensic_resp.json()
    assert data["record"]["id"] == MEM_A_SUSPICIOUS
    assert data["record"]["trust_state"] == "QUARANTINED"
    assert len(data["versions"]) > 0


@pytest.mark.asyncio
async def test_forensic_memory_access_by_unauthorized_role_rejected_403(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_DEV, EMAIL_A_DEV, TENANT_A_ID, "AI_DEVELOPER", test_settings)
    resp = await client.get(
        f"/api/v1/security/memory/{MEM_A_SUSPICIOUS}",
        headers={"Authorization": f"Bearer {token}"},
        params={"reason": "Attempting unauthorized forensic inspect"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_forensic_memory_access_cross_tenant_returns_404(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token_a = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # Analyst A attempts forensic read of Tenant B record -> 404 Not Found
    resp = await client.get(
        f"/api/v1/security/memory/{MEM_B_TRUSTED}",
        headers={"Authorization": f"Bearer {token_a}"},
        params={"reason": "Cross-tenant investigation probe"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_forensic_memory_access_requires_reason(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    # Missing reason parameter -> 400 Bad Request
    resp = await client.get(
        f"/api/v1/security/memory/{MEM_A_SUSPICIOUS}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


# ============================================================================
# 6. Security Alerts Summary Tests
# ============================================================================

@pytest.mark.asyncio
async def test_security_alerts_endpoint_aggregates_counts(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Create critical incident
    await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Critical breach alert",
            "classification": "PROMPT_INJECTION",
            "severity": "CRITICAL",
        },
    )

    # Quarantine memory
    await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Quarantine alert test"},
    )

    resp = await client.get(
        "/api/v1/security/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_alerts"] >= 1
    assert data["critical_count"] >= 1
    assert data["quarantined_records_count"] >= 1


# ============================================================================
# 7. Redaction & Bounded Pagination Tests
# ============================================================================

def test_redact_sensitive_dict_helper():
    payload = {
        "user": "alice",
        "nested": {
            "bearer_token": "secret123",
            "deep": {
                "private_key": "PEM_KEY_DATA",
                "normal": "value",
            },
        },
    }
    redacted = redact_sensitive_dict(payload)
    assert redacted["user"] == "alice"
    assert redacted["nested"]["bearer_token"] == "[REDACTED]"
    assert redacted["nested"]["deep"]["private_key"] == "[REDACTED]"
    assert redacted["nested"]["deep"]["normal"] == "value"


@pytest.mark.asyncio
async def test_incident_list_bounded_pagination(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)

    # Seed 3 incidents
    for i in range(3):
        await client.post(
            "/api/v1/security/incidents",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "title": f"Incident {i}",
                "classification": "UNAUTHORIZED_TOOL",
                "severity": "LOW",
            },
        )

    # Page limit 2, offset 0
    resp1 = await client.get(
        "/api/v1/security/incidents?limit=2&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert len(data1["items"]) == 2
    assert data1["has_more"] is True
    assert data1["total"] == 3

    # Page limit 2, offset 2
    resp2 = await client.get(
        "/api/v1/security/incidents?limit=2&offset=2",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) == 1
    assert data2["has_more"] is False


@pytest.mark.asyncio
async def test_client_supplied_tenant_id_in_payload_is_rejected_422(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify that caller-supplied tenant_id in request body is strictly rejected (extra forbid)."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Forged tenant incident",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
            "tenant_id": TENANT_B_ID,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_branch_scoping_isolation_and_rejection_for_incidents(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_agent_repo: InMemoryAgentRepository,
):
    """Verify branch scoping: a branch-restricted analyst cannot reference agents from other branches."""
    from backend.app.tenancy.context import TenantContext
    from backend.app.core.dependencies import get_tenant_context

    now = datetime.now(timezone.utc)
    # Seed Branch Karachi agent
    isolated_agent_repo._agents["agent-karachi-101"] = AgentEntity(
        id="agent-karachi-101",
        tenant_id=TENANT_A_ID,
        name="Karachi Ops Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Karachi prompt",
        branch_id="branch-karachi-99",
        created_at=now,
        updated_at=now,
    )
    # Seed Branch Lahore agent
    isolated_agent_repo._agents["agent-lahore-202"] = AgentEntity(
        id="agent-lahore-202",
        tenant_id=TENANT_A_ID,
        name="Lahore Ops Agent",
        runtime="LANGCHAIN",
        model="gpt-4o",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="Lahore prompt",
        branch_id="branch-lahore-88",
        created_at=now,
        updated_at=now,
    )

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate Karachi-scoped analyst context
    karachi_context = TenantContext(
        tenant_id=TENANT_A_ID,
        tenant_slug="company-a",
        tenant_name="Company A",
        user_id=USER_A_ANALYST,
        role="SECURITY_ANALYST",
        is_active=True,
    )
    object.__setattr__(karachi_context, "branch_id", "branch-karachi-99")

    app = client._transport.app  # type: ignore
    app.dependency_overrides[get_tenant_context] = lambda: karachi_context

    try:
        # 1. Referencing Lahore agent is rejected with 400
        resp_lahore = await client.post(
            "/api/v1/security/incidents",
            headers=headers,
            json={
                "title": "Cross-branch incident attempt",
                "classification": "UNAUTHORIZED_TOOL",
                "severity": "HIGH",
                "agent_id": "agent-lahore-202",
            },
        )
        assert resp_lahore.status_code == 400
        assert resp_lahore.json()["error"]["code"] == "VALIDATION_ERROR"

        # 2. Referencing Karachi agent succeeds with 201
        resp_karachi = await client.post(
            "/api/v1/security/incidents",
            headers=headers,
            json={
                "title": "Valid branch incident",
                "classification": "UNAUTHORIZED_TOOL",
                "severity": "HIGH",
                "agent_id": "agent-karachi-101",
            },
        )
        assert resp_karachi.status_code == 201
    finally:
        app.dependency_overrides.pop(get_tenant_context, None)


@pytest.mark.asyncio
async def test_cross_tenant_audit_event_reference_rejected(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    """Verify that referencing an audit event belonging to another tenant is rejected."""
    from backend.app.api.incident_management import AuditEventEntity

    # Seed an audit event for Tenant B
    isolated_incident_repo._audit_events.append(
        AuditEventEntity(
            id="aud-tenant-b-999",
            tenant_id=TENANT_B_ID,
            actor_id=USER_B_ANALYST,
            event_type="MEMORY_QUARANTINED",
            resource_id=MEM_B_TRUSTED,
            action="QUARANTINE_RECORD",
            outcome="SUCCESS",
            trace_id="tr-b-001",
            details_json={},
        )
    )

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Cross-tenant audit reference",
            "classification": "DRIFT_DIVERGENCE",
            "severity": "MEDIUM",
            "evidence": [
                {
                    "evidence_type": "AUDIT_EVENT",
                    "resource_id": "aud-tenant-b-999",
                    "metadata": {},
                }
            ],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_cross_tenant_memory_quarantine_returns_404(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify that attempting to quarantine a memory record from another tenant returns 404."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        f"/api/v1/memory/{MEM_B_TRUSTED}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Attacking victim tenant"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


@pytest.mark.asyncio
async def test_nonexistent_memory_quarantine_returns_404(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify that attempting to quarantine a nonexistent record returns 404."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/memory/mem-ghost-nonexistent/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Testing nonexistent record"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_malformed_identifier_rejected_400(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify that malformed path identifiers with control characters are rejected."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.get(
        "/api/v1/security/incidents/inc-bad%00null",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_concurrent_quarantine_requests_deterministic(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Verify that concurrent quarantine requests targeting the same record behave deterministically."""
    import asyncio

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    # Execute 5 concurrent quarantine requests
    tasks = [
        client.post(
            f"/api/v1/memory/{MEM_A_TRUSTED}/quarantine",
            headers=headers,
            json={"reason": f"Concurrent isolation test {i}"},
        )
        for i in range(5)
    ]
    responses = await asyncio.gather(*tasks)

    # All should return 200 OK and trust_state="QUARANTINED"
    for r in responses:
        assert r.status_code == 200
        assert r.json()["trust_state"] == "QUARANTINED"

    rec = isolated_memory_repo.get_record(MEM_A_TRUSTED, TENANT_A_ID)
    assert rec.trust_state == TrustState.QUARANTINED


@pytest.mark.asyncio
async def test_quarantine_with_resolved_incident_rejected_400(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    """Verify that linking a quarantine to an already RESOLVED incident is rejected."""
    from backend.app.api.incident_management import IncidentEntity

    # Seed an already resolved incident
    inc_resolved = IncidentEntity(
        id="inc-resolved-001",
        tenant_id=TENANT_A_ID,
        title="Resolved case",
        classification="PROMPT_INJECTION",
        severity="LOW",
        status="RESOLVED",
        affected_record_id=None,
        agent_id=None,
        evidence_json={},
    )
    isolated_incident_repo._incidents["inc-resolved-001"] = inc_resolved

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        f"/api/v1/memory/{MEM_A_SUSPICIOUS}/quarantine",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "reason": "Associating to resolved incident",
            "incident_id": "inc-resolved-001",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_forensic_memory_access_creates_durable_audit_event(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    """Verify forensic access durably appends an audit event to the repository."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.get(
        f"/api/v1/security/memory/{MEM_A_SUSPICIOUS}?reason=Forensic+forensic+audit+review",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200

    # Verify audit event is recorded
    audit_events = [
        ev for ev in isolated_incident_repo._audit_events
        if ev.event_type == "FORENSIC_MEMORY_ACCESSED" and ev.resource_id == MEM_A_SUSPICIOUS
    ]
    assert len(audit_events) == 1
    ev = audit_events[0]
    assert ev.tenant_id == TENANT_A_ID
    assert ev.actor_id == USER_A_ANALYST
    assert "Forensic forensic audit review" in ev.details_json["reason"]


@pytest.mark.asyncio
async def test_forensic_memory_access_does_not_modify_trust_state(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_memory_repo: InMemoryMemoryRepository,
):
    """Verify forensic memory read does not alter underlying trust state."""
    rec_before = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert rec_before.trust_state == TrustState.SUSPICIOUS

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.get(
        f"/api/v1/security/memory/{MEM_A_SUSPICIOUS}?reason=Forensic+read+only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200

    rec_after = isolated_memory_repo.get_record(MEM_A_SUSPICIOUS, TENANT_A_ID)
    assert rec_after.trust_state == TrustState.SUSPICIOUS


@pytest.mark.asyncio
async def test_incident_creation_transaction_rollback_leaves_no_traces(
    client: httpx.AsyncClient,
    test_settings: Settings,
    isolated_incident_repo: InMemoryIncidentRepository,
):
    """Verify that if incident transaction fails, no incident or evidence remains."""
    isolated_incident_repo.fail_incident_persistence = True

    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.post(
        "/api/v1/security/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Doomed incident",
            "classification": "PROMPT_INJECTION",
            "severity": "HIGH",
        },
    )
    assert resp.status_code == 500
    assert len(isolated_incident_repo._incidents) == 0


@pytest.mark.asyncio
async def test_list_incidents_invalid_filter_rejected_400(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify that passing invalid enum filters to list endpoint returns 400 with VALIDATION_ERROR."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    resp = await client.get(
        "/api/v1/security/incidents?status=SUPER_OPEN",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_list_incidents_filtering_works(
    client: httpx.AsyncClient,
    test_settings: Settings,
):
    """Verify filtering by status, severity, and classification works correctly."""
    token = create_token_for(USER_A_ANALYST, EMAIL_A_ANALYST, TENANT_A_ID, "SECURITY_ANALYST", test_settings)
    headers = {"Authorization": f"Bearer {token}"}

    await client.post(
        "/api/v1/security/incidents",
        headers=headers,
        json={"title": "Crit 1", "classification": "PROMPT_INJECTION", "severity": "CRITICAL"},
    )
    await client.post(
        "/api/v1/security/incidents",
        headers=headers,
        json={"title": "Low 1", "classification": "UNAUTHORIZED_TOOL", "severity": "LOW"},
    )

    # Filter severity=CRITICAL
    r_crit = await client.get("/api/v1/security/incidents?severity=CRITICAL", headers=headers)
    assert r_crit.status_code == 200
    items = r_crit.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "Crit 1"

    # Filter classification=UNAUTHORIZED_TOOL
    r_class = await client.get("/api/v1/security/incidents?classification=UNAUTHORIZED_TOOL", headers=headers)
    assert r_class.status_code == 200
    items_class = r_class.json()["items"]
    assert len(items_class) == 1
    assert items_class[0]["title"] == "Low 1"
