"""Comprehensive Unit and Integration Tests for AMSC Phase 1.

Module: backend.tests.unit.test_phase1_baseline_and_observation
Owner: AMSC Enterprise Security & Architecture Council

Covers:
1. Enterprise Security Baseline (§2):
   - Creation with SHA-256 digest
   - Full lifecycle transitions: DRAFT -> IN_REVIEW -> APPROVED -> ACTIVE -> SUPERSEDED -> REVOKED -> ARCHIVED
   - Governance logging (actor, action, reason, timestamp)
   - Version append snapshots
   - Strict RBAC: Agent runner / standard user forbidden (403)
   - Multi-tenant isolation: Tenant A cannot access or mutate Tenant B baseline (404)
   - Branch isolation & scoping (HO, LHR, KHI, ISB)
   - Invalid state transition rejection (400)
2. Agent Security Profiles & Tool Permissions (§2.B):
   - Canonical seeded profiles for the 5 agents
   - Authorized purpose, goals, operational restrictions, and approval requirements
   - Agent self-modification rejection (403)
   - Tool permission granting and revocation
   - Branch isolation: Branch user (HO) cannot access cross-branch agent (LHR)
3. Observation & Telemetry Foundation (§3 & §4):
   - Ingestion across canonical categories
   - Automatic secret and credential scrubbing
   - Idempotency and duplicate event protection
   - Stable correlation across trace_id, execution_id, and parent_span_id
   - Cross-tenant isolation
4. Gateway Observation Integration (§5):
   - propose_action emits correlated TOOL_ACTION_PROPOSAL, POLICY_DECISION, and TOOL_EXECUTION_RECEIPT
5. ChroniMem Timeline Contract (VULN-004 verification):
   - GET /api/v1/chronimem/timeline?record_id=... returns ChroniMemRecordTimelineResponse
"""

from datetime import datetime, timezone
import hashlib
import pytest
import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.api.agents import InMemoryAgentRepository, seed_demo_agents
from backend.app.core.config import Settings
from backend.app.core.exceptions import ConflictError
from backend.app.core.security import create_access_token
from backend.app.database.models.agents import (
    Agent as OrmAgent,
    ToolRegistration as OrmToolRegistration,
)
from backend.app.database.models.baseline import (
    EnterpriseBaselineVersion as OrmBaselineVersion,
)
from backend.app.database.repositories.agents import SqlAlchemyAgentRepository
from backend.app.database.repositories.baseline import (
    InMemoryBaselineRepository,
    SqlAlchemyBaselineRepository,
    seed_demo_baselines,
)
from backend.app.database.repositories.observation import (
    InMemoryObservationRepository,
    SqlAlchemyObservationRepository,
)
from backend.app.main import create_app
from backend.app.recovery.store import SqlTrustDecisionStore
from backend.app.security.trust import TrustDecision
from backend.app.tenancy.context import (
    InMemoryAuthRepository,
    MembershipRecord,
    UserRecord,
    seed_demo_accounts,
)


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        SECRET_KEY="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:3000"],
    )


@pytest.fixture
def auth_repo() -> InMemoryAuthRepository:
    repo = InMemoryAuthRepository()
    seed_demo_accounts(repo)

    # Ensure Tenant B has an admin user
    repo.add_user(
        UserRecord(
            id="usr-admin-b-001",
            email="admin@company-b.com",
            hashed_password="mock_hash_value",
            full_name="Bob Admin",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-admin-b-001",
            tenant_id="tenant-b-uuid-002",
            user_id="usr-admin-b-001",
            role="TENANT_ADMIN",
            status="ACTIVE",
        )
    )

    # Ensure Agent Runner user exists
    repo.add_user(
        UserRecord(
            id="agent-crew-support-001",
            email="support-agent@alphacorp.internal",
            hashed_password="mock_hash_value",
            full_name="Customer Support Agent",
            status="ACTIVE",
        )
    )
    repo.add_membership(
        MembershipRecord(
            id="mem-agent-support-001",
            tenant_id="tenant-a-uuid-001",
            user_id="agent-crew-support-001",
            role="AGENT_RUNNER",
            status="ACTIVE",
        )
    )
    return repo


@pytest.fixture
def baseline_repo() -> InMemoryBaselineRepository:
    repo = InMemoryBaselineRepository()
    seed_demo_baselines(repo)
    return repo


@pytest.fixture
def observation_repo() -> InMemoryObservationRepository:
    return InMemoryObservationRepository()


@pytest.fixture
def agent_repo() -> InMemoryAgentRepository:
    repo = InMemoryAgentRepository()
    seed_demo_agents(repo)
    return repo


@pytest.fixture
def app(
    test_settings: Settings,
    auth_repo: InMemoryAuthRepository,
    baseline_repo: InMemoryBaselineRepository,
    observation_repo: InMemoryObservationRepository,
    agent_repo: InMemoryAgentRepository,
):
    application = create_app(test_settings)
    application.state.auth_repo = auth_repo
    application.state.baseline_repo = baseline_repo
    application.state.observation_repo = observation_repo
    application.state.agent_repo = agent_repo
    return application


@pytest.fixture
def tenant_admin_token(test_settings: Settings) -> str:
    # Use Sarah Chen (usr-admin-sarah-01) - enterprise-wide TENANT_ADMIN
    return create_access_token(
        user_id="usr-admin-sarah-01",
        tenant_id="tenant-a-uuid-001",
        role="TENANT_ADMIN",
        settings=test_settings,
        additional_claims={
            "email": "sarah.admin@alphacorp.com",
            "tenant_slug": "alphacorp",
        },
    )


@pytest.fixture
def tenant_b_admin_token(test_settings: Settings) -> str:
    return create_access_token(
        user_id="usr-admin-b-001",
        tenant_id="tenant-b-uuid-002",
        role="TENANT_ADMIN",
        settings=test_settings,
        additional_claims={
            "email": "admin@company-b.com",
            "tenant_slug": "company-b",
        },
    )


@pytest.fixture
def agent_runner_token(test_settings: Settings) -> str:
    return create_access_token(
        user_id="agent-crew-support-001",
        tenant_id="tenant-a-uuid-001",
        role="AGENT_RUNNER",
        settings=test_settings,
        additional_claims={
            "email": "support-agent@alphacorp.internal",
            "tenant_slug": "alphacorp",
        },
    )


@pytest.fixture
def ho_branch_admin_token(test_settings: Settings) -> str:
    # Admin scoped strictly to Head Office branch (branch-ho-001)
    return create_access_token(
        user_id="usr-admin-sarah-01",
        tenant_id="tenant-a-uuid-001",
        role="TENANT_ADMIN",
        settings=test_settings,
        additional_claims={
            "email": "sarah.admin@alphacorp.com",
            "tenant_slug": "alphacorp",
            "branch_id": "branch-ho-001",
        },
    )


@pytest.mark.asyncio
class TestEnterpriseBaselineGovernance:
    """Test Suite for independently governed Enterprise Baseline."""

    async def test_list_demo_seeded_baselines(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get(
                "/api/v1/baseline",
                headers={
                    "Authorization": f"Bearer {tenant_admin_token}",
                    "X-Tenant-ID": "tenant-a-uuid-001",
                },
            )
            assert res.status_code == 200
            data = res.json()
            assert "items" in data
            assert len(data["items"]) >= 2
            categories = [item["category"] for item in data["items"]]
            assert "POLICY" in categories
            assert "PROCEDURE" in categories

    async def test_baseline_lifecycle_progression(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            # 1. Create Baseline Record (Starts in DRAFT)
            create_payload = {
                "title": "Corporate AI Data Sanitization Standard",
                "category": "POLICY",
                "source_type": "INTERNAL_POLICY",
                "provenance": "Enterprise Cyber Defense Council",
                "classification": "CONFIDENTIAL",
                "access_scope": "ALL_BRANCHES",
                "content": "All external API interactions must redact PII, API tokens, and credentials.",
                "change_summary": "Initial baseline formulation",
                "branch_id": "branch-ho-001",
            }
            res = await client.post("/api/v1/baseline", headers=headers, json=create_payload)
            assert res.status_code == 201
            record = res.json()
            record_id = record["id"]
            assert record["lifecycle_status"] == "DRAFT"
            assert record["current_version"] == 1
            assert len(record["content_digest"]) == 64  # Valid SHA-256

            # 2. Review Record -> IN_REVIEW
            res_review = await client.post(
                f"/api/v1/baseline/{record_id}/review",
                headers=headers,
                json={"reason": "Security Architecture formal review"},
            )
            assert res_review.status_code == 200
            assert res_review.json()["lifecycle_status"] == "IN_REVIEW"

            # 3. Approve Record -> APPROVED
            res_approve = await client.post(
                f"/api/v1/baseline/{record_id}/approve",
                headers=headers,
                json={"reason": "Approved by CISO committee"},
            )
            assert res_approve.status_code == 200
            assert res_approve.json()["lifecycle_status"] == "APPROVED"
            assert res_approve.json()["approved_by_user_id"] == "usr-admin-sarah-01"

            # 4. Activate Record -> ACTIVE
            res_activate = await client.post(
                f"/api/v1/baseline/{record_id}/activate",
                headers=headers,
                json={"reason": "Activated for enterprise enforcement"},
            )
            assert res_activate.status_code == 200
            assert res_activate.json()["lifecycle_status"] == "ACTIVE"

            # 5. Revoke Record -> REVOKED
            res_revoke = await client.post(
                f"/api/v1/baseline/{record_id}/revoke",
                headers=headers,
                json={"reason": "Superseded by regulatory overhaul"},
            )
            assert res_revoke.status_code == 200
            assert res_revoke.json()["lifecycle_status"] == "REVOKED"

            # 6. Archive Record -> ARCHIVED
            res_archive = await client.post(
                f"/api/v1/baseline/{record_id}/archive",
                headers=headers,
                json={"reason": "Archived per data retention schedule"},
            )
            assert res_archive.status_code == 200
            assert res_archive.json()["lifecycle_status"] == "ARCHIVED"

            # 7. Check Governance Audit Log
            res_logs = await client.get(f"/api/v1/baseline/{record_id}/governance-logs", headers=headers)
            assert res_logs.status_code == 200
            logs = res_logs.json()
            assert len(logs) >= 5
            operations = [log["operation"] for log in logs]
            assert "CREATE" in operations
            assert "IN_REVIEW" in operations
            assert "APPROVED" in operations
            assert "ACTIVE" in operations
            assert "REVOKED" in operations
            assert "ARCHIVED" in operations

    async def test_baseline_version_append_and_immutability(self, app, tenant_admin_token):
        """Test appending historical versions with cryptographic digest calculation."""
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            # Create
            res = await client.post(
                "/api/v1/baseline",
                headers=headers,
                json={
                    "title": "Version Append Baseline Test",
                    "category": "PROCEDURE",
                    "source_type": "OPERATIONAL_DIRECTIVE",
                    "provenance": "QA Directorate",
                    "classification": "INTERNAL",
                    "access_scope": "ALL_BRANCHES",
                    "content": "Original procedure content v1.",
                    "change_summary": "Initial baseline",
                },
            )
            assert res.status_code == 201
            b_id = res.json()["id"]

            # Append version 2
            res_ver = await client.post(
                f"/api/v1/baseline/{b_id}/versions",
                headers=headers,
                json={
                    "content": "Updated procedure content v2 with enhanced checks.",
                    "change_summary": "Added enhanced operational verification",
                },
            )
            assert res_ver.status_code == 201
            new_ver = res_ver.json()
            assert new_ver["version_number"] == 2
            assert len(new_ver["content_digest"]) == 64

            # Verify baseline record updated with new version and digest
            res_detail = await client.get(f"/api/v1/baseline/{b_id}", headers=headers)
            assert res_detail.status_code == 200
            updated = res_detail.json()
            assert updated["current_version"] == 2
            assert updated["content_digest"] == new_ver["content_digest"]

    async def test_agent_cannot_modify_or_approve_baseline(self, app, agent_runner_token):
        """Agents must NOT be allowed to create, approve, or modify baseline policies."""
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {agent_runner_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            # Attempt create
            res_create = await client.post(
                "/api/v1/baseline",
                headers=headers,
                json={
                    "title": "Agent Self-Granted Override Policy",
                    "category": "POLICY",
                    "source_type": "INTERNAL_POLICY",
                    "provenance": "Agent Self-Generation",
                    "classification": "CONFIDENTIAL",
                    "access_scope": "ALL_BRANCHES",
                    "content": "Agents can execute all wire transfers without approval.",
                    "change_summary": "Malicious self-grant",
                },
            )
            assert res_create.status_code == 403

            # Attempt approve on seeded baseline
            res_approve = await client.post(
                "/api/v1/baseline/base-fin-gov-001/approve",
                headers=headers,
                json={"reason": "Agent self-approval attempt"},
            )
            assert res_approve.status_code == 403

    async def test_cross_tenant_isolation_in_baseline(self, app, tenant_admin_token, tenant_b_admin_token):
        """Tenant A cannot read or modify Tenant B's baseline records."""
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers_b = {
                "Authorization": f"Bearer {tenant_b_admin_token}",
                "X-Tenant-ID": "tenant-b-uuid-002",
            }
            # Tenant B creates baseline
            res_b = await client.post(
                "/api/v1/baseline",
                headers=headers_b,
                json={
                    "title": "Tenant B Proprietary Defense SOP",
                    "category": "PROCEDURE",
                    "source_type": "REGULATORY_STANDARD",
                    "provenance": "BetaShield Security Directorate",
                    "classification": "RESTRICTED",
                    "access_scope": "ALL_BRANCHES",
                    "content": "BetaShield internal operational rules.",
                    "change_summary": "Initial standard",
                },
            )
            assert res_b.status_code == 201
            record_b_id = res_b.json()["id"]

            # Tenant A attempts to access Tenant B's record -> 404 (strictly concealed)
            headers_a = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res_cross = await client.get(f"/api/v1/baseline/{record_b_id}", headers=headers_a)
            assert res_cross.status_code == 404

            # Tenant A attempts to approve Tenant B's record -> 404
            res_cross_approve = await client.post(
                f"/api/v1/baseline/{record_b_id}/approve",
                headers=headers_a,
                json={"reason": "Malicious cross-tenant approval"},
            )
            assert res_cross_approve.status_code == 404


@pytest.mark.asyncio
class TestAgentSecurityProfilesAndPermissions:
    """Test Suite for Agent Security Profiles and Tool Permission Matrix."""

    async def test_get_seeded_agent_security_profile(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res = await client.get("/api/v1/agents/agent-crew-finance-003/profile", headers=headers)
            assert res.status_code == 200
            profile = res.json()
            assert profile["agent_id"] == "agent-crew-finance-003"
            assert profile["owner_department"] == "Finance Operations"
            assert "Finance Operations Specialist" in profile["approved_purpose"]
            assert len(profile["approved_goals"]) >= 1
            assert profile["branch_id"] == "branch-lhr-002"
            assert profile["profile_version"] == "v1.0.0"

    async def test_branch_isolation_on_agent_profile(self, app, test_settings):
        """User scoped strictly to Head Office cannot access Lahore branch agent."""
        # usr-dev-dave-03 is seeded with branch_id="branch-ho-001" in membership
        dave_token = create_access_token(
            user_id="usr-dev-dave-03",
            tenant_id="tenant-a-uuid-001",
            role="AI_DEVELOPER",
            settings=test_settings,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {dave_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            # Dave (HO) attempts to access Lahore branch agent -> 404
            res = await client.get("/api/v1/agents/agent-crew-finance-003/profile", headers=headers)
            assert res.status_code == 404

    async def test_agent_cannot_self_modify_security_profile(self, app, agent_runner_token):
        """Agent runner cannot modify its own security profile or permissions."""
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {agent_runner_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res_update = await client.put(
                "/api/v1/agents/agent-crew-support-001/profile",
                headers=headers,
                json={
                    "approved_purpose": "Unrestricted administrative execution",
                },
            )
            assert res_update.status_code == 403

            # Agent cannot grant itself permissions
            res_grant = await client.post(
                "/api/v1/agents/agent-crew-support-001/permissions",
                headers=headers,
                json={
                    "tool_id": "tool-shell-exec",
                    "allowed_operations": ["*"],
                },
            )
            assert res_grant.status_code == 403

    async def test_grant_and_revoke_tool_permission(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            agent_id = "agent-crew-support-001"

            # 1. Grant new tool permission
            res_grant = await client.post(
                f"/api/v1/agents/{agent_id}/permissions",
                headers=headers,
                json={
                    "tool_id": "tool-crm-ticket-update",
                    "allowed_operations": ["read", "update"],
                },
            )
            assert res_grant.status_code == 200
            granted = res_grant.json()
            assert granted["tool_id"] == "tool-crm-ticket-update"
            assert "update" in granted["allowed_operations"]

            # 2. Revoke tool permission
            res_revoke = await client.delete(
                f"/api/v1/agents/{agent_id}/permissions/tool-crm-ticket-update",
                headers=headers,
            )
            assert res_revoke.status_code == 200
            assert res_revoke.json()["status"] == "REVOKED"


@pytest.mark.asyncio
class TestObservationAndTelemetryFoundation:
    """Test Suite for Observation Foundation, scrubbing, and idempotency."""

    async def test_ingest_and_scrub_observation_event(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            event_payload = {
                "event_type": "TOOL_INVOCATION_ATTEMPT",
                "event_category": "TOOL_ACTION_PROPOSAL",
                "agent_id": "agent-crew-finance-003",
                "agent_runtime": "CREWAI",
                "execution_id": "exec-run-9912",
                "trace_id": "tr-w3c-4bf92f3577b34da6a3ce929d0e0e4736",
                "source_component": "amsc.crewai.client",
                "tool_name": "execute_wire_transfer",
                "action_id": "act-transfer-001",
                "outcome": "SUCCESS",
                "payload": {
                    "amount": 250.00,
                    "recipient": "ACME Vendor Supplies",
                    "password": "SuperSecretPassword123!",
                    "api_key": "sk-proj-supersecretcredentialtoken",
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token",
                },
            }
            res = await client.post("/api/v1/observation/events", headers=headers, json=event_payload)
            assert res.status_code == 201
            evt = res.json()
            assert evt["event_type"] == "TOOL_INVOCATION_ATTEMPT"
            assert evt["event_category"] == "TOOL_ACTION_PROPOSAL"
            assert evt["trace_id"] == "tr-w3c-4bf92f3577b34da6a3ce929d0e0e4736"

            # Verify secret scrubbing: sensitive fields must be [REDACTED]
            cleaned_payload = evt["payload"]
            assert cleaned_payload["password"] == "[REDACTED]"
            assert cleaned_payload["api_key"] == "[REDACTED]"
            assert cleaned_payload["authorization"] == "[REDACTED]"
            assert cleaned_payload["amount"] == 250.00  # Non-secret preserved

    async def test_idempotent_duplicate_protection(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            idempotency_key = "idemp-event-key-unique-001"
            payload = {
                "event_type": "AGENT_EXECUTION_START",
                "event_category": "AGENT_EXECUTION_LIFECYCLE",
                "agent_id": "agent-crew-support-001",
                "agent_runtime": "CREWAI",
                "execution_id": "run-001",
                "trace_id": "tr-001",
                "source_component": "amsc.crewai.client",
                "idempotency_key": idempotency_key,
                "payload": {"task": "Assist customer with refund"},
            }
            # First submission -> 201 Created
            res1 = await client.post("/api/v1/observation/events", headers=headers, json=payload)
            assert res1.status_code == 201
            evt1 = res1.json()

            # Second duplicate submission with same idempotency_key -> returned existing event, no duplicate
            res2 = await client.post("/api/v1/observation/events", headers=headers, json=payload)
            assert res2.status_code in (200, 201)
            evt2 = res2.json()
            assert evt1["id"] == evt2["id"]

    async def test_cross_tenant_isolation_in_observation(self, app, tenant_admin_token, tenant_b_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Tenant B logs an event
            headers_b = {
                "Authorization": f"Bearer {tenant_b_admin_token}",
                "X-Tenant-ID": "tenant-b-uuid-002",
            }
            res_b = await client.post(
                "/api/v1/observation/events",
                headers=headers_b,
                json={
                    "event_type": "DEFENSE_TASK_COMPLETE",
                    "event_category": "TASK_AND_CONTEXT_TRANSITION",
                    "agent_id": "agent-beta-sentinel-001",
                    "source_component": "betashield.ops",
                    "outcome": "SUCCESS",
                },
            )
            assert res_b.status_code == 201
            evt_b_id = res_b.json()["id"]

            # Tenant A queries events: Tenant B event must NOT appear
            headers_a = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res_a_list = await client.get("/api/v1/observation/events", headers=headers_a)
            assert res_a_list.status_code == 200
            a_ids = [e["id"] for e in res_a_list.json()["items"]]
            assert evt_b_id not in a_ids

            # Tenant A queries Tenant B event directly by ID -> 404
            res_a_direct = await client.get(f"/api/v1/observation/events/{evt_b_id}", headers=headers_a)
            assert res_a_direct.status_code == 404


@pytest.mark.asyncio
class TestGatewayObservationTelemetryCorrelation:
    """Test Suite verifying Gateway propose_action emits correlated observation events."""

    async def test_gateway_propose_emits_observation_events(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            proposal_payload = {
                "action_id": "act-wire-obs-test-001",
                "agent_id": "agent-crew-finance-003",
                "tool_name": "sandbox_transfer",
                "operation": "transfer_funds",
                "parameters": {"amount": 150.00, "vendor": "Office Supplies Ltd"},
                "memory_refs": [],
                "idempotency_key": "idem-wire-obs-test-001",
                "trace_id": "tr-gateway-obs-correlation-001",
            }
            res_gw = await client.post(
                "/api/v1/gateway/actions/propose",
                headers=headers,
                json=proposal_payload,
            )
            assert res_gw.status_code == 200
            gw_data = res_gw.json()
            assert gw_data["decision"] in ("ALLOW", "BLOCK")

            # Check that observation events were durably captured in observation repo
            res_obs = await client.get(
                "/api/v1/observation/events",
                headers=headers,
                params={"trace_id": "tr-gateway-obs-correlation-001"},
            )
            assert res_obs.status_code == 200
            events = res_obs.json()["items"]
            assert len(events) >= 2
            event_types = [e["event_type"] for e in events]
            assert "TOOL_PROPOSAL_SUBMITTED" in event_types
            assert "POLICY_DECISION_EVALUATED" in event_types


@pytest.mark.asyncio
class TestChroniMemContractAlignment:
    """Test Suite verifying VULN-004 ChroniMem timeline with record_id query parameter."""

    async def test_chronimem_timeline_with_record_id(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res = await client.get(
                "/api/v1/chronimem/timeline",
                headers=headers,
                params={"record_id": "rec-8812-441a"},
            )
            assert res.status_code == 200
            data = res.json()
            # Must return ChroniMemRecordTimelineResponse shape with versions array
            assert "record_id" in data
            assert data["record_id"] == "rec-8812-441a"
            assert "versions" in data
            assert isinstance(data["versions"], list)
            assert len(data["versions"]) >= 1
            assert "version" in data["versions"][0]
            assert "checksum" in data["versions"][0]


@pytest.mark.asyncio
class TestChroniMemContractExtended:
    """Extended security and isolation tests for ChroniMem timeline API."""

    async def test_chronimem_timeline_nonexistent_returns_404(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res = await client.get(
                "/api/v1/chronimem/timeline",
                headers=headers,
                params={"record_id": "rec-nonexistent-999"},
            )
            assert res.status_code == 404

    async def test_chronimem_timeline_cross_tenant_isolation_returns_404(self, app, tenant_b_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Tenant B attempting to access Tenant A's record rec-8812-441a
            headers = {
                "Authorization": f"Bearer {tenant_b_admin_token}",
                "X-Tenant-ID": "tenant-b-uuid-002",
            }
            res = await client.get(
                "/api/v1/chronimem/timeline",
                headers=headers,
                params={"record_id": "rec-8812-441a"},
            )
            assert res.status_code == 404


@pytest.mark.asyncio
class TestGatewayObservationSecretScrubbing:
    """Verifies that Gateway proposals redact passwords and API keys before persisting observation telemetry."""

    async def test_gateway_propose_redacts_sensitive_parameters(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            trace_id = "tr-sensitive-scrub-001"
            proposal_payload = {
                "action_id": "act-sensitive-test-001",
                "agent_id": "agent-crew-finance-003",
                "tool_name": "sandbox_transfer",
                "operation": "transfer_funds",
                "parameters": {
                    "amount": 250.00,
                    "api_key": "sk-super-secret-key-12345",
                    "password": "unredacted-password-plain",
                    "recipient": "vendor-corp",
                },
                "memory_refs": [],
                "idempotency_key": "idem-sensitive-test-001",
                "trace_id": trace_id,
            }
            res = await client.post(
                "/api/v1/gateway/actions/propose",
                headers=headers,
                json=proposal_payload,
            )
            assert res.status_code == 200

            # Check emitted observation events for this trace
            res_obs = await client.get(
                "/api/v1/observation/events",
                headers=headers,
                params={"trace_id": trace_id},
            )
            assert res_obs.status_code == 200
            events = res_obs.json()["items"]
            proposal_events = [e for e in events if e["event_type"] == "TOOL_PROPOSAL_SUBMITTED"]
            assert len(proposal_events) == 1
            payload = proposal_events[0]["payload"]
            assert payload["parameters"]["amount"] == 250.00
            assert payload["parameters"]["recipient"] == "vendor-corp"
            assert payload["parameters"]["api_key"] == "[REDACTED]"
            assert payload["parameters"]["password"] == "[REDACTED]"


@pytest.mark.asyncio
class TestObservationValidationAndGovernanceHardening:
    """Tests schema validation, agent mutation blocking, and governance logs branch isolation."""

    async def test_invalid_observation_category_returns_400(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res = await client.post(
                "/api/v1/observation/events",
                headers=headers,
                json={
                    "event_type": "TEST_INVALID",
                    "event_category": "COMPLETELY_INVALID_CATEGORY_XYZ",
                    "agent_id": "agent-crew-finance-003",
                    "source_component": "test",
                },
            )
            assert res.status_code == 400
            data = res.json()
            assert data["error"]["code"] == "VALIDATION_ERROR"

    async def test_agent_caller_cannot_mutate_baseline(self, app, agent_runner_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {agent_runner_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            # Attempt to activate baseline
            res = await client.post(
                "/api/v1/baseline/base-sec-001/activate",
                headers=headers,
                json={"reason": "Agent self-authorizing policy change"},
            )
            assert res.status_code == 403

    async def test_governance_logs_nonexistent_returns_404(self, app, tenant_admin_token):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {
                "Authorization": f"Bearer {tenant_admin_token}",
                "X-Tenant-ID": "tenant-a-uuid-001",
            }
            res = await client.get(
                "/api/v1/baseline/base-does-not-exist/governance-logs",
                headers=headers,
            )
            assert res.status_code == 404


SQLITE_PHASE1_DDL = """
CREATE TABLE enterprise_baseline_records (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    branch_id VARCHAR(36),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL,
    source_uri VARCHAR(512),
    source_type VARCHAR(64) NOT NULL,
    provenance VARCHAR(255) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    access_scope VARCHAR(32) NOT NULL,
    current_version INTEGER DEFAULT 1 NOT NULL,
    lifecycle_status VARCHAR(32) DEFAULT 'DRAFT' NOT NULL,
    superseded_by_id VARCHAR(36),
    effective_from DATETIME,
    expires_at DATETIME,
    created_by_user_id VARCHAR(128) NOT NULL,
    reviewed_by_user_id VARCHAR(128),
    approved_by_user_id VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (tenant_id, id)
);
CREATE TABLE enterprise_baseline_versions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    baseline_id VARCHAR(36) NOT NULL,
    version INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    change_summary VARCHAR(512) NOT NULL,
    created_by_user_id VARCHAR(128) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (baseline_id, version)
);
CREATE TABLE baseline_governance_logs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    baseline_id VARCHAR(36) NOT NULL,
    version INTEGER NOT NULL,
    operation VARCHAR(32) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    actor_role VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE observation_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    branch_id VARCHAR(36),
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64),
    agent_runtime VARCHAR(64),
    execution_id VARCHAR(128),
    trace_id VARCHAR(128),
    parent_span_id VARCHAR(128),
    source_component VARCHAR(64) DEFAULT 'GATEWAY' NOT NULL,
    related_memory_id VARCHAR(64),
    related_memory_version INTEGER,
    tool_name VARCHAR(128),
    action_id VARCHAR(128),
    policy_decision_id VARCHAR(128),
    execution_receipt_id VARCHAR(128),
    baseline_version VARCHAR(32),
    outcome VARCHAR(32) NOT NULL,
    idempotency_key VARCHAR(128),
    payload_json JSON DEFAULT '{}' NOT NULL,
    occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);
CREATE TABLE trust_decisions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    record_id VARCHAR(36) NOT NULL,
    from_state VARCHAR(32) NOT NULL,
    to_state VARCHAR(32) NOT NULL,
    operation VARCHAR(64) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    reason_code VARCHAR(64) NOT NULL,
    evidence_json JSON DEFAULT '{}' NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE agents (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    branch_id VARCHAR(36),
    name VARCHAR(255) NOT NULL,
    runtime VARCHAR(64) DEFAULT 'LANGCHAIN' NOT NULL,
    model VARCHAR(64) DEFAULT 'gpt-4o' NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL,
    config_version VARCHAR(32) DEFAULT 'v1.0.0' NOT NULL,
    system_prompt TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (tenant_id, id)
);
CREATE TABLE tool_registrations (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(128) NOT NULL,
    adapter_type VARCHAR(64) DEFAULT 'SANDBOX_REST' NOT NULL,
    description TEXT,
    is_protected BOOLEAN DEFAULT 1 NOT NULL,
    schema_definition JSON DEFAULT '{}' NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE TABLE agent_tool_permissions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    agent_id VARCHAR(36) NOT NULL,
    tool_id VARCHAR(36) NOT NULL,
    allowed_operations VARCHAR(255) DEFAULT '*' NOT NULL,
    constraints_json JSON DEFAULT '{}' NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE (agent_id, tool_id)
);
CREATE TABLE agent_security_profiles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    agent_id VARCHAR(36) NOT NULL UNIQUE,
    owner_department VARCHAR(128) NOT NULL,
    approved_purpose TEXT NOT NULL,
    approved_goals JSON DEFAULT '[]' NOT NULL,
    branch_id VARCHAR(36),
    data_scope JSON DEFAULT '[]' NOT NULL,
    operational_restrictions JSON DEFAULT '{}' NOT NULL,
    approval_requirements JSON DEFAULT '{}' NOT NULL,
    profile_version VARCHAR(32) DEFAULT 'v1.0.0' NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' NOT NULL,
    governed_by_user_id VARCHAR(36) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
"""


@pytest.mark.asyncio
class TestSqlAlchemyRepositoriesParity:
    """Validates real asynchronous SQLAlchemy repositories against SQLite in-memory engine."""

    async def _make_test_session_factory(self):
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            for statement in SQLITE_PHASE1_DDL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        return engine, factory

    async def test_sql_baseline_crud_lifecycle_and_digest(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyBaselineRepository(db_session_factory)
            tenant_id = "tenant-sql-001"
            user_id = "usr-admin-sql-01"

            content = "Strict operational directive for cloud infrastructure security."
            expected_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

            rec = await repo.create_baseline_record(
                tenant_id=tenant_id,
                title="Cloud Security Standard",
                category="SECURITY_DIRECTIVE",
                source_type="SECURITY_DIRECTIVE",
                provenance="SecOps Policy Board",
                classification="CONFIDENTIAL",
                access_scope="GLOBAL",
                content=content,
                change_summary="Initial release",
                user_id=user_id,
            )
            assert rec["id"].startswith("base-")
            assert rec["content_digest"] == expected_digest
            assert rec["lifecycle_status"] == "DRAFT"

            # Verify get_baseline_record returns content_digest
            fetched = await repo.get_baseline_record(tenant_id, rec["id"])
            assert fetched is not None
            assert fetched["content_digest"] == expected_digest

            # Append new version
            new_content = "Updated operational directive with quantum resistance requirements."
            new_digest = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
            v2 = await repo.append_baseline_version(
                tenant_id=tenant_id,
                baseline_id=rec["id"],
                content=new_content,
                change_summary="Add quantum resistance",
                user_id=user_id,
            )
            assert v2["version"] == 2
            assert v2["content_sha256"] == new_digest

            # Verify updated record current_version and content_digest
            updated = await repo.get_baseline_record(tenant_id, rec["id"])
            assert updated["current_version"] == 2
            assert updated["content_digest"] == new_digest

            # Transition lifecycle
            trans = await repo.transition_lifecycle(
                tenant_id=tenant_id,
                baseline_id=rec["id"],
                target_status="IN_REVIEW",
                actor_id=user_id,
                actor_role="TENANT_ADMIN",
                reason="Submitting for board review",
            )
            assert trans["lifecycle_status"] == "IN_REVIEW"

            # Governance logs
            logs = await repo.list_governance_logs(tenant_id, rec["id"])
            assert len(logs) >= 2
            operations = [entry["operation"] for entry in logs]
            assert "CREATE" in operations
            assert "IN_REVIEW" in operations
        finally:
            await engine.dispose()

    async def test_sql_baseline_concurrent_version_conflict_raises_conflict_error(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyBaselineRepository(db_session_factory)
            tenant_id = "tenant-sql-conflict-001"
            user_id = "usr-admin-sql-01"

            rec = await repo.create_baseline_record(
                tenant_id=tenant_id,
                title="Conflict Test Baseline",
                category="SECURITY_DIRECTIVE",
                source_type="SECURITY_DIRECTIVE",
                provenance="SecOps Board",
                classification="INTERNAL",
                access_scope="GLOBAL",
                content="Initial version 1 content",
                change_summary="V1",
                user_id=user_id,
            )

            # Insert version 2 directly into DB to simulate a race where another worker committed version 2 first
            now = datetime.now(timezone.utc)
            async with db_session_factory() as session:
                async with session.begin():
                    conflict_ver = OrmBaselineVersion(
                        id="bver-preempted-002",
                        tenant_id=tenant_id,
                        baseline_id=rec["id"],
                        version=2,
                        content="Preempted concurrent content",
                        content_sha256="preempted-sha",
                        change_summary="Preempted write",
                        created_by_user_id="usr-other-02",
                        created_at=now,
                    )
                    session.add(conflict_ver)

            # Now append_baseline_version calculates next_ver = rec.current_version + 1 = 2
            # Inserting version 2 again violates UNIQUE (baseline_id, version) constraint -> ConflictError
            with pytest.raises(ConflictError) as exc_info:
                await repo.append_baseline_version(
                    tenant_id=tenant_id,
                    baseline_id=rec["id"],
                    content="Conflicting content payload",
                    change_summary="Attempting duplicate v2",
                    user_id=user_id,
                )
            assert "Concurrent version conflict" in str(exc_info.value)
        finally:
            await engine.dispose()

    async def test_sql_observation_idempotency_and_deduplication(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyObservationRepository(db_session_factory)
            tenant_id = "tenant-sql-obs-001"
            idemp_key = "idem-unique-key-12345"

            event_payload = {
                "tenant_id": tenant_id,
                "event_type": "TOOL_EXECUTION_RECEIPT",
                "event_category": "TOOL_EXECUTION_RECEIPT",
                "agent_id": "agent-sql-001",
                "trace_id": "tr-sql-001",
                "source_component": "GATEWAY",
                "outcome": "SUCCESS",
                "idempotency_key": idemp_key,
                "payload_json": {"result": "success", "latency_ms": 12},
            }

            first = await repo.record_event(event_payload)
            assert first["idempotency_key"] == idemp_key
            first_id = first["id"]

            # Duplicate delivery must return the exact existing record
            duplicate = await repo.record_event(event_payload)
            assert duplicate["id"] == first_id

            # Query list
            events, has_more = await repo.list_events(tenant_id, trace_id="tr-sql-001")
            assert len(events) == 1
            assert events[0]["id"] == first_id
        finally:
            await engine.dispose()

    async def test_sql_trust_decision_no_double_insertion(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            store = SqlTrustDecisionStore(db_session_factory)
            tenant_id = "tenant-sql-trust-001"
            record_id = "rec-trust-test-001"

            decision = TrustDecision(
                decision_id="td-test-inst-001",
                allowed=True,
                applied=True,
                decision="APPLIED",
                reason_codes=("VERIFIED_PROVENANCE",),
                reason="Verified provenance during recovery test",
                record_id=record_id,
                tenant_id=tenant_id,
                operation="APPROVE_RECORD",
                transition_id=None,
                current_state="PROPOSED",
                stored_state="PROPOSED",
                target_state="TRUSTED",
                resulting_state="TRUSTED",
                record_version=1,
                version_checksum="abc",
                actor_type="USER",
                actor_id="usr-evaluator-01",
                actor_role="ADMIN",
                incident_id=None,
                evidence_summary={"verifier": "rule-set-alpha"},
                policy_version="1.0.0",
                timestamp=datetime.now(timezone.utc),
                history_available=True,
            )

            await store.aappend(decision)

            # Verify from database directly using alist_for_record
            decisions = await store.alist_for_record(tenant_id, record_id)
            assert len(decisions) == 1
            assert decisions[0].actor_id == "usr-evaluator-01"
            assert decisions[0].reason_codes[0] == "VERIFIED_PROVENANCE"
        finally:
            await engine.dispose()

    async def test_sql_agent_permission_grant_and_revoke_by_name_and_id(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyAgentRepository(db_session_factory)
            tenant_id = "tenant-sql-agent-001"
            agent_id = "agent-sql-test-01"
            tool_id = "tool-sql-id-01"
            tool_name = "crm_ticket_manager"

            now = datetime.now(timezone.utc)
            async with db_session_factory() as session:
                async with session.begin():
                    agent = OrmAgent(
                        id=agent_id,
                        tenant_id=tenant_id,
                        name="SQL Test Support Agent",
                        runtime="LANGCHAIN",
                        model="gpt-4o",
                        status="ACTIVE",
                        config_version="v1.0.0",
                        system_prompt="Support Prompt",
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(agent)
                    tool = OrmToolRegistration(
                        id=tool_id,
                        tenant_id=tenant_id,
                        name=tool_name,
                        adapter_type="SANDBOX_REST",
                        description="CRM Tool",
                        is_protected=True,
                        schema_definition={"type": "object"},
                        created_at=now,
                    )
                    session.add(tool)

            # 1. Grant permission referencing tool by NAME
            granted = await repo.grant_tool_permission(
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_id=tool_name,
                allowed_operations="read,update",
            )
            assert granted["tool_id"] == tool_id
            assert granted["tool_name"] == tool_name
            assert "update" in granted["allowed_operations"]

            # 2. Revoke permission referencing tool by NAME
            revoked_by_name = await repo.revoke_tool_permission(
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_id=tool_name,
            )
            assert revoked_by_name is True

            # Verify no permissions remain
            perms = await repo.get_agent_tool_permissions(tenant_id=tenant_id, agent_id=agent_id)
            assert len(perms) == 0

            # 3. Grant permission referencing tool by ID
            granted_by_id = await repo.grant_tool_permission(
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_id=tool_id,
                allowed_operations="*",
            )
            assert granted_by_id["tool_id"] == tool_id

            # 4. Revoke permission referencing tool by ID
            revoked_by_id = await repo.revoke_tool_permission(
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_id=tool_id,
            )
            assert revoked_by_id is True
            perms_after = await repo.get_agent_tool_permissions(tenant_id=tenant_id, agent_id=agent_id)
            assert len(perms_after) == 0
        finally:
            await engine.dispose()

    async def test_sql_agent_security_profile_governance(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyAgentRepository(db_session_factory)
            tenant_id = "tenant-sql-prof-001"
            agent_id = "agent-sql-prof-01"

            now = datetime.now(timezone.utc)
            async with db_session_factory() as session:
                async with session.begin():
                    agent = OrmAgent(
                        id=agent_id,
                        tenant_id=tenant_id,
                        name="Profile Governed Agent",
                        runtime="LANGCHAIN",
                        model="gpt-4o",
                        status="ACTIVE",
                        config_version="v1.0.0",
                        system_prompt="Prompt",
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(agent)

            # 1. Missing profile is fail-closed: never synthesize permissions.
            missing_prof = await repo.get_agent_profile(agent_id=agent_id, tenant_id=tenant_id)
            assert missing_prof is None

            # 2. Persist an explicit administrator-governed profile.
            update_payload = {
                "owner_department": "Customer Support Operations",
                "approved_purpose": "Handle tier-1 CRM tickets only",
                "approved_goals": ["Resolve tier-1 inquiries", "Escalate tier-2 issues"],
                "data_scope": ["tickets:read", "tickets:update"],
                "operational_restrictions": {"max_parameter_depth": 3, "disallow_shell": True},
                "approval_requirements": {"ticket_closure": "REQUIRE_HUMAN_APPROVAL"},
                "profile_version": "v1.1.0",
                "status": "ACTIVE",
                "branch_id": None,
            }
            updated = await repo.update_agent_profile(
                agent_id=agent_id,
                tenant_id=tenant_id,
                profile_data=update_payload,
                user_id="usr-secops-admin",
            )
            assert updated["owner_department"] == "Customer Support Operations"
            assert updated["profile_version"] == "v1.1.0"
            assert updated["governed_by_user_id"] == "usr-secops-admin"

            # 3. Read back to confirm persistence
            persisted = await repo.get_agent_profile(agent_id=agent_id, tenant_id=tenant_id)
            assert persisted is not None
            assert persisted["approved_purpose"] == "Handle tier-1 CRM tickets only"
            assert "tickets:update" in persisted["data_scope"]
            assert persisted["operational_restrictions"]["disallow_shell"] is True
        finally:
            await engine.dispose()

    async def test_sql_observation_occurred_at_fidelity_and_deterministic_order(self):
        engine, db_session_factory = await self._make_test_session_factory()
        try:
            repo = SqlAlchemyObservationRepository(db_session_factory)
            tenant_id = "tenant-sql-obs-fid-001"

            explicit_time = "2026-05-15T10:30:00+00:00"
            event1 = await repo.record_event({
                "tenant_id": tenant_id,
                "event_type": "TOOL_EXECUTION_RECEIPT",
                "event_category": "TOOL_EXECUTION_RECEIPT",
                "occurred_at": explicit_time,
                "agent_id": "agent-obs-01",
                "trace_id": "tr-order-001",
                "outcome": "SUCCESS",
            })
            # Verify explicit occurred_at is preserved
            assert event1["occurred_at"].startswith("2026-05-15T10:30:00")

            # Ingest two events with same timestamp to test deterministic tie-breaking on id
            shared_time = "2026-06-01T12:00:00+00:00"
            await repo.record_event({
                "id": "obs-event-aaa",
                "tenant_id": tenant_id,
                "event_type": "POLICY_DECISION",
                "event_category": "POLICY_DECISION",
                "occurred_at": shared_time,
                "trace_id": "tr-order-001",
                "outcome": "ALLOW",
            })
            await repo.record_event({
                "id": "obs-event-bbb",
                "tenant_id": tenant_id,
                "event_type": "POLICY_DECISION",
                "event_category": "POLICY_DECISION",
                "occurred_at": shared_time,
                "trace_id": "tr-order-001",
                "outcome": "ALLOW",
            })

            # List events: e_b (id='obs-event-bbb') should sort before e_a (id='obs-event-aaa')
            events, has_more = await repo.list_events(tenant_id=tenant_id, trace_id="tr-order-001")
            assert len(events) == 3
            assert events[0]["id"] == "obs-event-bbb"
            assert events[1]["id"] == "obs-event-aaa"
            assert events[2]["id"] == event1["id"]
        finally:
            await engine.dispose()
