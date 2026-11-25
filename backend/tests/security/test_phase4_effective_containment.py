"""Regression tests for effective, persisted Phase 4 containment actions."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.app.api.agents import AgentEntity, AgentVersionEntity, InMemoryAgentRepository
from backend.app.security.containment import (
    ContainmentAction,
    ContainmentRequest,
    ContainmentService,
    ContainmentStatus,
    ContainmentType,
)
from backend.app.security.investigation import IncidentStatus
from backend.app.tenancy.context import TenantContext


TENANT = "tenant-containment-test"
AGENT = "agent-containment-test"
ANALYST = TenantContext(
    tenant_id=TENANT,
    tenant_slug="test",
    tenant_name="Test",
    user_id="analyst-containment",
    role="SECURITY_ANALYST",
    is_active=True,
)


class Investigation:
    async def get_investigation(self, context, incident_id):
        assert context.tenant_id == TENANT
        assert incident_id == "incident-containment-test"
        return SimpleNamespace(status=IncidentStatus.OPEN)


class RuntimeCancellation:
    async def cancel_agent_work(self, *, tenant_id, agent_id, incident_id, trace_id):
        assert tenant_id == TENANT
        assert agent_id == AGENT
        return {
            "complete": True,
            "active_runs_cancelled": 1,
            "queued_jobs_cancelled": 2,
        }


def make_repository():
    repo = InMemoryAgentRepository()
    now = datetime.now(timezone.utc)
    agent = AgentEntity(
        id=AGENT,
        tenant_id=TENANT,
        name="Containment test agent",
        runtime="CREWAI",
        model="test-model",
        status="ACTIVE",
        config_version="v1.0.0",
        system_prompt="not used by these tests",
        created_at=now,
        updated_at=now,
    )
    version = AgentVersionEntity(
        id="version-containment-test",
        tenant_id=TENANT,
        agent_id=AGENT,
        version="v1.0.0",
        config_payload={},
        created_at=now,
    )
    return repo, agent, version


def make_request(*actions):
    return ContainmentRequest(
        incident_id="incident-containment-test",
        containment_actions=actions,
        reason="Verified suspicious agent activity",
    )


def make_service(repo, *, cancellation=None, resource_adapter=None):
    return ContainmentService(
        Investigation(),
        quarantine_workflow=None,
        memory_repository=None,
        agent_repository=repo,
        runtime_cancellation=cancellation,
        resource_isolation_adapter=resource_adapter,
    )


@pytest.mark.asyncio
async def test_agent_suspension_changes_authoritative_agent_state_and_records_evidence():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    service = make_service(repo, cancellation=RuntimeCancellation())
    persisted = []

    async def persist(outcome):
        persisted.append(outcome)

    outcome = await service.apply_containment(
        ANALYST,
        make_request(ContainmentAction(ContainmentType.AGENT_SUSPENSION, AGENT)),
        persist_evidence=persist,
    )

    stored = await repo.get_agent_by_id(AGENT, TENANT)
    assert outcome.success is True
    assert outcome.status is ContainmentStatus.APPLIED
    assert stored.status == "ISOLATED"
    profile = await repo.get_agent_profile(AGENT, TENANT)
    assert profile["status"] == "ISOLATED"
    assert len(persisted) == 1
    assert persisted[0].resulting_state == "ISOLATED"


@pytest.mark.asyncio
async def test_agent_suspension_does_not_claim_complete_without_runtime_cancellation():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    service = make_service(repo)
    persisted = []

    async def persist(outcome):
        persisted.append(outcome)

    outcome = await service.apply_containment(
        ANALYST,
        make_request(ContainmentAction(ContainmentType.AGENT_SUSPENSION, AGENT)),
        persist_evidence=persist,
    )

    stored = await repo.get_agent_by_id(AGENT, TENANT)
    assert stored.status == "ISOLATED"
    assert outcome.success is False
    assert outcome.status is ContainmentStatus.RECONCILIATION_REQUIRED
    assert len(persisted) == 1


@pytest.mark.asyncio
async def test_action_blocking_revokes_only_requested_operation_and_verifies_permission_state():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    await repo.grant_tool_permission(
        tenant_id=TENANT,
        agent_id=AGENT,
        tool_id="sandbox_transfer",
        allowed_operations="transfer_funds,get_balance",
    )
    service = make_service(repo)
    persisted = []

    async def persist(outcome):
        persisted.append(outcome)

    outcome = await service.apply_containment(
        ANALYST,
        make_request(
            ContainmentAction(
                ContainmentType.ACTION_BLOCKING,
                AGENT,
                {"tool_name": "sandbox_transfer", "operation": "transfer_funds"},
            )
        ),
        persist_evidence=persist,
    )

    permissions = await repo.get_agent_tool_permissions(AGENT, TENANT)
    grant = next(item for item in permissions if item["tool_name"] == "sandbox_transfer")
    assert outcome.success is True
    assert grant["allowed_operations"] == ["get_balance"]
    assert len(persisted) == 1


@pytest.mark.asyncio
async def test_multi_action_containment_returns_every_action_outcome():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    await repo.grant_tool_permission(
        tenant_id=TENANT,
        agent_id=AGENT,
        tool_id="sandbox_transfer",
        allowed_operations="transfer_funds,get_balance",
    )
    service = make_service(repo, cancellation=RuntimeCancellation())
    persisted = []

    async def persist(outcome):
        persisted.append(outcome)

    outcome = await service.apply_containment(
        ANALYST,
        make_request(
            ContainmentAction(ContainmentType.AGENT_SUSPENSION, AGENT),
            ContainmentAction(
                ContainmentType.ACTION_BLOCKING,
                AGENT,
                {"tool_name": "sandbox_transfer", "operation": "transfer_funds"},
            ),
        ),
        persist_evidence=persist,
    )

    assert outcome.success is True
    assert outcome.status is ContainmentStatus.APPLIED
    assert len(outcome.action_outcomes) == 2
    assert {item.containment_type for item in outcome.action_outcomes} == {
        ContainmentType.AGENT_SUSPENSION,
        ContainmentType.ACTION_BLOCKING,
    }
    assert len(persisted) == 2


@pytest.mark.asyncio
async def test_resource_isolation_without_authoritative_adapter_fails_closed():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    service = make_service(repo)
    persisted = []

    async def persist(outcome):
        persisted.append(outcome)

    outcome = await service.apply_containment(
        ANALYST,
        make_request(
            ContainmentAction(
                ContainmentType.RESOURCE_ISOLATION,
                "company-file-123",
                {"resource_type": "COMPANY_FILE"},
            )
        ),
        persist_evidence=persist,
    )

    assert outcome.success is False
    assert outcome.status is ContainmentStatus.FAILED
    assert not persisted


@pytest.mark.asyncio
async def test_evidence_failure_after_agent_isolation_is_reconciliation_required():
    repo, agent, version = make_repository()
    await repo.create_agent_atomic(agent, version)
    service = make_service(repo, cancellation=RuntimeCancellation())

    async def persist(_outcome):
        raise RuntimeError("audit database unavailable")

    outcome = await service.apply_containment(
        ANALYST,
        make_request(ContainmentAction(ContainmentType.AGENT_SUSPENSION, AGENT)),
        persist_evidence=persist,
    )

    stored = await repo.get_agent_by_id(AGENT, TENANT)
    assert stored.status == "ISOLATED"
    assert outcome.success is False
    assert outcome.status is ContainmentStatus.RECONCILIATION_REQUIRED
