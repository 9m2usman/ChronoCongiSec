"""Phase 3 security tests: M4 decisions for company operations and adapter fail-closed paths.

These tests need no database. They cover:
* M4 REVIEW (REQUIRES_APPROVAL) for the high-impact ``company_workspace:transfer_file``
  operation, bound human approval, and that the guard never dispatches without ALLOW;
* the server-side company adapter rejecting direct invocation, agent-supplied scope,
  malformed parameters and unavailable persistence, always as FAILED (never success);
* the adapter being registered only when company persistence exists.

Database-backed end-to-end execution is in
``backend/tests/database/test_phase3_connected_agent_execution.py``.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import OperationalError

from backend.app.api.gateway import get_default_tool_registry
from backend.app.core.config import Settings
from backend.app.gateway.adapters.company import (
    FORBIDDEN_SCOPE_KEYS,
    PARAMETER_SCHEMAS,
    TOOL_NAME,
    CompanyOperationsAdapter,
)
from backend.app.main import create_app
from backend.app.security import policy as policy_mod
from backend.app.security.policy import (
    DEFAULT_TOOL_POLICIES,
    ApprovalEvidence,
    PolicyConfig,
    PolicyOutcome,
    PolicyResult,
    ToolGrant,
    ToolPolicy,
    decision_is_executable,
)
from backend.tests.security.conftest import AGENT, DEV, T_A, SpyAdapter, World


def run(coro):
    return asyncio.run(coro)


def company_proposal(operation: str, parameters: dict, agent: str = AGENT) -> dict:
    return {
        "action_id": f"act-{uuid.uuid4().hex[:8]}",
        "agent_id": agent,
        "tool_name": TOOL_NAME,
        "operation": operation,
        "parameters": parameters,
        "memory_refs": [],
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
        "trace_id": "tr-phase3-01",
    }


def company_world(config: PolicyConfig | None = None) -> World:
    world = World(config)
    world.grants.grants[(T_A, AGENT, TOOL_NAME)] = ToolGrant(
        tool_name=TOOL_NAME,
        allowed_operations="create_file,transfer_file,send_message",
        constraints={},
    )
    return world


def approval_for(proposal: dict, **overrides) -> ApprovalEvidence:
    facts = policy_mod.normalize_proposal(proposal)
    values = dict(
        approval_id=f"appr-{uuid.uuid4().hex[:8]}",
        tenant_id=T_A,
        status="APPROVED",
        proposal_fingerprint=policy_mod.proposal_fingerprint(facts, T_A, DEV.user_id),
        approver_user_id="analyst-1",
        approver_role="SECURITY_ANALYST",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    values.update(overrides)
    return ApprovalEvidence(**values)


TRANSFER = {"file_id": "file-1", "recipient_user_id": "usr-2"}


# ----------------------------------------------------------------------------
# M4 decisions
# ----------------------------------------------------------------------------

def test_transfer_file_is_registered_as_high_impact_policy():
    policy = DEFAULT_TOOL_POLICIES[(TOOL_NAME, "transfer_file")]
    assert policy.always_requires_review is True and policy.review_permitted is True


def test_transfer_file_without_approval_requires_review_and_is_not_executable():
    world = company_world()
    decision = run(world.engine.evaluate(company_proposal("transfer_file", TRANSFER), DEV))
    assert decision.outcome is PolicyOutcome.REQUIRES_APPROVAL
    assert decision.policy_result is PolicyResult.ELEVATED
    assert "HIGH_IMPACT_APPROVAL_REQUIRED" in decision.reason_codes
    assert not decision_is_executable(decision)


def test_guard_never_dispatches_company_transfer_without_approval():
    world = company_world()
    proposal = company_proposal("transfer_file", TRANSFER)
    decision = run(world.engine.evaluate(proposal, DEV))
    spy, persisted = SpyAdapter(), []

    async def persist(d):
        persisted.append(d)

    outcome = run(world.guard.execute(decision, proposal, DEV, persist_decision=persist, executor=spy))
    assert outcome.executed is False and spy.calls == []


def test_transfer_file_with_bound_human_approval_is_allowed():
    world = company_world()
    proposal = company_proposal("transfer_file", TRANSFER)
    decision = run(world.engine.evaluate(proposal, DEV, approval=approval_for(proposal)))
    assert decision.outcome is PolicyOutcome.ALLOW, decision.reason_codes
    assert decision_is_executable(decision)


def test_transfer_file_approval_for_another_proposal_is_blocked():
    world = company_world()
    approved = company_proposal("transfer_file", TRANSFER)
    other = company_proposal("transfer_file", {"file_id": "file-1", "recipient_user_id": "usr-attacker"})
    decision = run(world.engine.evaluate(other, DEV, approval=approval_for(approved)))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "APPROVAL_SCOPE_MISMATCH" in decision.reason_codes


def test_transfer_file_self_approval_is_blocked():
    world = company_world()
    proposal = company_proposal("transfer_file", TRANSFER)
    approval = approval_for(proposal, approver_user_id=DEV.user_id)
    decision = run(world.engine.evaluate(proposal, DEV, approval=approval))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "APPROVAL_SELF_APPROVAL" in decision.reason_codes


def test_high_impact_operation_without_review_permission_is_blocked():
    config = PolicyConfig(tool_policies={
        (TOOL_NAME, "transfer_file"): ToolPolicy(review_permitted=False, always_requires_review=True),
    })
    world = company_world(config)
    decision = run(world.engine.evaluate(company_proposal("transfer_file", TRANSFER), DEV))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "REVIEW_NOT_PERMITTED" in decision.reason_codes


def test_routine_company_operation_is_allowed_by_grant():
    world = company_world()
    decision = run(world.engine.evaluate(
        company_proposal("send_message", {"recipient_user_id": "usr-2", "body": "hi"}), DEV))
    assert decision.outcome is PolicyOutcome.ALLOW, decision.reason_codes


def test_ungranted_company_operation_is_blocked():
    world = company_world()
    decision = run(world.engine.evaluate(company_proposal("handoff_task", {"task_id": "t", "assigned_to_user_id": "u"}), DEV))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "OPERATION_DENIED" in decision.reason_codes


def test_company_tool_without_grant_is_blocked():
    world = World()
    decision = run(world.engine.evaluate(company_proposal("create_file", {}), DEV))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "TOOL_NOT_ASSIGNED" in decision.reason_codes


def test_unregistered_company_adapter_blocks():
    world = company_world()
    world.grants.grants[(T_A, AGENT, TOOL_NAME)] = ToolGrant(
        tool_name=TOOL_NAME, allowed_operations="create_file", constraints={}, tool_registered=False)
    decision = run(world.engine.evaluate(company_proposal("create_file", {}), DEV))
    assert decision.outcome is PolicyOutcome.BLOCK
    assert "TOOL_NOT_REGISTERED" in decision.reason_codes


# ----------------------------------------------------------------------------
# Adapter fail-closed behaviour (no database reachable or needed)
# ----------------------------------------------------------------------------

class _ExplodingFactory:
    """Session factory that must never be used."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("adapter touched persistence before rejecting the request")


class _UnavailableSession:
    async def __aenter__(self):
        raise OperationalError("SELECT 1", {}, ConnectionRefusedError("database down"))

    async def __aexit__(self, *exc):
        return False


def _context(**overrides) -> dict:
    ctx = {
        "tenant_id": T_A, "agent_id": AGENT, "idempotency_key": "idem-1", "trace_id": "tr-1",
        "proposal_id": "prop-1", "grant_id": "grant-1", "user_id": "usr-dev-dave-03",
        "role": "AI_DEVELOPER", "branch_id": "branch-khi-003",
    }
    ctx.update(overrides)
    return ctx


def test_adapter_requires_a_session_factory():
    with pytest.raises(ValueError):
        CompanyOperationsAdapter(None)


@pytest.mark.parametrize("missing", ["tenant_id", "agent_id", "proposal_id", "user_id", "role", "trace_id"])
def test_direct_adapter_invocation_without_gateway_context_fails(missing):
    factory = _ExplodingFactory()
    adapter = CompanyOperationsAdapter(factory)
    result = run(adapter.execute("read_inbox", {}, _context(**{missing: None})))
    assert result.status == "FAILED" and result.status_code == 403
    assert result.result_payload["error_code"] == "GATEWAY_CONTEXT_REQUIRED"
    assert factory.calls == 0


def test_adapter_rejects_non_dict_context():
    result = run(CompanyOperationsAdapter(_ExplodingFactory()).execute("read_inbox", {}, None))
    assert result.status == "FAILED" and result.status_code == 403


@pytest.mark.parametrize("forged", sorted(FORBIDDEN_SCOPE_KEYS))
def test_agent_supplied_scope_is_rejected_before_persistence(forged):
    factory = _ExplodingFactory()
    params = {"workspace_id": "ws-1", forged: "branch-ho-001"}
    result = run(CompanyOperationsAdapter(factory).execute("list_files", params, _context()))
    assert result.status == "FAILED" and result.status_code == 403
    assert result.result_payload["error_code"] == "AGENT_SUPPLIED_SCOPE_REJECTED"
    assert factory.calls == 0


def test_unsupported_operation_is_rejected():
    result = run(CompanyOperationsAdapter(_ExplodingFactory()).execute("drop_tables", {}, _context()))
    assert result.status == "FAILED" and result.status_code == 400
    assert result.result_payload["error_code"] == "OPERATION_UNSUPPORTED"


@pytest.mark.parametrize("operation,params", [
    ("list_files", {}),                                         # missing workspace
    ("list_files", {"workspace_id": 7}),                        # wrong type (strict)
    ("list_files", {"workspace_id": "../../etc/passwd"}),       # not an identifier
    ("create_file", {"workspace_id": "ws", "name": "a", "content": "x", "unexpected": 1}),
    ("send_message", {"recipient_user_id": "u", "body": ""}),   # empty body
    ("read_inbox", {"anything": True}),
])
def test_malformed_parameters_are_rejected(operation, params):
    factory = _ExplodingFactory()
    result = run(CompanyOperationsAdapter(factory).execute(operation, params, _context()))
    assert result.status == "FAILED" and result.status_code == 400
    assert result.result_payload["error_code"] == "PARAMETERS_INVALID"
    assert factory.calls == 0


def test_unavailable_persistence_fails_closed_never_success():
    adapter = CompanyOperationsAdapter(lambda: _UnavailableSession())
    result = run(adapter.execute("read_inbox", {}, _context()))
    assert result.status == "FAILED" and result.status_code == 503
    assert result.result_payload["error_code"] == "COMPANY_PERSISTENCE_UNAVAILABLE"


def test_every_operation_has_a_strict_schema():
    assert set(PARAMETER_SCHEMAS) == set(CompanyOperationsAdapter.allowed_operations)
    for schema in PARAMETER_SCHEMAS.values():
        assert schema.model_config.get("extra") == "forbid"


def test_company_adapter_not_registered_without_persistence():
    settings = Settings(
        APP_ENV="development",
        JWT_SECRET="test-secret-key-at-least-32-characters-long",
        DATABASE_URL="",
        ALLOW_IN_MEMORY_AUTH=True,
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )
    app = create_app(settings)

    async def start():
        async with app.router.lifespan_context(app):
            registry = getattr(app.state, "tool_registry", None) or get_default_tool_registry()
            return registry.get_adapter(TOOL_NAME)

    assert run(start()) is None
    assert get_default_tool_registry().get_adapter(TOOL_NAME) is None
