"""Shared fixtures for M4 security tests (policy engine, trust evaluator).

Module: backend.tests.security.conftest
Owner: M4 — Security Engine & Incident Response Lead

Uses M3's real in-memory memory repository and services, M1's TenantContext,
the Day 3 TrustEvaluator and the Day 4 PolicyEngine. No production code is mocked
except where a test explicitly injects a failure.
"""

import uuid
from datetime import datetime, timezone

import pytest

import backend.tests.conftest  # noqa: F401  (Windows proactor patch, as in other suites)
from backend.app.memory import InMemoryMemoryRepository, ProvenanceEdge, ingest_memory
from backend.app.security.policy import PolicyConfig, PolicyEngine, ProtectedExecutionGuard, ToolGrant
from backend.app.security.trust import (
    OPERATION_TARGET,
    InMemoryTrustDecisionStore,
    TrustDimension,
    TrustEvaluator,
    TrustOperation,
    UserActor,
)
from backend.app.tenancy.context import TenantContext

T_A = "tenant-a-uuid-001"
T_B = "tenant-b-uuid-002"
AGENT = "agent-001"                      # seeded ACTIVE agent, tenant A
AGENT_ISOLATED = "agent-inactive-001"    # seeded ISOLATED agent, tenant A
AGENT_OTHER = "agent-head-office-001"    # seeded ACTIVE agent, tenant A
AGENT_B = "agent-b-001"                  # seeded ACTIVE agent, tenant B
SRC_A = "src-doc-001"
VENDOR = "ACC-VENDOR-VALID"
ATTACKER = "ACC-ATTACKER-999"


def make_ctx(role="AI_DEVELOPER", tenant=T_A, user="dev-1", active=True) -> TenantContext:
    return TenantContext(tenant_id=tenant, tenant_slug="s", tenant_name="n", user_id=user, role=role, is_active=active)


DEV = make_ctx()
ANALYST_ACTOR = UserActor(make_ctx(role="SECURITY_ANALYST", user="analyst-1"))
ADMIN_ACTOR = UserActor(make_ctx(role="TENANT_ADMIN", user="admin-1"))


def default_grant(**constraints) -> ToolGrant:
    base = {
        "max_amount": 500.0,
        "approval_threshold_amount": 300.0,
        "min_amount": 0,
        "allowed_destination_account": [VENDOR],
    }
    base.update(constraints)
    return ToolGrant(tool_name="sandbox_transfer", allowed_operations="transfer_funds,get_balance", constraints=base)


class Grants:
    """Test implementation of the ToolGrantDirectory port (M6 provides the real one)."""

    def __init__(self):
        self.grants = {(T_A, AGENT, "sandbox_transfer"): default_grant()}

    def get_tool_grant(self, tenant_id, agent_id, tool_name):
        return self.grants.get((tenant_id, agent_id, tool_name))


class World:
    def __init__(self, config: PolicyConfig | None = None):
        self.repo = InMemoryMemoryRepository()
        self.store = InMemoryTrustDecisionStore()
        self.trust = TrustEvaluator(self.repo, self.store, app_env="test")
        self.grants = Grants()
        self.engine = PolicyEngine(self.trust, self.repo, self.grants, config)
        self.guard = ProtectedExecutionGuard(self.engine)

    # -- memory -----------------------------------------------------------------
    def memory(self, content=None, tenant=T_A, source_id=SRC_A, parent=None, agent_id=None) -> str:
        rec, _ = ingest_memory(tenant, content or f"memo {uuid.uuid4()}",
                               source_id=source_id if tenant == T_A else None,
                               parent_record_id=parent, agent_id=agent_id, repository=self.repo)
        return rec.id

    def _request(self, rid, op, **evidence):
        rec = self.repo.get_record(rid, T_A)
        ev = {"evidence_refs": ["ev-1"], "incident_id": "inc-1"}
        if op is TrustOperation.VALIDATE:
            ver = self.repo.get_version(rid, rec.current_version, T_A)
            ev["validation"] = {
                "assessed_version": rec.current_version,
                "assessed_checksum": ver.checksum,
                "dimensions": {d.value: {"status": "PASS", "evidence_ref": "r"} for d in TrustDimension},
            }
        ev.update(evidence)
        return {
            "record_id": rid, "operation": op.value, "target_state": OPERATION_TARGET[op].value,
            "expected_state": self.trust.effective_state(T_A, rid), "expected_version": rec.current_version,
            "reason": "test", "evidence": ev,
        }

    def transition(self, rid, op, actor=ANALYST_ACTOR, **evidence):
        d = self.trust.apply(self._request(rid, op, **evidence), actor)
        assert d.applied, d.reason_codes
        return d

    def trusted_memory(self, **kw) -> str:
        rid = self.memory(**kw)
        self.transition(rid, TrustOperation.VALIDATE)
        return rid

    def memory_in_state(self, state: str) -> str:
        rid = self.memory()
        if state == "UNVERIFIED":
            return rid
        if state == "TRUSTED":
            self.transition(rid, TrustOperation.VALIDATE)
        elif state == "SUSPICIOUS":
            self.transition(rid, TrustOperation.FLAG_SUSPICIOUS)
        elif state == "QUARANTINED":
            self.transition(rid, TrustOperation.QUARANTINE)
        elif state == "REJECTED":
            self.transition(rid, TrustOperation.REJECT)
        elif state == "SUPERSEDED":
            self.transition(rid, TrustOperation.VALIDATE)
            succ = self.trusted_memory()
            self.repo.create_edge(ProvenanceEdge(id=str(uuid.uuid4()), tenant_id=T_A, from_record_id=succ,
                                                 to_record_id=rid, relation_type="SUPERSEDES"))
            self.transition(rid, TrustOperation.SUPERSEDE, successor_record_id=succ)
        assert self.repo.get_record(rid, T_A).trust_state == state
        return rid


def proposal(memory_refs, amount=150.0, destination=VENDOR, agent=AGENT, tool="sandbox_transfer",
             operation="transfer_funds", **overrides):
    p = {
        "action_id": f"act-{uuid.uuid4().hex[:8]}",
        "agent_id": agent,
        "tool_name": tool,
        "operation": operation,
        "parameters": {"destination_account": destination, "amount": amount, "currency": "USD"},
        "memory_refs": list(memory_refs),
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
        "trace_id": "tr-test-01",
    }
    p.update(overrides)
    return p


class SpyAdapter:
    """Protected adapter stand-in that records every invocation."""

    def __init__(self, fail_with: Exception | None = None):
        self.calls = []
        self.fail_with = fail_with

    async def __call__(self, grant):
        self.calls.append(grant)
        if self.fail_with is not None:
            raise self.fail_with
        return {"transaction_id": "tx-sbx-test", "status": "SETTLED_IN_SANDBOX"}


@pytest.fixture
def world():
    return World()


FIXED_NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
