"""Day 7 fail-closed security suite (M4): infrastructure failures must never execute a protected action.

Module: backend.tests.security.test_fail_closed
Owner: M4 — Security Engine & Incident Response Lead
Plan: Doc 06 Day 7, M4 row — "Review fail-closed behavior across simulated infrastructure
failures"; exit: "All simulated outages trigger BLOCK".

Every scenario asserts BOTH the safe result AND the absence of the dangerous side effect:
the ``SpyAdapter`` records every invocation and must stay empty.

Real interfaces exercised:
- M4: ``PolicyEngine``, ``ProtectedExecutionGuard``, ``TrustEvaluator``, ``QuarantineWorkflow``,
  ``DriftReviewService`` + ``SqlDriftReviewStore``.
- M6: ``UnitOfWork`` and ``AuditEventRepository`` (driven by a fault-injecting async session —
  no PostgreSQL is available in this environment; see report).
- M1: ``get_tenant_context`` (JWT + membership), ``InMemoryRateLimiter``, ``RateLimitResult``,
  global exception handlers.
- M3: in-memory memory repository and services.

No real sleeps: timeouts are injected deterministically.
"""

import asyncio
import logging
import uuid
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Body, Depends, FastAPI, Request
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.sql.dml import Update
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.sql.selectable import Select

from backend.app.core.config import Settings
from backend.app.core.dependencies import InMemoryRateLimiter, RateLimitResult, get_tenant_context
from backend.app.core.exceptions import SecurityDependencyError, register_exception_handlers
from backend.app.core.security import create_access_token
from backend.app.database.models import AuditEvent
from backend.app.database.unit_of_work import UnitOfWork
from backend.app.memory import retrieve_memory, transition_memory_trust_state, update_memory
from backend.app.security import policy as policy_mod
from backend.app.security.drift import DriftReviewService, SqlDriftReviewStore
from backend.app.security.policy import (
    MandatoryControl,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyOutcome,
    PolicyResult,
    ToolGrant,
    decision_is_executable,
    lock_control,
    rate_limit_control,
)
from backend.app.security.quarantine import QuarantineStatus, QuarantineWorkflow
from backend.app.security.trust import ActionMemoryAssessment
from backend.app.tenancy.context import InMemoryAuthRepository, MembershipRecord, TenantRecord, UserRecord
from backend.tests.security.conftest import (
    AGENT,
    AGENT_ISOLATED,
    DEV,
    T_A,
    T_B,
    SpyAdapter,
    World,
    make_ctx,
    proposal,
)

SECRET_DSN = "postgresql+asyncpg://amsc:S3CR3T-PG-PASSWORD@db.internal:5432/amsc"
SECRET_REDIS = "redis://:S3CR3T-REDIS-PASSWORD@redis.internal:6379/0"


def run(coro):
    return asyncio.run(coro)


# =============================================================================
# Fault-injecting async session for M6's real UnitOfWork / repositories
# =============================================================================

class FaultySessionFactory:
    """Callable like an ``async_sessionmaker``; each session supports what M6's UnitOfWork,
    TenantScopedRepository and AuditEventRepository use. Writes become visible in
    ``committed`` only when the transaction commits successfully."""

    def __init__(self, faults=None, rows=None):
        self.faults = dict(faults or {})   # stage -> exception: connect|set_config|select|update|flush|refresh|commit
        self.rows = rows or {}             # (tenant, obs_id) -> row object for SELECT ... FOR UPDATE
        self.committed = []                # (kind, payload) after successful commit
        self.sessions = 0

    def __call__(self):
        self.sessions += 1
        return _FaultySession(self)


class _FaultySession:
    def __init__(self, factory):
        self.f = factory
        self.pending = []

    async def __aenter__(self):
        if "connect" in self.f.faults:
            raise self.f.faults["connect"]
        return self

    async def __aexit__(self, *exc):
        return False

    def begin(self):
        return _FaultyTx(self)

    async def execute(self, stmt, params=None):
        if isinstance(stmt, TextClause):
            stage = "set_config"
        elif isinstance(stmt, Select):
            stage = "select"
        elif isinstance(stmt, Update):
            stage = "update"
        else:
            stage = "other"
        if stage in self.f.faults:
            raise self.f.faults[stage]
        if stage == "select":
            row = next(iter(self.f.rows.values()), None)
            return SimpleNamespace(scalar_one_or_none=lambda: row, scalars=lambda: SimpleNamespace(all=lambda: []))
        if stage == "update":
            row = next(iter(self.f.rows.values()), None)
            self.pending.append(("update", row.id if row else None))
            return SimpleNamespace(scalar_one_or_none=lambda: row.id if row else None)
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, obj):
        self.pending.append(("add", obj))

    async def flush(self):
        if "flush" in self.f.faults:
            raise self.f.faults["flush"]

    async def refresh(self, obj, attribute_names=None):
        if "refresh" in self.f.faults:
            raise self.f.faults["refresh"]
        obj.chain_seq, obj.prev_hash, obj.event_hash = 1, None, "0" * 64


class _FaultyTx:
    def __init__(self, session):
        self.s = session

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.s.pending.clear()                 # ROLLBACK
            return False
        if "commit" in self.s.f.faults:
            self.s.pending.clear()
            raise self.s.f.faults["commit"]
        self.s.f.committed.extend(self.s.pending)  # COMMIT
        return False


def m6_persist(factory):
    """Gateway-style decision persistence through M6's real UnitOfWork + AuditEventRepository."""
    async def persist(decision: PolicyDecision):
        async with UnitOfWork(factory)(decision.tenant_id) as tx:
            await tx.audit.append(AuditEvent(
                id=str(uuid.uuid4()), actor_id=decision.principal_id or "unknown", event_type="TOOL_POLICY_DECIDED",
                resource_id=decision.decision_id, action=f"{decision.tool_name}:{decision.operation}",
                outcome=decision.outcome.value, trace_id=decision.trace_id,
                details_json=decision.to_persistence_record()["details_json"],
            ))
    return persist


DB_FAULTS = {
    "connection refused": ("connect", ConnectionRefusedError(f"connect to {SECRET_DSN} refused")),
    "connection timeout": ("connect", TimeoutError("connect timeout")),
    "session/statement failure": ("set_config", OperationalError("SET", {}, Exception(SECRET_DSN))),
    "query failure (flush)": ("flush", DBAPIError("INSERT", {}, Exception("server closed the connection"))),
    "constraint failure": ("flush", IntegrityError("INSERT", {}, Exception("23503"))),
    "post-insert refresh failure": ("refresh", OperationalError("SELECT", {}, Exception("lost"))),
    "commit failure": ("commit", OperationalError("COMMIT", {}, Exception("could not commit"))),
    "asyncio timeout": ("flush", asyncio.TimeoutError()),
    "unexpected exception": ("flush", RuntimeError("driver bug")),
}


@pytest.fixture
def w():
    return World()


def allow_decision(w, **kw):
    p = proposal([w.trusted_memory()], **kw)
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.ALLOW, d.reason_codes
    return p, d


def guard(w, d, p, *, persist=None, controls=(), spy=None, ctx=DEV, approval=None):
    spy = spy or SpyAdapter()
    persisted = []

    async def default_persist(dec):
        persisted.append(dec.decision_id)

    out = run(w.guard.execute(d, p, ctx, persist_decision=persist or default_persist, executor=spy,
                              mandatory_controls=controls, approval=approval))
    return out, spy, persisted


# =============================================================================
# Group 1 — Database failures (decision / audit persistence through M6 UnitOfWork)
# =============================================================================

@pytest.mark.parametrize("label", list(DB_FAULTS))
def test_db_failure_during_decision_persistence_blocks_execution(w, label, caplog):
    stage, exc = DB_FAULTS[label]
    factory = FaultySessionFactory({stage: exc})
    p, d = allow_decision(w)
    caplog.set_level(logging.DEBUG)
    out, spy, _ = guard(w, d, p, persist=m6_persist(factory))
    assert not out.executed and out.status == "NOT_EXECUTED"
    assert out.reason_codes == ("AUDIT_PERSISTENCE_FAILED",)
    assert spy.calls == []                       # adapter never invoked
    assert factory.committed == []               # nothing claimed durable
    assert "S3CR3T-PG-PASSWORD" not in caplog.text and "S3CR3T" not in repr(out)


def test_db_healthy_path_persists_then_executes(w):
    factory = FaultySessionFactory()
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, persist=m6_persist(factory))
    assert out.executed and out.status == "EXECUTED" and len(spy.calls) == 1
    kinds = [k for k, _ in factory.committed]
    assert kinds == ["add"] and isinstance(factory.committed[0][1], AuditEvent)


def test_persistence_reporting_false_is_a_failure(w):
    p, d = allow_decision(w)

    async def returns_false(_):
        return False

    out, spy, _ = guard(w, d, p, persist=returns_false)
    assert out.reason_codes == ("AUDIT_PERSISTENCE_FAILED",) and spy.calls == []


@pytest.mark.parametrize("persist", [None, "not-callable", 42])
def test_missing_persistence_dependency_blocks_execution(w, persist):
    p, d = allow_decision(w)
    out = run(w.guard.execute(d, p, DEV, persist_decision=persist, executor=SpyAdapter()))
    assert not out.executed and out.reason_codes == ("AUDIT_PERSISTENCE_FAILED",)


def test_memory_repository_outage_blocks_at_policy(w, monkeypatch):
    p = proposal([w.trusted_memory()])
    monkeypatch.setattr(w.repo, "get_record", lambda *a, **k: (_ for _ in ()).throw(ConnectionResetError()))
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "MEMORY_TRUST_UNAVAILABLE" in d.reason_codes
    out, spy, _ = guard(w, d, p)
    assert spy.calls == [] and not out.executed


@pytest.mark.parametrize("label", ["connection refused", "session/statement failure", "query failure (flush)",
                                   "commit failure", "unexpected exception"])
def test_db_failure_during_drift_review_never_reports_success(label):
    """M4 drift review through the real SqlDriftReviewStore -> M6 UnitOfWork -> audit repository."""
    stage, exc = DB_FAULTS[label]
    row = SimpleNamespace(id="obs-1", tenant_id=T_A, record_id="mem-1", classification="POTENTIAL_POISONING",
                          divergence_score="0.78", evidence_summary="x", reviewer_status="PENDING", created_at=None)
    factory = FaultySessionFactory({stage: exc}, rows={(T_A, "obs-1"): row})
    svc = DriftReviewService(SqlDriftReviewStore(factory))
    with pytest.raises(SecurityDependencyError):
        run(svc.review(make_ctx(role="SECURITY_ANALYST", user="analyst-1"), "obs-1", "REJECTED"))
    assert factory.committed == []


def test_drift_review_cas_failure_at_update_rolls_back():
    row = SimpleNamespace(id="obs-1", tenant_id=T_A, record_id="mem-1", classification="OUTDATED",
                          divergence_score="0.40", evidence_summary="x", reviewer_status="PENDING", created_at=None)
    factory = FaultySessionFactory({"update": OperationalError("UPDATE", {}, Exception("deadlock"))},
                                   rows={(T_A, "obs-1"): row})
    with pytest.raises(SecurityDependencyError):
        run(DriftReviewService(SqlDriftReviewStore(factory)).review(
            make_ctx(role="SECURITY_ANALYST", user="a"), "obs-1", "APPROVED"))
    assert factory.committed == []


def test_drift_review_healthy_path_commits_status_and_audit_together():
    row = SimpleNamespace(id="obs-1", tenant_id=T_A, record_id="mem-1", classification="OUTDATED",
                          divergence_score="0.40", evidence_summary="x", reviewer_status="PENDING", created_at=None)
    factory = FaultySessionFactory(rows={(T_A, "obs-1"): row})
    out = run(DriftReviewService(SqlDriftReviewStore(factory)).review(
        make_ctx(role="SECURITY_ANALYST", user="a"), "obs-1", "APPROVED"))
    assert out.kind.value == "APPLIED" and out.audit_event_id
    assert [k for k, _ in factory.committed] == ["update", "add"]


class _BadDriftStore:
    def __init__(self, list_result=None, review_result=None):
        self.list_result, self.review_result = list_result, review_result

    async def list_observations(self, tenant_id, **kw):
        return self.list_result

    async def review(self, tenant_id, observation_id, decide, audit):
        return self.review_result


@pytest.mark.parametrize("bad", [None, "rows", {"id": "x"}, [{"id": "obs-1", "tenant_id": T_A}], [object()]])
def test_drift_store_invalid_list_result_is_503_not_data(bad):
    svc = DriftReviewService(_BadDriftStore(list_result=bad))
    with pytest.raises(SecurityDependencyError):
        run(svc.list_observations(make_ctx(role="AI_DEVELOPER", user="d")))


@pytest.mark.parametrize("bad", ["applied", {"plan": "APPLY"}, SimpleNamespace(plan=None, before=None, after=None), 1])
def test_drift_store_invalid_review_result_is_503_not_success(bad):
    svc = DriftReviewService(_BadDriftStore(review_result=bad))
    with pytest.raises(SecurityDependencyError):
        run(svc.review(make_ctx(role="SECURITY_ANALYST", user="a"), "obs-1", "APPROVED"))


def test_quarantine_evidence_store_outage_reverts_and_reports_failure(w, monkeypatch):
    rid = w.trusted_memory()
    monkeypatch.setattr(w.store, "append", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    out = run(QuarantineWorkflow(w.trust, w.repo).quarantine(
        make_ctx(role="SECURITY_ANALYST", user="analyst-1"), {"record_id": rid, "reason": "r"},
        persist_evidence=lambda o: asyncio.sleep(0)))
    assert not out.success and out.status is QuarantineStatus.FAILED
    assert w.repo.get_record(rid, T_A).trust_state == "TRUSTED"   # no false claim of quarantine


# =============================================================================
# Group 2 — Redis failures (mandatory distributed controls)
# =============================================================================

class _Limiter:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    async def check_rate_limit(self, key, max_requests, window_seconds):
        if isinstance(self.behaviour, BaseException):
            raise self.behaviour
        return self.behaviour


REDIS_FAILURES = {
    "connection refused": ConnectionRefusedError(f"{SECRET_REDIS} refused"),
    "timeout": TimeoutError("redis timeout"),
    "asyncio timeout": asyncio.TimeoutError(),
    "unavailable (M1 SecurityDependencyError)": SecurityDependencyError("Rate limiting service unavailable."),
    "unexpected exception": RuntimeError("lua script error"),
    "OS error": OSError("network unreachable"),
}


@pytest.mark.parametrize("label", list(REDIS_FAILURES))
def test_rate_limit_backend_failure_blocks_execution(w, label, caplog):
    p, d = allow_decision(w)
    persisted = []

    async def persist(dec):
        persisted.append(dec)

    caplog.set_level(logging.DEBUG)
    control = rate_limit_control(_Limiter(REDIS_FAILURES[label]), f"gw:{T_A}:{AGENT}", 100, 60)
    out, spy, _ = guard(w, d, p, persist=persist, controls=(control,))
    assert not out.executed and out.reason_codes == ("MANDATORY_CONTROL_UNAVAILABLE",)
    assert spy.calls == [] and persisted == []
    assert "S3CR3T-REDIS-PASSWORD" not in caplog.text


@pytest.mark.parametrize("result", [
    None, {"allowed": True}, True, "allowed", SimpleNamespace(allowed=True),
    RateLimitResult(allowed=False, retry_after=30), RateLimitResult(allowed="true"), RateLimitResult(allowed=1),
])
def test_rate_limit_invalid_or_denied_result_blocks_execution(w, result):
    p, d = allow_decision(w)
    out, spy, persisted = guard(w, d, p, controls=(rate_limit_control(_Limiter(result), "k", 1, 60),))
    assert out.reason_codes == ("MANDATORY_CONTROL_DENIED",) and spy.calls == [] and persisted == []


def test_real_m1_in_memory_limiter_unavailable_blocks(w):
    limiter = InMemoryRateLimiter()
    limiter.is_available = False                       # M1's own outage switch
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, controls=(rate_limit_control(limiter, "k", 10, 60),))
    assert out.reason_codes == ("MANDATORY_CONTROL_UNAVAILABLE",) and spy.calls == []


def test_real_m1_limiter_exhausted_blocks_second_action(w):
    limiter = InMemoryRateLimiter()
    p1, d1 = allow_decision(w)
    p2, d2 = allow_decision(w)
    spy = SpyAdapter()
    first, _, _ = guard(w, d1, p1, spy=spy, controls=(rate_limit_control(limiter, "agent-k", 1, 60),))
    second, _, _ = guard(w, d2, p2, spy=spy, controls=(rate_limit_control(limiter, "agent-k", 1, 60),))
    assert first.executed and not second.executed and second.reason_codes == ("MANDATORY_CONTROL_DENIED",)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("acquire_result", [False, None, "OK", 1, b"1", {"acquired": True}])
def test_idempotency_lock_not_acquired_blocks_execution(w, acquire_result):
    p, d = allow_decision(w)

    async def acquire():
        return acquire_result

    out, spy, persisted = guard(w, d, p, controls=(lock_control(acquire),))
    assert out.reason_codes == ("MANDATORY_CONTROL_DENIED",) and spy.calls == [] and persisted == []


@pytest.mark.parametrize("label", list(REDIS_FAILURES))
def test_idempotency_lock_failure_blocks_execution(w, label):
    p, d = allow_decision(w)

    async def acquire():
        raise REDIS_FAILURES[label]

    out, spy, _ = guard(w, d, p, controls=(lock_control(acquire),))
    assert out.reason_codes == ("MANDATORY_CONTROL_UNAVAILABLE",) and spy.calls == []


@pytest.mark.parametrize("controls", [object(), "lock", [object()], [lambda: True], {"lock": 1}])
def test_malformed_control_configuration_blocks_execution(w, controls):
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, controls=controls)
    assert not out.executed and out.reason_codes == ("MANDATORY_CONTROL_UNAVAILABLE",) and spy.calls == []


def test_all_mandatory_controls_must_pass_and_run_before_persistence(w):
    p, d = allow_decision(w)
    order = []

    async def ok():
        order.append("lock")
        return True

    async def rl_check():
        order.append("rate")
        return True

    async def persist(_):
        order.append("persist")

    async def executor(grant):
        order.append("execute")
        return {"tx": 1}

    out = run(w.guard.execute(d, p, DEV, persist_decision=persist, executor=executor,
                              mandatory_controls=(MandatoryControl("lock", ok), MandatoryControl("rate", rl_check))))
    assert out.executed and order == ["lock", "rate", "persist", "execute"]


def test_policy_evaluation_has_no_redis_dependency(w):
    """A Redis outage must not block operations that do not depend on Redis: the policy
    engine, trust evaluator, quarantine and drift services never call Redis."""
    p = proposal([w.trusted_memory()])
    assert run(w.engine.evaluate(p, DEV)).outcome is PolicyOutcome.ALLOW
    assert not hasattr(w.engine, "_redis") and not hasattr(w.guard, "_redis")


# =============================================================================
# Group 3 — Memory trust failures
# =============================================================================

def _assessment(rid, **kw):
    base = dict(record_id=rid, found=True, eligible=True, reason_codes=(), stored_state="TRUSTED",
                effective_state="TRUSTED", version=1, checksum="a" * 64, agent_id=None, trust_decision_id="td-1")
    base.update(kw)
    return ActionMemoryAssessment(**base)


TRUST_FAULTS = {
    "evaluator connection error": lambda rid: (_ for _ in ()).throw(ConnectionError()),
    "evaluator timeout": lambda rid: (_ for _ in ()).throw(TimeoutError()),
    "evaluator asyncio timeout": lambda rid: (_ for _ in ()).throw(asyncio.TimeoutError()),
    "evaluator crash": lambda rid: (_ for _ in ()).throw(RuntimeError("bug")),
    "returns None": lambda rid: None,
    "returns dict": lambda rid: {"eligible": True},
    "wrong record id": lambda rid: _assessment("other-record"),
    "found=False but eligible=True": lambda rid: _assessment(rid, found=False),
    "state not TRUSTED but eligible=True": lambda rid: _assessment(rid, effective_state="SUSPICIOUS"),
    "missing state": lambda rid: _assessment(rid, effective_state=None),
    "unknown state": lambda rid: _assessment(rid, effective_state="TRUSTED_ISH"),
    "missing checksum": lambda rid: _assessment(rid, checksum=None),
    "malformed checksum": lambda rid: _assessment(rid, checksum="not-a-sha256"),
    "missing version": lambda rid: _assessment(rid, version=None),
    "version as string": lambda rid: _assessment(rid, version="1"),
    "missing trust evidence id": lambda rid: _assessment(rid, trust_decision_id=None),
    "blank trust evidence id": lambda rid: _assessment(rid, trust_decision_id="  "),
    "reason codes not a tuple": lambda rid: _assessment(rid, reason_codes=[]),
    "eligible truthy non-bool": lambda rid: _assessment(rid, eligible=1),
}


@pytest.mark.parametrize("label", list(TRUST_FAULTS))
def test_trust_failure_or_malformed_evidence_blocks(w, monkeypatch, label):
    rid = w.trusted_memory()
    fault = TRUST_FAULTS[label]
    monkeypatch.setattr(w.trust, "assess_for_action", lambda tenant, record_id, version=None: fault(record_id))
    p = proposal([rid])
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "REFERENCED_UNTRUSTED_MEMORY" in d.reason_codes, d.reason_codes
    assert not decision_is_executable(d)
    out, spy, _ = guard(w, d, p)
    assert spy.calls == [] and not out.executed


def test_well_formed_trusted_assessment_is_the_only_passing_shape(w, monkeypatch):
    rid = w.trusted_memory()
    real = w.trust.assess_for_action(T_A, rid)
    assert real.eligible and real.found and real.trust_decision_id
    monkeypatch.setattr(w.trust, "assess_for_action", lambda *a, **k: real)
    assert run(w.engine.evaluate(proposal([rid]), DEV)).outcome is PolicyOutcome.ALLOW


@pytest.mark.parametrize("fault", ["store_list", "get_versions", "get_edges"])
def test_trust_backing_store_outages_block(w, monkeypatch, fault):
    rid = w.trusted_memory()
    target = {"store_list": (w.store, "list_for_record"), "get_versions": (w.repo, "get_versions"),
              "get_edges": (w.repo, "get_edges_for_record")}[fault]
    monkeypatch.setattr(*target, lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    d = run(w.engine.evaluate(proposal([rid]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "MEMORY_TRUST_UNAVAILABLE" in d.reason_codes


@pytest.mark.parametrize("state", ["UNVERIFIED", "SUSPICIOUS", "QUARANTINED", "REJECTED", "SUPERSEDED"])
def test_every_non_trusted_state_blocks_and_never_executes(w, state):
    p = proposal([w.memory_in_state(state)])
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK and f"MEMORY_{state}" in d.reason_codes
    out, spy, _ = guard(w, d, p)
    assert spy.calls == []


@pytest.mark.parametrize("setup", ["missing", "cross_tenant", "trusted_outside_m4", "tampered", "updated_after_validation"])
def test_unverifiable_memory_blocks(w, setup):
    if setup == "missing":
        rid = "mem-does-not-exist"
    elif setup == "cross_tenant":
        rid = w.memory(tenant=T_B)
        w.repo._records[rid].trust_state = "TRUSTED"
    elif setup == "trusted_outside_m4":
        rid = w.memory()
        transition_memory_trust_state(T_A, rid, "TRUSTED", repository=w.repo)
    elif setup == "tampered":
        rid = w.trusted_memory()
        w.repo._versions[rid][0].content = "tampered"
    else:
        rid = w.trusted_memory()
        update_memory(T_A, rid, "changed", repository=w.repo)
    p = proposal([rid])
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK
    out, spy, _ = guard(w, d, p)
    assert spy.calls == []


def test_agent_supplied_trust_claims_are_ignored(w):
    rid = w.memory()   # UNVERIFIED
    p = proposal([rid])
    p["memory_trust"] = "TRUSTED"
    p["parameters"]["trust_state"] = "TRUSTED"
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "MEMORY_UNVERIFIED" in d.reason_codes


# =============================================================================
# Group 4 — Policy engine failures
# =============================================================================

@pytest.mark.parametrize("method", ["_check_agent", "_check_tool_and_operation", "_check_parameters",
                                    "_check_memory", "_conclude", "_evaluate_inner"])
def test_policy_stage_exception_blocks(w, monkeypatch, method):
    p = proposal([w.trusted_memory()])

    def boom(*a, **k):
        raise RuntimeError(f"engine fault reading {SECRET_DSN}")

    monkeypatch.setattr(PolicyEngine, method, boom)
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.BLOCK and d.evaluation_status in ("ERROR", "COMPLETE")
    assert not decision_is_executable(d) and "S3CR3T" not in repr(d)
    out, spy, _ = guard(w, d, p)
    assert spy.calls == []


@pytest.mark.parametrize("method", ["_check_agent", "_check_memory", "_check_parameters"])
def test_skipped_mandatory_check_blocks(w, monkeypatch, method):
    async def skip_async(*a, **k):
        return None

    def skip(*a, **k):
        return None

    monkeypatch.setattr(PolicyEngine, method, skip_async if method in ("_check_agent",) else skip)
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "RULESET_INCOMPLETE" in d.reason_codes


def test_policy_timeout_blocks_deterministically(w, monkeypatch):
    async def timeout(coro, timeout):
        coro.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(policy_mod.asyncio, "wait_for", timeout)
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and d.reason_codes == ("POLICY_EVALUATION_TIMEOUT",)
    assert d.evaluation_status == "TIMEOUT"


def test_policy_budget_overrun_detected_post_hoc(w, monkeypatch):
    ticks = iter([0.0] + [10.0] * 100)                 # first call = start, later calls = 10 s elapsed
    monkeypatch.setattr(policy_mod.time, "perf_counter", lambda: next(ticks))
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and d.reason_codes == ("POLICY_EVALUATION_TIMEOUT",)


@pytest.mark.parametrize("grant_result", [None, {"tool_name": "sandbox_transfer"}, "granted",
                                          ToolGrant("other_tool", "transfer_funds", {"max_amount": 500})])
def test_missing_or_invalid_tool_permission_blocks(w, monkeypatch, grant_result):
    monkeypatch.setattr(w.grants, "get_tool_grant", lambda *a, **k: grant_result)
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK


def test_permission_store_outage_blocks(w, monkeypatch):
    monkeypatch.setattr(w.grants, "get_tool_grant", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "TOOL_GRANT_UNAVAILABLE" in d.reason_codes


def test_agent_directory_outage_blocks(w, monkeypatch):
    monkeypatch.setattr(w.repo, "get_agent", lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "AGENT_DIRECTORY_UNAVAILABLE" in d.reason_codes


@pytest.mark.parametrize("constraints", [{}, {"allowed_destination_account": ["ACC-VENDOR-VALID"]},
                                         {"max_amount": "500"}, {"maxAmount": 500}, None])
def test_missing_or_invalid_parameter_ceiling_blocks(w, constraints):
    w.grants.grants[(T_A, AGENT, "sandbox_transfer")] = ToolGrant("sandbox_transfer", "transfer_funds",
                                                                  constraints if constraints is not None else "x")
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK


def test_missing_approval_evidence_never_executes(w):
    p = proposal([w.trusted_memory()], amount=450)
    d = run(w.engine.evaluate(p, DEV))
    assert d.outcome is PolicyOutcome.REQUIRES_APPROVAL
    out, spy, persisted = guard(w, d, p)
    assert out.status == "PENDING_APPROVAL" and spy.calls == [] and persisted == []


@pytest.mark.parametrize("approval", [{"status": "APPROVED"}, "APPROVED", object()])
def test_malformed_approval_evidence_blocks(w, approval):
    d = run(w.engine.evaluate(proposal([w.trusted_memory()], amount=450), DEV, approval=approval))
    assert d.outcome is PolicyOutcome.BLOCK and "APPROVAL_INVALID" in d.reason_codes


@pytest.mark.parametrize("cfg", [PolicyConfig(timeout_seconds=-1), PolicyConfig(proposer_roles=()),
                                 PolicyConfig(proposer_roles=("ROOT",))])
def test_invalid_policy_configuration_refuses_to_start(w, cfg):
    with pytest.raises(policy_mod.PolicyConfigurationError):
        PolicyEngine(w.trust, w.repo, w.grants, cfg)


@pytest.mark.parametrize("bogus", [None, "ALLOW", {"outcome": "ALLOW"}, PolicyOutcome.ALLOW, object(), 1])
def test_unknown_decision_objects_never_execute(w, bogus):
    p, _ = allow_decision(w)
    out, spy, persisted = guard(w, bogus, p)
    assert not out.executed and spy.calls == [] and persisted == []


@pytest.mark.parametrize("change", [
    dict(policy_result=PolicyResult.DENIED),                         # conflicting result fields
    dict(policy_result=PolicyResult.ELEVATED),
    dict(reason_codes=()),                                           # missing reason codes
    dict(reason_codes=("ALL_CHECKS_PASSED", "CEILING_EXCEEDED")),
    dict(evaluation_status="TIMEOUT"),
    dict(execution_eligible=False),
    dict(policy_version="amsc-policy/0.0.1"),
    "drop_check", "block_check", "ineligible_memory", "forged_id",
])
def test_tampered_or_inconsistent_allow_never_executes(w, change):
    p, d = allow_decision(w)
    if change == "drop_check":
        bad = replace(d, checks=d.checks[:-1])
    elif change == "block_check":
        bad = replace(d, checks=d.checks[:-1] + (replace(d.checks[-1], outcome="BLOCK"),))
    elif change == "ineligible_memory":
        bad = replace(d, memory_evidence=tuple(replace(m, eligible=False) for m in d.memory_evidence))
    elif change == "forged_id":
        bad = replace(d, decision_id="forged")
    else:
        bad = replace(d, **change)
    out, spy, persisted = guard(w, bad, p)
    assert not out.executed and spy.calls == [] and persisted == []


@pytest.mark.parametrize("field,value", [("tool_name", "cloud_infra"), ("operation", "delete_all"),
                                         ("agent_id", "agent-head-office-001"), ("principal_id", "admin-1"),
                                         ("approval_id", "apr-forged"), ("trace_id", "tr-other")])
def test_allow_with_retargeted_fields_never_executes(w, field, value):
    """A copy of a genuine ALLOW with a re-targeted field (e.g. the grant's tool_name) must not
    execute even though the proposal fingerprint and memory snapshot are unchanged."""
    p, d = allow_decision(w)
    out, spy, persisted = guard(w, replace(d, **{field: value}), p)
    assert not out.executed and spy.calls == [] and persisted == []
    assert out.reason_codes == ("DECISION_NOT_ISSUED_BY_ENGINE",)


@pytest.mark.parametrize("change", [
    dict(policy_result=PolicyResult.DENIED), dict(policy_result=PolicyResult.ELEVATED),
    "drop_check", "block_check", "indeterminate_check", "duplicate_check", "ineligible_memory",
])
def test_decision_is_executable_rejects_internally_inconsistent_allow(w, change):
    _, d = allow_decision(w)
    assert decision_is_executable(d)
    if change == "drop_check":
        bad = replace(d, checks=d.checks[:-1])
    elif change == "block_check":
        bad = replace(d, checks=d.checks[:-1] + (replace(d.checks[-1], outcome="BLOCK"),))
    elif change == "indeterminate_check":
        bad = replace(d, checks=(replace(d.checks[0], outcome="INDETERMINATE"),) + d.checks[1:])
    elif change == "duplicate_check":
        bad = replace(d, checks=d.checks[:-1] + (d.checks[0],))
    elif change == "ineligible_memory":
        bad = replace(d, memory_evidence=tuple(replace(m, eligible=False) for m in d.memory_evidence))
    else:
        bad = replace(d, **change)
    assert decision_is_executable(bad) is False


@pytest.mark.parametrize("raw", [1, "OK", "true", b"1", object(), [True], {"ok": True}, None, False])
def test_guard_requires_exact_true_from_raw_mandatory_control(w, raw):
    p, d = allow_decision(w)

    async def check():
        return raw

    out, spy, persisted = guard(w, d, p, controls=(MandatoryControl("raw", check),))
    assert out.reason_codes == ("MANDATORY_CONTROL_DENIED",) and spy.calls == [] and persisted == []


def test_decision_from_untrusted_engine_instance_never_executes(w):
    other = World()
    p = proposal([other.trusted_memory()])
    d = run(other.engine.evaluate(p, DEV))
    out, spy, _ = guard(w, d, p)
    assert out.reason_codes == ("DECISION_NOT_ISSUED_BY_ENGINE",) and spy.calls == []


def test_revalidation_failure_after_persistence_never_executes(w, monkeypatch):
    p, d = allow_decision(w)
    persisted = []

    async def persist(dec):
        persisted.append(dec)
        # Dependency fails between persistence and execution (e.g. trust store partitioned).
        monkeypatch.setattr(w.trust, "assess_for_action", lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))

    out, spy, _ = guard(w, d, p, persist=persist)
    assert persisted and spy.calls == []
    assert out.reason_codes[0] == "PRE_EXECUTION_REVALIDATION_FAILED" and "MEMORY_TRUST_UNAVAILABLE" in out.reason_codes


# =============================================================================
# Group 5 — Authentication and tenant failures
# =============================================================================

@pytest.mark.parametrize("ctx", [None, "tenant-a", make_ctx(active=False), make_ctx(tenant=""), make_ctx(user="")])
def test_missing_or_invalid_context_blocks(w, ctx):
    p = proposal([w.trusted_memory()])
    d = run(w.engine.evaluate(p, ctx))
    assert d.outcome is PolicyOutcome.BLOCK and d.reason_codes == ("TENANT_CONTEXT_INVALID",)
    out, spy, _ = guard(w, d, p, ctx=ctx)
    assert spy.calls == []


@pytest.mark.parametrize("role", ["DEVELOPER", "AUDITOR", "SECURITY_ANALYST", "TENANT_ADMIN", "", "developer"])
def test_unauthorized_or_unknown_role_blocks(w, role):
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), make_ctx(role=role, user="u")))
    assert d.outcome is PolicyOutcome.BLOCK and "PRINCIPAL_ROLE_NOT_AUTHORIZED" in d.reason_codes


def test_tenant_mismatch_between_decision_and_execution_never_executes(w):
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, ctx=make_ctx(tenant=T_B))   # executed under another tenant's context
    assert not out.executed and spy.calls == []
    assert "PRE_EXECUTION_REVALIDATION_FAILED" in out.reason_codes


def test_cross_tenant_agent_and_memory_block(w):
    rid_b = w.memory(tenant=T_B)
    d = run(w.engine.evaluate(proposal([rid_b], agent="agent-b-001"), DEV))
    assert d.outcome is PolicyOutcome.BLOCK
    assert {"AGENT_NOT_REGISTERED", "MEMORY_REFERENCE_NOT_FOUND"} <= set(d.reason_codes)


# -- HTTP: M1 authentication -> M4 engine -> guard (mandatory controls + M6 persistence) -> spy

JWT = "m4-day7-fail-closed-test-secret-with-plenty-of-entropy!"
SETTINGS = Settings(APP_ENV="test", JWT_SECRET=JWT)


class _AuthRepo(InMemoryAuthRepository):
    outage = False

    async def get_membership(self, user_id, tenant_id):
        if self.outage:
            raise ConnectionRefusedError(SECRET_DSN)
        return await super().get_membership(user_id, tenant_id)


def _http_app(w, *, limiter=None, factory=None):
    """TEST-ONLY reference wiring of the contract (not the production gateway, which is M1/M2's)."""
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = SETTINGS
    repo = _AuthRepo()
    repo.add_tenant(TenantRecord(id=T_A, name="A", slug="a"))
    repo.add_tenant(TenantRecord(id=T_B, name="B", slug="b"))
    for uid, tid, role, status in [("dev-1", T_A, "AI_DEVELOPER", "ACTIVE"), ("dev-rev", T_A, "AI_DEVELOPER", "REVOKED"),
                                   ("dev-b", T_B, "AI_DEVELOPER", "ACTIVE")]:
        repo.add_user(UserRecord(id=uid, email=f"{uid}@x.t", hashed_password="x", full_name=uid))
        repo.add_membership(MembershipRecord(id=f"m-{uid}", tenant_id=tid, user_id=uid, role=role, status=status))
    app.state.auth_repo = repo
    app.state.spy = SpyAdapter()
    app.state.limiter = limiter or InMemoryRateLimiter()
    app.state.factory = factory or FaultySessionFactory()

    @app.post("/test-gateway/propose")
    async def propose(request: Request, body: dict = Body(...), ctx=Depends(get_tenant_context)):
        decision = await w.engine.evaluate(body, ctx)
        controls = (rate_limit_control(request.app.state.limiter, f"gw:{ctx.tenant_id}:{body.get('agent_id')}", 100, 60),)
        out = await w.guard.execute(decision, body, ctx, persist_decision=m6_persist(request.app.state.factory),
                                    executor=request.app.state.spy, mandatory_controls=controls)
        return {"decision": decision.outcome.value, "execution_status": out.status,
                "reason_codes": list(out.reason_codes)}

    return app


def _post(app, body, user="dev-1", tenant=T_A, headers=None, auth=True):
    async def go():
        h = dict(headers or {})
        if auth:
            h["Authorization"] = "Bearer " + create_access_token(user_id=user, tenant_id=tenant, role="TENANT_ADMIN",
                                                                 settings=SETTINGS)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            return await c.post("/test-gateway/propose", json=body, headers=h)
    return asyncio.run(go())


def test_http_benign_request_executes_once(w):
    app = _http_app(w)
    res = _post(app, proposal([w.trusted_memory()]))
    assert res.status_code == 200 and res.json()["execution_status"] == "EXECUTED" and len(app.state.spy.calls) == 1


@pytest.mark.parametrize("case,expected_status", [
    ("missing token", 401), ("forged token", 401), ("tenant header mismatch", 403),
    ("revoked membership", 403), ("auth repository outage", 503),
])
def test_http_auth_and_tenant_failures_never_reach_adapter(w, case, expected_status):
    app = _http_app(w)
    body = proposal([w.trusted_memory()])
    if case == "missing token":
        res = _post(app, body, auth=False)
    elif case == "forged token":
        res = _post(app, body, auth=False, headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."})
    elif case == "tenant header mismatch":
        res = _post(app, body, headers={"X-Tenant-ID": T_B})
    elif case == "revoked membership":
        res = _post(app, body, user="dev-rev")
    else:
        app.state.auth_repo.outage = True
        res = _post(app, body)
    assert res.status_code == expected_status and app.state.spy.calls == []
    assert "S3CR3T" not in res.text and "Traceback" not in res.text


def test_http_client_tenant_field_is_not_authoritative(w):
    app = _http_app(w)
    body = proposal([w.memory(tenant=T_B)])
    body["tenant_id"] = T_B
    res = _post(app, body)
    assert res.json()["decision"] == "BLOCK" and app.state.spy.calls == []


@pytest.mark.parametrize("failure", ["redis_unavailable", "db_commit", "db_connect"])
def test_http_infrastructure_outage_never_reaches_adapter(w, failure):
    limiter, factory = InMemoryRateLimiter(), FaultySessionFactory()
    if failure == "redis_unavailable":
        limiter.is_available = False
    elif failure == "db_commit":
        factory.faults["commit"] = OperationalError("COMMIT", {}, Exception(SECRET_DSN))
    else:
        factory.faults["connect"] = ConnectionRefusedError(SECRET_DSN)
    app = _http_app(w, limiter=limiter, factory=factory)
    res = _post(app, proposal([w.trusted_memory()]))
    body = res.json()
    assert res.status_code == 200 and body["decision"] == "ALLOW" and body["execution_status"] == "NOT_EXECUTED"
    assert app.state.spy.calls == [] and factory.committed == [] and "S3CR3T" not in res.text


# =============================================================================
# Group 6 — Execution safety (matrix: every failure scenario, one invariant)
# =============================================================================

def _scenario(w, monkeypatch, name):
    """Return (proposal, decision, extra guard kwargs) for a failure scenario."""
    p = proposal([w.trusted_memory()])
    extra = {}
    if name == "trust_down":
        monkeypatch.setattr(w.trust, "assess_for_action", lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))
    elif name == "grants_down":
        monkeypatch.setattr(w.grants, "get_tool_grant", lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))
    elif name == "agents_down":
        monkeypatch.setattr(w.repo, "get_agent", lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))
    elif name == "engine_crash":
        monkeypatch.setattr(PolicyEngine, "_conclude", lambda *a, **k: 1 / 0)
    elif name == "isolated_agent":
        p = proposal([w.trusted_memory()], agent=AGENT_ISOLATED)
    elif name == "ceiling":
        p = proposal([w.trusted_memory()], amount=10_000)
    elif name == "approval_required":
        p = proposal([w.trusted_memory()], amount=450)
    elif name == "quarantined_memory":
        p = proposal([w.memory_in_state("QUARANTINED")])
    elif name == "db_persist_down":
        extra["persist"] = m6_persist(FaultySessionFactory({"connect": ConnectionRefusedError()}))
    elif name == "redis_lock_down":
        async def acquire():
            raise ConnectionRefusedError()
        extra["controls"] = (lock_control(acquire),)
    elif name == "invalid_context":
        return p, run(w.engine.evaluate(p, None)), {"ctx": None}
    return p, run(w.engine.evaluate(p, DEV)), extra


SCENARIOS = ["trust_down", "grants_down", "agents_down", "engine_crash", "isolated_agent", "ceiling",
             "approval_required", "quarantined_memory", "db_persist_down", "redis_lock_down", "invalid_context"]


@pytest.mark.parametrize("name", SCENARIOS)
def test_no_failure_scenario_reaches_the_adapter(w, monkeypatch, name):
    p, d, extra = _scenario(w, monkeypatch, name)
    out, spy, _ = guard(w, d, p, **extra)
    assert spy.calls == [] and out.executed is False and out.status in ("NOT_EXECUTED", "PENDING_APPROVAL")


def test_only_valid_allow_reaches_execution_with_bound_grant(w):
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p)
    assert out.executed and len(spy.calls) == 1
    grant = spy.calls[0]
    assert (grant.decision_id, grant.tenant_id, grant.tool_name, grant.proposal_fingerprint) == \
           (d.decision_id, T_A, "sandbox_transfer", d.proposal_fingerprint)


def test_adapter_timeout_is_reported_as_unknown_not_success(w):
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, spy=SpyAdapter(fail_with=asyncio.TimeoutError()))
    assert out.executed is True and out.status == "UNKNOWN" and out.result is None


def test_adapter_failure_after_dispatch_is_failed_not_a_safe_block(w):
    p, d = allow_decision(w)
    out, spy, _ = guard(w, d, p, spy=SpyAdapter(fail_with=ConnectionResetError(SECRET_REDIS)))
    assert out.executed is True and out.status == "FAILED" and out.error_type == "ConnectionResetError"
    assert "S3CR3T" not in repr(out)


def test_retrieval_and_quarantine_invariants_hold_under_failure(w, monkeypatch):
    """Trust failures never create retrievable or action-eligible memory."""
    rid = w.memory()
    monkeypatch.setattr(w.store, "list_for_record", lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))
    assert rid not in [r.id for r in retrieve_memory(T_A, repository=w.repo)]
    d = run(w.engine.evaluate(proposal([rid]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK
