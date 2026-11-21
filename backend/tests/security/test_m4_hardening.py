"""Adversarial regression tests for M4 hardening findings (2026-11-19 security pass).

Module: backend.tests.security.test_m4_hardening
Owner: M4 — Security Engine & Incident Response Lead

Each section names the finding it pins (see docs/security-design/m4-security-assessment.md).
These are unit/contract tests against the real M4 engine and guard; the protected adapter is
a spy (M2's adapters do not exist yet), and nothing security-critical is mocked away.
"""

import asyncio
import dataclasses
from datetime import timedelta

import pytest

from backend.app.security import policy as policy_mod
from backend.app.security.policy import ApprovalEvidence, PolicyOutcome
from backend.tests.security.conftest import DEV, T_A, T_B, SpyAdapter, World, proposal


def run(coro):
    return asyncio.run(coro)


async def _persist_ok(_):
    return None


def _approval(world, p, **overrides):
    fp = run(world.engine.evaluate(p, DEV)).proposal_fingerprint
    base = dict(approval_id="apr-replay", tenant_id=T_A, status="APPROVED", proposal_fingerprint=fp,
                approver_user_id="analyst-9", approver_role="SECURITY_ANALYST",
                expires_at=policy_mod.datetime.now(policy_mod.timezone.utc) + timedelta(minutes=15))
    base.update(overrides)
    return ApprovalEvidence(**base)


def _evaluate_and_execute(world, p, spy, approval=None):
    d = run(world.engine.evaluate(p, DEV, approval=approval))
    return d, run(world.guard.execute(d, p, DEV, persist_decision=_persist_ok, executor=spy, approval=approval))


# =============================================================================
# M4-F1 — replay of a proposal or an approval through the guard
# =============================================================================

def test_same_proposal_cannot_execute_twice():
    w, spy = World(), SpyAdapter()
    p = proposal([w.trusted_memory()])
    d1, first = _evaluate_and_execute(w, p, spy)
    d2, second = _evaluate_and_execute(w, p, spy)
    assert d1.outcome is d2.outcome is PolicyOutcome.ALLOW       # each evaluation alone is ALLOW
    assert first.executed is True and second.executed is False
    assert second.reason_codes == ("EXECUTION_ALREADY_PERFORMED",)
    assert len(spy.calls) == 1


def test_same_approval_cannot_authorise_two_executions():
    w, spy = World(), SpyAdapter()
    p = proposal([w.trusted_memory()], amount=450)
    apr = _approval(w, p)
    _, first = _evaluate_and_execute(w, p, spy, apr)
    assert first.executed is True
    # A second proposal (new idempotency key) presenting the same approval: refused at evaluation.
    p2 = dict(p, idempotency_key="idem-other", action_id="act-other")
    d2 = run(w.engine.evaluate(p2, DEV, approval=dataclasses.replace(apr, proposal_fingerprint=run(
        w.engine.evaluate(p2, DEV)).proposal_fingerprint)))
    assert d2.outcome is PolicyOutcome.BLOCK and "APPROVAL_ALREADY_CONSUMED" in d2.reason_codes
    assert len(spy.calls) == 1


def test_approval_replayed_with_same_proposal_is_refused():
    w, spy = World(), SpyAdapter()
    p = proposal([w.trusted_memory()], amount=450)
    apr = _approval(w, p)
    _evaluate_and_execute(w, p, spy, apr)
    d, out = _evaluate_and_execute(w, p, spy, apr)
    assert d.outcome is PolicyOutcome.BLOCK and "APPROVAL_ALREADY_CONSUMED" in d.reason_codes
    assert out.executed is False and len(spy.calls) == 1


def test_concurrent_duplicates_dispatch_once():
    w, spy = World(), SpyAdapter()
    p = proposal([w.trusted_memory()])

    async def both():
        d1 = await w.engine.evaluate(p, DEV)
        d2 = await w.engine.evaluate(p, DEV)
        return await asyncio.gather(
            w.guard.execute(d1, p, DEV, persist_decision=_persist_ok, executor=spy),
            w.guard.execute(d2, p, DEV, persist_decision=_persist_ok, executor=spy),
        )

    results = run(both())
    assert sorted(r.executed for r in results) == [False, True]
    assert len(spy.calls) == 1


def test_failed_or_timed_out_execution_is_not_silently_retried():
    """A side effect may have happened: the key stays reserved; the caller replays the stored outcome."""
    for error in (TimeoutError(), RuntimeError("adapter crashed")):
        w = World()
        p = proposal([w.trusted_memory()])
        _, first = _evaluate_and_execute(w, p, SpyAdapter(fail_with=error))
        assert first.status in ("UNKNOWN", "FAILED")
        spy = SpyAdapter()
        _, retry = _evaluate_and_execute(w, p, spy)
        assert retry.executed is False and retry.reason_codes == ("EXECUTION_ALREADY_PERFORMED",)
        assert spy.calls == []


def test_blocked_before_dispatch_does_not_reserve_the_key():
    """Revalidation, persistence or control failures happen before any side effect: a retry is
    evaluated again and may execute once conditions hold."""
    w, spy = World(), SpyAdapter()
    p = proposal([w.trusted_memory()])
    d = run(w.engine.evaluate(p, DEV))

    async def persist_fail(_):
        raise RuntimeError("db down")

    out = run(w.guard.execute(d, p, DEV, persist_decision=persist_fail, executor=spy))
    assert out.executed is False and spy.calls == []
    _, retry = _evaluate_and_execute(w, p, spy)
    assert retry.executed is True and len(spy.calls) == 1


def test_ledger_is_tenant_scoped_and_fails_closed_on_missing_key():
    w = World()
    d = run(w.engine.evaluate(proposal([w.trusted_memory()]), DEV))
    other_tenant = dataclasses.replace(d, tenant_id=T_B)
    assert w.engine._reserve_execution(d) is None
    assert w.engine._reserve_execution(d).value == "EXECUTION_ALREADY_PERFORMED"
    assert w.engine._reserve_execution(other_tenant) is None          # same key, other tenant: independent
    for broken in (dataclasses.replace(d, idempotency_key=None), dataclasses.replace(d, tenant_id="")):
        assert w.engine._reserve_execution(broken).value == "DECISION_NOT_EXECUTABLE"


# =============================================================================
# M4-F4 — audit actor identity (OD-9: user:/agent:/system:)
# =============================================================================

from backend.app.core.exceptions import ForbiddenError  # noqa: E402
from backend.app.security.audit_identity import SYSTEM_COMPONENTS, agent_actor, system_actor, user_actor  # noqa: E402
from backend.app.security.drift import DriftReviewService  # noqa: E402
from backend.app.security.quarantine import ForensicAccess  # noqa: E402
from backend.tests.security.conftest import make_ctx  # noqa: E402


def test_actor_ids_use_the_od9_prefixes():
    assert user_actor("analyst-1") == "user:analyst-1"
    assert user_actor("3f1c9a2e-8d4b-4f6a-9c1d-2b7e5a0f9e11").startswith("user:")
    assert agent_actor("agent-001") == "agent:agent-001"
    assert {system_actor(c) for c in SYSTEM_COMPONENTS} == {f"system:{c}" for c in SYSTEM_COMPONENTS}


@pytest.mark.parametrize("bad", ["", " ", "a b", "x\nuser:admin", "x" * 121, None, 7, b"u", "user/../admin"])
def test_malformed_principal_ids_are_refused(bad):
    for build in (user_actor, agent_actor):
        with pytest.raises(ValueError):
            build(bad)


@pytest.mark.parametrize("bad", ["", "Gateway", "system", "attacker", "gateway ", None])
def test_only_fixed_system_components(bad):
    with pytest.raises(ValueError):
        system_actor(bad)


def test_drift_review_with_malformed_context_user_writes_nothing():
    from backend.tests.security.test_drift_api import TransactionalMemoryStore
    store = TransactionalMemoryStore()
    store.add(T_A, "obs-1", divergence_score="0.78")
    ctx = make_ctx(role="SECURITY_ANALYST", user="analyst 1")      # space: not a valid principal id
    with pytest.raises(ForbiddenError):
        run(DriftReviewService(store).review(ctx, "obs-1", "APPROVED"))
    assert store.calls == [] and store.audit == []
    assert store.rows[(T_A, "obs-1")].reviewer_status == "PENDING"


def test_forensic_read_with_malformed_context_user_is_refused_and_not_audited():
    w, audit = World(), []

    async def persist_audit(event):
        audit.append(event)

    rid = w.memory()
    ctx = make_ctx(role="SECURITY_ANALYST", user="analyst\n1")
    with pytest.raises(ForbiddenError):
        run(ForensicAccess(w.trust, w.repo).read(ctx, rid, "INC-1 investigation", persist_audit=persist_audit))
    assert audit == []


# =============================================================================
# M4-F5 — trust transition must not overwrite a concurrent change (lost update)
# =============================================================================

import threading  # noqa: E402

from backend.app.memory import update_memory  # noqa: E402
from backend.tests.security.test_trust_evaluator import ADMIN, ANALYST, ANALYST_2, OP, Harness  # noqa: E402


def _during_evaluation(h, action):
    """Run ``action`` once while the evaluator is between reading and writing the record."""
    original, fired = h.repo.get_edges_for_record, []

    def patched(record_id, tenant_id):
        if not fired:
            fired.append(True)
            action()
        return original(record_id, tenant_id)

    h.repo.get_edges_for_record = patched


def test_concurrent_quarantine_survives_a_racing_validate():
    h = Harness()
    rid = h.new()
    req = h.request(rid, OP.VALIDATE)
    _during_evaluation(h, lambda: h.must(rid, OP.QUARANTINE, actor=ANALYST_2))
    d = h.ev.apply(req, ANALYST)
    assert d.applied is False and d.reason_codes == ("STALE_STATE",)
    assert h.state(rid) == "QUARANTINED" and h.ev.effective_state(T_A, rid) == "QUARANTINED"


def test_concurrent_new_version_is_not_rolled_back_or_trusted():
    h = Harness()
    rid = h.new()
    req = h.request(rid, OP.VALIDATE)
    _during_evaluation(h, lambda: update_memory(T_A, rid, "v2 content", repository=h.repo))
    d = h.ev.apply(req, ANALYST)
    rec = h.rec(rid)
    assert d.applied is False and d.reason_codes == ("STALE_VERSION",)
    assert rec.current_version == 2 and rec.trust_state == "UNVERIFIED"


def test_failed_evidence_write_does_not_revert_over_a_concurrent_change():
    """If the ledger append fails, the revert must not overwrite a write made by someone else."""
    h = Harness()
    rid = h.new()
    req = h.request(rid, OP.VALIDATE)
    original_append = h.ev._store.append

    def failing_append(decision):
        if decision.applied:
            r = h.rec(rid)                       # a concurrent writer lands right after our write
            r.trust_state = "QUARANTINED"
            h.repo.update_record(r)
            raise RuntimeError("ledger down")
        return original_append(decision)

    h.ev._store.append = failing_append
    d = h.ev.apply(req, ANALYST)
    assert d.applied is False and "DECISION_STORE_UNAVAILABLE" in d.reason_codes
    assert h.state(rid) == "QUARANTINED"          # not reverted to UNVERIFIED over the other writer


def test_threads_racing_conflicting_transitions_apply_at_most_one():
    h = Harness()
    rid = h.new()
    barrier = threading.Barrier(2, timeout=10)
    original_apply = h.ev._apply
    overlapped = []

    def synchronised_apply(req, record, ctx):
        barrier.wait()                           # both threads finished evaluating the same record
        overlapped.append(True)
        return original_apply(req, record, ctx)

    reqs = {"validate": (h.request(rid, OP.VALIDATE), ANALYST),
            "quarantine": (h.request(rid, OP.QUARANTINE), ADMIN)}
    h.ev._apply = synchronised_apply
    original_update = h.repo.update_record

    def slow_update(record):                     # yield between re-read and write (a real DB round trip)
        import time
        time.sleep(0.05)
        return original_update(record)

    h.repo.update_record = slow_update
    results = {}
    threads = [threading.Thread(target=lambda k=k, r=r, a=a: results.__setitem__(k, h.ev.apply(r, a)))
               for k, (r, a) in reqs.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    applied = [k for k, d in results.items() if d.applied]
    assert len(overlapped) == 2                  # the race really happened
    assert len(results) == 2 and len(applied) == 1
    loser = next(d for k, d in results.items() if not d.applied)
    assert loser.reason_codes == ("STALE_STATE",)
    final = h.state(rid)
    assert final == {"validate": "TRUSTED", "quarantine": "QUARANTINED"}.get(applied[0] if applied else None, "UNVERIFIED")


def test_quarantine_retries_when_a_new_version_lands_mid_transition():
    """M4-F5 x quarantine: the stale refusal is retried against the fresh record, not lost."""
    from backend.app.security.quarantine import QuarantineStatus, QuarantineWorkflow
    h = Harness()
    rid = h.new()
    wf = QuarantineWorkflow(h.ev, h.repo)
    original_apply, fired = h.ev._apply, []

    def apply_after_concurrent_update(req, record, ctx):   # lands after evaluation, before the write
        if not fired:
            fired.append(True)
            update_memory(T_A, rid, "v2 content", repository=h.repo)
        return original_apply(req, record, ctx)

    h.ev._apply = apply_after_concurrent_update
    evidence = []

    async def persist(outcome):
        evidence.append(outcome)

    out = run(wf.quarantine(ANALYST.context, {"record_id": rid, "reason": "Verified prompt injection"},
                            persist_evidence=persist))
    assert fired == [True]
    assert out.status is QuarantineStatus.QUARANTINED and out.success and out.retries == 1
    assert h.state(rid) == "QUARANTINED" and h.rec(rid).current_version == 2 and len(evidence) == 1
