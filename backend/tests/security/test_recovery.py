"""Recovery orchestration: unit + contract tests (finding M4-F7: recovery API/orchestration missing).

Module: backend.tests.security.test_recovery
Owner: M4 — Security Engine & Incident Response Lead

The orchestrator is real; M3's memory repository and M4's trust evaluator are real (in-memory).
The M6/M3 ports are test doubles that model the documented contracts:

- ``ContractRewind`` models ``backend.app.database.rewind.RewindCoordinator``: the snapshot is
  committed once; the rollback runs in one all-or-nothing transaction (state restored on any
  exception); ``compare_and_set_current_version`` refuses a moved pointer; a plan executes once.
- ``MemoryPlanStore`` models recovery_plans with compare-and-set status (OD-21).

These are NOT PostgreSQL tests. Running the orchestrator against M6's real RewindCoordinator
needs M3's checkpoint reader and the PostgreSQL memory adapter (see m4-integration-contracts.md).
"""

import asyncio
import copy
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import pytest

from backend.app.core.exceptions import ForbiddenError, NotFoundError, SecurityDependencyError, ValidationError
from backend.app.memory import LineageResult, MemoryVersion, sha256_hex, update_memory
from backend.app.recovery import orchestrator as orch_mod
from backend.app.recovery.orchestrator import (
    CheckpointItemView,
    CheckpointView,
    ExternalActionView,
    RecoveryPlanRecord,
    RecoveryService,
    RecoveryStatus,
    checkpoint_integrity_hash,
)
from backend.app.security.policy import PolicyOutcome
from backend.app.security.trust import TrustOperation
from backend.tests.security.conftest import DEV, T_A, T_B, World, make_ctx, proposal

ANALYST = make_ctx(role="SECURITY_ANALYST", user="analyst-1")
ANALYST_B = make_ctx(role="SECURITY_ANALYST", tenant=T_B, user="analyst-b")
CP_TIME = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


# =============================================================================
# Contract doubles for the M3/M6 ports
# =============================================================================

class MemoryCheckpoints:
    def __init__(self):
        self.rows, self.fail = {}, False

    def add(self, cp: CheckpointView):
        self.rows[(cp.tenant_id, cp.id)] = cp

    async def get_checkpoint(self, tenant_id, checkpoint_id):
        if self.fail:
            raise ConnectionError("checkpoint source down")
        return self.rows.get((tenant_id, checkpoint_id))


class MemoryPlanStore:
    def __init__(self):
        self.rows, self.fail_create, self.fail_transition_to = {}, False, None

    async def create(self, plan):
        if self.fail_create:
            raise ConnectionError("db down")
        self.rows[(plan.tenant_id, plan.id)] = plan

    async def get(self, tenant_id, plan_id):
        await asyncio.sleep(0)                   # a real store round trip yields to the event loop
        return self.rows.get((tenant_id, plan_id))

    async def transition(self, tenant_id, plan_id, *, expected_status, new_status, snapshot_sha256=None):
        if new_status == self.fail_transition_to:
            return False
        plan = self.rows.get((tenant_id, plan_id))
        if plan is None or plan.status != expected_status:
            return False
        self.rows[(tenant_id, plan_id)] = replace(plan, status=new_status,
                                                  snapshot_sha256=snapshot_sha256 or plan.snapshot_sha256)
        return True


@dataclass
class Receipt:
    plan_id: str
    sha256: str


class _Rtx:
    def __init__(self, rewind, tenant_id, plan):
        self.r, self.tenant_id, self.plan = rewind, tenant_id, plan

    async def checkpoint_item_for(self, record_id):
        cp = self.r.checkpoints.rows.get((self.tenant_id, self.plan.checkpoint_id))
        return next((i for i in cp.items if i.record_id == record_id), None) if cp else None

    async def append_version(self, record_id, *, content, checksum):
        self.r._tick("append_version")
        repo = self.r.repo
        rec = repo.get_record(record_id, self.tenant_id)
        highest = max(v.version for v in repo.get_versions(record_id, self.tenant_id))
        v = MemoryVersion(id=f"v-{record_id}-{highest + 1}", tenant_id=self.tenant_id, record_id=record_id,
                          version=highest + 1, content=content, checksum=checksum,
                          created_at=datetime.now(timezone.utc))
        repo.create_version(v)
        assert rec is not None
        return v

    async def compare_and_set_current_version(self, record_id, *, expected, new):
        self.r._tick("cas")
        rec = self.r.repo.get_record(record_id, self.tenant_id)
        if rec.current_version != expected:
            raise RuntimeError("ConcurrencyConflict")
        self.r.repo.update_record(rec.model_copy(update={"current_version": new}))

    async def record_action(self, resource_id, action_taken, outcome=None):
        self.r._tick("record_action")
        self.pending.append((resource_id, action_taken, outcome))


class ContractRewind:
    """Models M6's RewindCoordinator semantics on the M3 in-memory repository."""

    def __init__(self, repo, plans, checkpoints, log):
        self.repo, self.plans, self.checkpoints, self.log = repo, plans, checkpoints, log
        self.snapshots, self.executed, self.actions = {}, set(), []
        self.fail_snapshot, self.fail_at, self._ops = False, None, 0
        self.capture_calls = self.rollback_calls = 0

    def _tick(self, name):
        self._ops += 1
        if self.fail_at is not None and self._ops >= self.fail_at:
            raise RuntimeError(f"injected failure at {name}")

    async def capture_snapshot(self, tenant_id, plan_id, snapshot):
        self.capture_calls += 1
        await asyncio.sleep(0)
        self.log.append("snapshot")
        if self.fail_snapshot:
            raise ConnectionError("db down")
        if (tenant_id, plan_id) in self.snapshots:
            raise RuntimeError("SnapshotAlreadyCaptured")
        if await self.plans.get(tenant_id, plan_id) is None:
            raise RuntimeError("PlanNotFound")
        sha = hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()
        self.snapshots[(tenant_id, plan_id)] = sha
        return Receipt(plan_id, sha)

    async def execute_rollback(self, tenant_id, plan_id, *, expected_snapshot_sha256, restore):
        self.rollback_calls += 1
        self.log.append("rollback")
        if self.snapshots.get((tenant_id, plan_id)) != expected_snapshot_sha256:
            raise RuntimeError("SnapshotMismatch")
        if (tenant_id, plan_id) in self.executed:
            raise RuntimeError("PlanAlreadyExecuted")
        plan = await self.plans.get(tenant_id, plan_id)
        saved = (copy.deepcopy(self.repo._records), copy.deepcopy(self.repo._versions))
        rtx = _Rtx(self, tenant_id, plan)
        rtx.pending = []
        self._ops = 0
        try:
            await restore(rtx)
        except BaseException:
            self.repo._records, self.repo._versions = saved          # ROLLBACK
            raise
        self.actions.extend(rtx.pending)                             # COMMIT
        self.executed.add((tenant_id, plan_id))


class External:
    def __init__(self, actions=()):
        self.actions, self.fail = list(actions), False

    async def executions_referencing(self, tenant_id, record_ids, since):
        if self.fail:
            raise ConnectionError("tool execution history down")
        return list(self.actions)


class Env:
    """A poisoned record with a derived child, a valid checkpoint and one prior external execution."""

    def __init__(self, target_state="QUARANTINED"):
        self.w = World()
        self.log, self.audit = [], []
        self.fail_audit_for = set()
        self.target = self.w.trusted_memory(content="Vendor ACC-VENDOR-VALID is the approved payee.")
        baseline = self.w.repo.get_version(self.target, 1, T_A)
        self.child = self.w.memory(content="Derived payment instruction", parent=self.target)
        update_memory(T_A, self.target, "Vendor ACC-ATTACKER-999 is the approved payee.", repository=self.w.repo)
        if target_state == "QUARANTINED":
            self.w.transition(self.target, TrustOperation.QUARANTINE)
        elif target_state == "TRUSTED":
            self.w.transition(self.target, TrustOperation.VALIDATE)
        items = (CheckpointItemView(self.target, 1, baseline.checksum, baseline.content),)
        self.checkpoint = CheckpointView("cp-001", T_A, checkpoint_integrity_hash(items), CP_TIME, items)
        self.checkpoints = MemoryCheckpoints()
        self.checkpoints.add(self.checkpoint)
        self.plans = MemoryPlanStore()
        self.rewind = ContractRewind(self.w.repo, self.plans, self.checkpoints, self.log)
        self.external = External([ExternalActionView("exec-1", "SUCCESS")])
        self.svc = RecoveryService(trust=self.w.trust, memory=self.w.repo, checkpoints=self.checkpoints,
                                   plans=self.plans, rewind=self.rewind, external_actions=self.external,
                                   persist_audit=self.persist_audit)
        original_apply = self.w.trust.apply

        def logged_apply(req, actor):
            self.log.append(f"trust:{req['operation']}:{req['record_id'][:6]}")
            return original_apply(req, actor)

        self.w.trust.apply = logged_apply

    async def persist_audit(self, event):
        if event["event_type"] in self.fail_audit_for:
            raise ConnectionError("audit down")
        self.audit.append(event)

    def request(self, **overrides):
        body = {"checkpoint_id": "cp-001", "target_record_id": self.target, "incident_id": "inc-001",
                "reason": "Restore vendor memo poisoned in INC-001"}
        body.update(overrides)
        return body

    def preview(self, ctx=ANALYST, **overrides):
        return run(self.svc.preview(ctx, self.request(**overrides)))

    def state(self, rid):
        return self.w.trust.effective_state(T_A, rid)

    def content(self, rid):
        rec = self.w.repo.get_record(rid, T_A)
        return self.w.repo.get_version(rid, rec.current_version, T_A).content


@pytest.fixture
def env():
    return Env()


# =============================================================================
# Successful recovery
# =============================================================================

def test_full_recovery_restores_content_and_never_trusts(env):
    pv = env.preview()
    assert [r.record_id for r in pv.records] == [env.target, env.child]
    assert {r.record_id: r.action for r in pv.records} == {env.target: "RESTORED_TO_CHECKPOINT",
                                                           env.child: "QUARANTINED_INTERMEDIARY"}
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.EXECUTED and out.success, out.reason_codes
    # Content is the checkpoint's, as a NEW version (OD-17), and the record is UNVERIFIED, never TRUSTED.
    rec = env.w.repo.get_record(env.target, T_A)
    assert rec.current_version == 3 and env.content(env.target) == env.checkpoint.items[0].content
    assert env.state(env.target) == "UNVERIFIED" and rec.trust_state == "UNVERIFIED"
    assert env.state(env.child) == "QUARANTINED"
    assert set(env.rewind.actions) == {(env.target, "RESTORED_TO_CHECKPOINT", "SUCCESS"),
                                      (env.child, "QUARANTINED_INTERMEDIARY", "SUCCESS"),
                                      ("exec-1", "EXTERNAL_ACTION_IRREVERSIBLE", "REQUIRES_COMPENSATION")}
    assert out.irreversible_external_actions == 1
    assert env.plans.rows[(T_A, pv.plan_id)].status == "EXECUTED"
    assert [e["event_type"] for e in env.audit] == ["RECOVERY_PREVIEWED", "RECOVERY_EXECUTED"]
    assert {e["actor_id"] for e in env.audit} == {"user:analyst-1"}


def test_snapshot_is_committed_before_any_state_change(env):
    pv = env.preview()
    run(env.svc.execute(ANALYST, pv.plan_id))
    first_change = next(i for i, e in enumerate(env.log) if e != "snapshot")
    assert env.log.index("snapshot") < first_change
    assert env.log.index("rollback") > env.log.index("snapshot")


def test_restored_memory_cannot_justify_a_protected_action(env):
    pv = env.preview()
    run(env.svc.execute(ANALYST, pv.plan_id))
    d = run(env.w.engine.evaluate(proposal([env.target]), DEV))
    assert d.outcome is PolicyOutcome.BLOCK and "MEMORY_UNVERIFIED" in d.reason_codes


def test_trusted_target_is_contained_then_restored_unverified():
    env = Env(target_state="TRUSTED")
    pv = env.preview()
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.success and env.state(env.target) == "UNVERIFIED"
    assert any(e.startswith("trust:QUARANTINE") for e in env.log)       # contained before content changed


# =============================================================================
# Authorization, tenant isolation and input validation
# =============================================================================

@pytest.mark.parametrize("role", ["AI_DEVELOPER", "AUDITOR", "DEVELOPER", "", "security_analyst"])
def test_only_security_operators_may_preview_or_execute(env, role):
    ctx = make_ctx(role=role, user="u-x")
    with pytest.raises(ForbiddenError):
        run(env.svc.preview(ctx, env.request()))
    pv = env.preview()
    with pytest.raises(ForbiddenError):
        run(env.svc.execute(ctx, pv.plan_id))
    assert env.rewind.capture_calls == 0 and env.state(env.target) == "QUARANTINED"


def test_inactive_or_missing_context_is_refused(env):
    for ctx in (None, make_ctx(role="SECURITY_ANALYST", active=False), make_ctx(role="SECURITY_ANALYST", user="a b")):
        with pytest.raises(ForbiddenError):
            run(env.svc.preview(ctx, env.request()))


def test_cross_tenant_target_checkpoint_and_plan_are_indistinguishable_from_missing(env):
    other = World().memory(tenant=T_B)
    env.checkpoints.add(replace(env.checkpoint, id="cp-b", tenant_id=T_B))
    msgs = set()
    for kwargs in (dict(target_record_id=other), dict(checkpoint_id="cp-b"), dict(checkpoint_id="cp-missing")):
        with pytest.raises(NotFoundError) as exc:
            env.preview(**kwargs)
        msgs.add(str(exc.value))
    assert len(msgs) == 1
    pv = env.preview()
    with pytest.raises(NotFoundError):
        run(env.svc.execute(ANALYST_B, pv.plan_id))
    assert env.rewind.capture_calls == 0


@pytest.mark.parametrize("bad", [
    dict(tenant_id=T_B), dict(checkpoint_id="../cp"), dict(target_record_id=""), dict(reason="short"),
    dict(incident_id="inc 1"), dict(checkpoint_id=7),
])
def test_malformed_preview_requests_are_rejected(env, bad):
    with pytest.raises(ValidationError):
        env.preview(**bad)
    assert env.plans.rows == {}


# =============================================================================
# Checkpoint integrity and scope
# =============================================================================

def _tampered(env, **changes):
    env.checkpoints.add(replace(env.checkpoint, **changes))


@pytest.mark.parametrize("mutate", [
    lambda e: _tampered(e, integrity_hash="0" * 64),
    lambda e: _tampered(e, items=(replace(e.checkpoint.items[0], content="attacker content"),)),
    lambda e: _tampered(e, items=e.checkpoint.items * 2,
                        integrity_hash=checkpoint_integrity_hash(e.checkpoint.items * 2)),
    lambda e: _tampered(e, items=()),
    lambda e: _tampered(e, items=(replace(e.checkpoint.items[0], version=0),)),
])
def test_tampered_or_malformed_checkpoint_is_refused(env, mutate):
    mutate(env)
    with pytest.raises(ValidationError):
        env.preview()
    assert env.plans.rows == {} and env.audit == []


def test_target_must_be_in_the_checkpoint(env):
    items = (CheckpointItemView("someone-else", 1, sha256_hex("x"), "x"),)
    _tampered(env, items=items, integrity_hash=checkpoint_integrity_hash(items))
    with pytest.raises(ValidationError):
        env.preview()


def test_rejected_target_cannot_be_recovered():
    env = Env(target_state="QUARANTINED")
    from backend.tests.security.conftest import ADMIN_ACTOR
    env.w.transition(env.target, TrustOperation.REJECT, actor=ADMIN_ACTOR)
    with pytest.raises(ValidationError):
        env.preview()


def test_incomplete_blast_radius_is_refused(env, monkeypatch):
    monkeypatch.setattr(orch_mod, "get_descendants",
                        lambda *a, **k: LineageResult([], complete=False, truncated_reason="max_nodes"))
    with pytest.raises(ValidationError):
        env.preview()


@pytest.mark.parametrize("failure", ["raises", "bad_type"])
def test_unknown_external_action_history_refuses_preview(env, failure):
    if failure == "raises":
        env.external.fail = True
    else:
        env.external.actions = [{"execution_id": "exec-1"}]
    with pytest.raises(SecurityDependencyError):
        env.preview()


def test_checkpoint_source_outage_refuses_preview(env):
    env.checkpoints.fail = True
    with pytest.raises(SecurityDependencyError):
        env.preview()


# =============================================================================
# Stale, repeated, concurrent and failing executions
# =============================================================================

def test_stale_plan_is_refused_without_any_change(env):
    pv = env.preview()
    update_memory(T_A, env.child, "child changed after preview", repository=env.w.repo)
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.FAILED and out.reason_codes[0] == "PLAN_STALE"
    assert env.rewind.capture_calls == 0 and env.rewind.rollback_calls == 0
    assert env.content(env.target).startswith("Vendor ACC-ATTACKER")
    assert env.plans.rows[(T_A, pv.plan_id)].status == "PREVIEWED"


def test_repeated_execution_runs_once(env):
    pv = env.preview()
    assert run(env.svc.execute(ANALYST, pv.plan_id)).success
    again = run(env.svc.execute(ANALYST, pv.plan_id))
    assert again.status is RecoveryStatus.FAILED and again.reason_codes == ("PLAN_ALREADY_EXECUTED",)
    assert env.rewind.rollback_calls == 1 and env.w.repo.get_record(env.target, T_A).current_version == 3


def test_concurrent_executions_of_one_plan_run_once(env):
    pv = env.preview()

    async def both():
        return await asyncio.gather(env.svc.execute(ANALYST, pv.plan_id), env.svc.execute(ANALYST, pv.plan_id))

    results = run(both())
    assert sorted(r.status.value for r in results) == ["EXECUTED", "FAILED"]
    loser = next(r for r in results if not r.success)
    assert loser.reason_codes == ("PLAN_NOT_EXECUTABLE",)     # refused by M4 before reaching M6
    assert env.rewind.capture_calls == 1 and env.rewind.rollback_calls == 1


@pytest.mark.parametrize("fail_at", [1, 2, 3, 5])
def test_rollback_failure_changes_no_content_and_is_retryable(env, fail_at):
    pv = env.preview()
    env.rewind.fail_at = fail_at
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.FAILED and out.reason_codes[0] == "ROLLBACK_FAILED"
    assert env.w.repo.get_record(env.target, T_A).current_version == 2           # transaction rolled back
    assert env.content(env.target).startswith("Vendor ACC-ATTACKER")
    assert env.state(env.target) == "QUARANTINED" and env.state(env.child) == "QUARANTINED"   # contained
    assert env.rewind.actions == []
    assert env.plans.rows[(T_A, pv.plan_id)].status == "FAILED"
    assert env.audit[-1]["event_type"] == "RECOVERY_FAILED"
    env.rewind.fail_at = None
    retry = run(env.svc.execute(ANALYST, pv.plan_id))
    assert retry.success and env.rewind.capture_calls == 1                       # same committed snapshot
    assert env.state(env.target) == "UNVERIFIED"


def test_snapshot_failure_changes_nothing(env):
    pv = env.preview()
    env.rewind.fail_snapshot = True
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.FAILED and out.reason_codes[0] == "SNAPSHOT_FAILED"
    assert env.state(env.child) == "UNVERIFIED" and env.rewind.rollback_calls == 0
    assert not any(e.startswith("trust:") for e in env.log)


def test_trust_restore_failure_leaves_records_restricted_and_reports_reconciliation(env):
    pv = env.preview()
    apply = env.w.trust.apply

    def deny_restore(req, actor):
        if req["operation"] == "RECOVERY_RESTORE":
            raise_free = apply({**req, "expected_version": 999}, actor)    # a refused transition
            return raise_free
        return apply(req, actor)

    env.w.trust.apply = deny_restore
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.RECONCILIATION_REQUIRED and "TRUST_RESTORE_FAILED" in out.reason_codes
    assert env.state(env.target) == "QUARANTINED"          # never relaxed, never TRUSTED


def test_record_found_trusted_after_recovery_is_never_reported_as_success(env):
    """Defence in depth: if any path (a bug, an M3 bypass) leaves a restored record TRUSTED,
    the post-condition check catches it and the outcome is not success."""
    pv = env.preview()
    apply = env.w.trust.apply

    def restore_then_bypass(req, actor):
        d = apply(req, actor)
        if req["operation"] == "RECOVERY_RESTORE":
            rec = env.w.repo.get_record(req["record_id"], T_A)
            env.w.repo.update_record(rec.model_copy(update={"trust_state": "TRUSTED"}))
        return d

    env.w.trust.apply = restore_then_bypass
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.RECONCILIATION_REQUIRED and "POSTCONDITION_FAILED" in out.reason_codes
    assert any("TRUSTED_AFTER_RECOVERY" in f for f in out.postconditions["failures"])


def test_final_audit_failure_is_not_reported_as_success(env):
    pv = env.preview()
    env.fail_audit_for = {"RECOVERY_EXECUTED"}
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.RECONCILIATION_REQUIRED and "AUDIT_FAILED" in out.reason_codes
    assert env.state(env.target) == "UNVERIFIED"


def test_plan_status_write_failure_is_not_reported_as_success(env):
    pv = env.preview()
    env.plans.fail_transition_to = "EXECUTED"
    out = run(env.svc.execute(ANALYST, pv.plan_id))
    assert out.status is RecoveryStatus.RECONCILIATION_REQUIRED and "PLAN_STATUS_NOT_RECORDED" in out.reason_codes
    # A second attempt cannot roll back twice: content changed, so the plan is stale.
    again = run(env.svc.execute(ANALYST, pv.plan_id))
    assert again.reason_codes[0] == "PLAN_STALE" and env.rewind.rollback_calls == 1


def test_preview_audit_failure_fails_the_plan(env):
    env.fail_audit_for = {"RECOVERY_PREVIEWED"}
    with pytest.raises(SecurityDependencyError):
        env.preview()
    (plan,) = env.plans.rows.values()
    assert plan.status == "FAILED"


def test_plan_store_outage_refuses_preview(env):
    env.plans.fail_create = True
    with pytest.raises(SecurityDependencyError):
        env.preview()
    assert env.audit == []


# =============================================================================
# Integrity helper
# =============================================================================

def test_checkpoint_hash_is_order_independent_and_field_sensitive():
    a = CheckpointItemView("r-a", 1, "a" * 64, "")
    b = CheckpointItemView("r-b", 2, "b" * 64, "")
    assert checkpoint_integrity_hash([a, b]) == checkpoint_integrity_hash([b, a])
    assert checkpoint_integrity_hash([a, b]) != checkpoint_integrity_hash([replace(a, version=2), b])
    assert checkpoint_integrity_hash([a, b]) != checkpoint_integrity_hash([replace(a, checksum="c" * 64), b])


def test_service_refuses_missing_ports():
    w = World()
    with pytest.raises(TypeError):
        RecoveryService(trust=w.trust, memory=w.repo, checkpoints=None, plans=MemoryPlanStore(),
                        rewind=object(), external_actions=External(), persist_audit=lambda e: None)
    with pytest.raises(TypeError):
        RecoveryService(trust=object(), memory=w.repo, checkpoints=MemoryCheckpoints(), plans=MemoryPlanStore(),
                        rewind=object(), external_actions=External(), persist_audit=lambda e: None)
    assert isinstance(RecoveryPlanRecord, type)


# =============================================================================
# HTTP routes (api/recovery.py) — router mounted on a test app (M1 has not registered it)
# =============================================================================

from fastapi import FastAPI  # noqa: E402

from backend.app.api.recovery import router as recovery_router  # noqa: E402
from backend.app.core.exceptions import register_exception_handlers  # noqa: E402
from backend.tests.security.test_drift_api import SETTINGS, auth_repo, call  # noqa: E402


def recovery_app(env=None):
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = SETTINGS
    app.state.auth_repo = auth_repo()
    if env is not None:
        app.state.recovery_service = env.svc
    app.include_router(recovery_router, prefix="/api/v1")
    return app


def test_http_preview_execute_and_read(env):
    app = recovery_app(env)
    res = call(app, "POST", "/api/v1/recovery/plans/preview", "analyst-a", env.request())
    assert res.status_code == 200 and res.json()["restored_records_become"] == "UNVERIFIED"
    plan_id = res.json()["plan_id"]
    assert res.json()["irreversible_external_actions"] == 1
    read = call(app, "GET", f"/api/v1/recovery/plans/{plan_id}", "aud-a")          # AUDITOR may read
    assert read.status_code == 200 and read.json()["status"] == "PREVIEWED"
    ex = call(app, "POST", "/api/v1/recovery/plans/execute", "admin-a", {"plan_id": plan_id})
    assert ex.status_code == 200 and ex.json()["status"] == "EXECUTED" and ex.json()["success"] is True
    again = call(app, "POST", "/api/v1/recovery/plans/execute", "admin-a", {"plan_id": plan_id})
    assert again.status_code == 409 and again.json()["success"] is False


@pytest.mark.parametrize("user", ["aud-a", "aidev-a", "dev-a"])
def test_http_mutations_require_security_operator(env, user):
    app = recovery_app(env)
    assert call(app, "POST", "/api/v1/recovery/plans/preview", user, env.request()).status_code == 403
    assert call(app, "POST", "/api/v1/recovery/plans/execute", user, {"plan_id": "plan-x"}).status_code == 403
    assert env.plans.rows == {}


def test_http_unknown_role_cannot_read_plans(env):
    app = recovery_app(env)
    plan_id = env.preview().plan_id
    assert call(app, "GET", f"/api/v1/recovery/plans/{plan_id}", "dev-a").status_code == 403


def test_http_cross_tenant_plan_is_not_found(env):
    app = recovery_app(env)
    plan_id = env.preview().plan_id
    assert call(app, "GET", f"/api/v1/recovery/plans/{plan_id}", "analyst-b").status_code == 404
    assert call(app, "POST", "/api/v1/recovery/plans/execute", "analyst-b", {"plan_id": plan_id}).status_code == 404


def test_http_failed_rollback_is_503_not_success(env):
    app = recovery_app(env)
    plan_id = env.preview().plan_id
    env.rewind.fail_at = 1
    res = call(app, "POST", "/api/v1/recovery/plans/execute", "analyst-a", {"plan_id": plan_id})
    assert res.status_code == 503 and res.json()["success"] is False and "ROLLBACK_FAILED" in res.json()["reason_codes"]


@pytest.mark.parametrize("body", [{"plan_id": "x", "tenant_id": T_B}, {"plan_id": "../x"}, {}])
def test_http_execute_body_is_strict(env, body):
    res = call(recovery_app(env), "POST", "/api/v1/recovery/plans/execute", "analyst-a", body)
    assert res.status_code in (400, 422)


def test_http_without_configured_service_fails_closed():
    app = recovery_app()
    assert call(app, "POST", "/api/v1/recovery/plans/execute", "analyst-a", {"plan_id": "plan-1"}).status_code == 503
    assert call(app, "GET", "/api/v1/recovery/plans/plan-1", "aud-a").status_code == 503


def test_http_route_layer_alone_rejects_non_operators(env):
    """Route dependencies reject before the service is reached (service-level checks mask otherwise)."""
    calls = []

    class PermissiveRecovery(RecoveryService):
        async def preview(self, context, request):
            calls.append("preview")
            raise NotFoundError("stub")

        async def execute(self, context, plan_id):
            calls.append("execute")
            raise NotFoundError("stub")

    app = recovery_app(env)
    app.state.recovery_service = PermissiveRecovery(
        trust=env.w.trust, memory=env.w.repo, checkpoints=env.checkpoints, plans=env.plans, rewind=env.rewind,
        external_actions=env.external, persist_audit=env.persist_audit)
    for user in ("aud-a", "aidev-a"):
        assert call(app, "POST", "/api/v1/recovery/plans/preview", user, env.request()).status_code == 403
        assert call(app, "POST", "/api/v1/recovery/plans/execute", user, {"plan_id": "plan-1"}).status_code == 403
    assert calls == []
    assert call(app, "POST", "/api/v1/recovery/plans/execute", "analyst-a", {"plan_id": "plan-1"}).status_code == 404
    assert calls == ["execute"]
