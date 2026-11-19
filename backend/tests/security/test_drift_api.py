"""HTTP tests for the Drift Monitor API (M4 Day 6) behind M1's real authentication.

Module: backend.tests.security.test_drift_api
Owner: M4 — Security Engine & Incident Response Lead

``TransactionalMemoryStore`` is a TEST double implementing the ``DriftReviewStore``
contract (row lock -> decide -> compare-and-set -> audit append, all-or-nothing) with
failure injection. The production adapter is ``SqlDriftReviewStore`` over M6's
UnitOfWork; its PostgreSQL behaviour is covered by ``test_drift_postgres.py`` (which
requires a database) and its SQL by ``test_drift_scoring.py``.
"""

import asyncio
import copy
import uuid
from dataclasses import replace
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI

from backend.app.api.drift import router as drift_router
from backend.app.core.config import Settings
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.security import create_access_token
from backend.app.security.drift import (
    AUDIT_EVENT_TYPE,
    DriftObservationView,
    DriftReviewService,
    PlanKind,
    ReviewConflict,
    StoreReviewResult,
)
from backend.app.tenancy.context import InMemoryAuthRepository, MembershipRecord, TenantRecord, UserRecord

T_A, T_B = "tenant-a-uuid-001", "tenant-b-uuid-002"
JWT = "m4-day6-drift-api-test-secret-with-plenty-of-entropy!!"
SETTINGS = Settings(APP_ENV="test", JWT_SECRET=JWT)


class TransactionalMemoryStore:
    """In-memory ``DriftReviewStore`` with transactional semantics and fault injection."""

    def __init__(self):
        self.rows = {}           # (tenant, id) -> DriftObservationView
        self.audit = []          # appended audit events (append-only)
        self.calls = []          # (method, tenant) for "no unscoped query" checks
        self._locks = {}
        self.fail_audit = False
        self.fail_list = False
        self.lose_cas = False    # simulate a concurrent writer winning between lock and CAS
        self.yield_inside_lock = True

    def add(self, tenant, obs_id, **fields):
        base = dict(record_id=f"mem-{obs_id}", classification="POTENTIAL_POISONING", divergence_score="0.78",
                    evidence_summary="Vendor account replaced with ACC-ATTACKER-999", reviewer_status="PENDING",
                    created_at=datetime(2026, 11, 18, tzinfo=timezone.utc))
        base.update(fields)
        self.rows[(tenant, obs_id)] = DriftObservationView(id=obs_id, tenant_id=tenant, **base)
        return obs_id

    async def list_observations(self, tenant_id, *, limit, offset, classification, reviewer_status):
        self.calls.append(("list", tenant_id))
        if not tenant_id:
            raise AssertionError("unscoped query attempted")
        if self.fail_list:
            raise ConnectionError("db down")
        rows = sorted((v for (t, _), v in self.rows.items() if t == tenant_id), key=lambda v: v.id)
        if classification:
            rows = [r for r in rows if r.classification == classification]
        if reviewer_status:
            rows = [r for r in rows if r.reviewer_status == reviewer_status]
        return rows[offset: offset + limit]

    async def review(self, tenant_id, observation_id, decide, audit):
        self.calls.append(("review", tenant_id))
        if not tenant_id:
            raise AssertionError("unscoped query attempted")
        key = (tenant_id, observation_id)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:                                   # SELECT ... FOR UPDATE
            if self.yield_inside_lock:
                await asyncio.sleep(0)
            before = self.rows.get(key)
            if before is None:
                return None
            snapshot_rows, snapshot_audit = copy.copy(self.rows), list(self.audit)
            try:
                plan = decide(before)
                if plan.kind is not PlanKind.APPLY:
                    return StoreReviewResult(plan, before, before, None)
                if self.lose_cas or self.rows[key].reviewer_status != before.reviewer_status:
                    raise ReviewConflict()
                after = replace(before, reviewer_status=plan.new_status)
                self.rows[key] = after
                draft = audit(plan, before)
                if self.fail_audit:
                    raise ConnectionError("audit insert failed")
                event = {"id": str(uuid.uuid4()), "tenant_id": tenant_id, "actor_id": draft.actor_id,
                         "event_type": AUDIT_EVENT_TYPE, "resource_id": observation_id, "action": "REVIEW",
                         "outcome": "SUCCESS", "trace_id": draft.trace_id, "details_json": dict(draft.details),
                         "chain_seq": len([e for e in self.audit if e["tenant_id"] == tenant_id]) + 1}
                self.audit.append(event)
                return StoreReviewResult(plan, before, after, event["id"], event["chain_seq"])
            except BaseException:
                self.rows, self.audit = snapshot_rows, snapshot_audit   # ROLLBACK
                raise


def auth_repo():
    repo = InMemoryAuthRepository()
    repo.add_tenant(TenantRecord(id=T_A, name="A", slug="a"))
    repo.add_tenant(TenantRecord(id=T_B, name="B", slug="b"))
    for uid, tid, role in [("analyst-a", T_A, "SECURITY_ANALYST"), ("admin-a", T_A, "TENANT_ADMIN"),
                           ("dev-a", T_A, "DEVELOPER"), ("aidev-a", T_A, "AI_DEVELOPER"),
                           ("aud-a", T_A, "AUDITOR"), ("analyst-b", T_B, "SECURITY_ANALYST")]:
        repo.add_user(UserRecord(id=uid, email=f"{uid}@x.test", hashed_password="x", full_name=uid))
        repo.add_membership(MembershipRecord(id=f"m-{uid}", tenant_id=tid, user_id=uid, role=role, status="ACTIVE"))
    return repo


def build_app(store=None, with_service=True):
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = SETTINGS
    app.state.auth_repo = auth_repo()
    if with_service:
        app.state.drift_service = DriftReviewService(store)
    app.include_router(drift_router, prefix="/api/v1")
    return app


USER_TENANT = {"analyst-a": T_A, "admin-a": T_A, "dev-a": T_A, "aidev-a": T_A, "aud-a": T_A, "analyst-b": T_B}


def headers(user, **extra):
    h = {"Authorization": "Bearer " + create_access_token(user_id=user, tenant_id=USER_TENANT[user],
                                                          role="TENANT_ADMIN", settings=SETTINGS)}
    h.update(extra)
    return h


def call(app, method, path, user=None, json=None, **hdrs):
    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            h = headers(user, **hdrs) if user else dict(hdrs)
            return await c.request(method, path, json=json, headers=h)
    return asyncio.run(go())


def review(app, obs_id, status_value, user="analyst-a", **hdrs):
    return call(app, "POST", f"/api/v1/drift/observations/{obs_id}/review", user, {"status": status_value}, **hdrs)


@pytest.fixture
def store():
    s = TransactionalMemoryStore()
    s.add(T_A, "obs-a1", divergence_score="0.78")
    s.add(T_A, "obs-a2", classification="LEGITIMATE_UPDATE", divergence_score="0.12")
    s.add(T_A, "obs-a3", classification="OUTDATED", divergence_score="0.40", reviewer_status="APPROVED")
    s.add(T_B, "obs-b1", divergence_score="0.91")
    return s


@pytest.fixture
def app(store):
    return build_app(store)


# =============================================================================
# B. Listing
# =============================================================================

def test_list_returns_tenant_observations_with_assessment(app):
    res = call(app, "GET", "/api/v1/drift/observations", "analyst-a")
    assert res.status_code == 200
    body = res.json()
    assert [o["id"] for o in body] == ["obs-a1", "obs-a2", "obs-a3"]
    first = body[0]
    assert set(first) == {"id", "tenant_id", "record_id", "classification", "divergence_score",
                          "evidence_summary", "reviewer_status", "created_at", "assessment"}
    assert first["assessment"]["priority"] == "HIGH" and first["assessment"]["is_verdict"] is False
    assert body[1]["assessment"]["priority"] == "LOW"


@pytest.mark.parametrize("user", ["dev-a", "aud-a", "admin-a"])
def test_any_tenant_member_may_list(app, user):
    assert call(app, "GET", "/api/v1/drift/observations", user).status_code == 200


def test_list_pagination_and_filters(app):
    page = call(app, "GET", "/api/v1/drift/observations?limit=2&offset=1", "analyst-a").json()
    assert [o["id"] for o in page] == ["obs-a2", "obs-a3"]
    pending = call(app, "GET", "/api/v1/drift/observations?reviewer_status=PENDING", "analyst-a").json()
    assert {o["id"] for o in pending} == {"obs-a1", "obs-a2"}
    outdated = call(app, "GET", "/api/v1/drift/observations?classification=OUTDATED", "analyst-a").json()
    assert [o["id"] for o in outdated] == ["obs-a3"]


def test_empty_list(app):
    assert call(app, "GET", "/api/v1/drift/observations?offset=50", "analyst-a").json() == []


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=abc", "offset=-1",
                                   "classification=MALICIOUS", "reviewer_status=pending"])
def test_invalid_pagination_or_filters_rejected(app, query):
    res = call(app, "GET", f"/api/v1/drift/observations?{query}", "analyst-a")
    assert res.status_code == 400 and res.json()["error"]["code"] == "VALIDATION_ERROR"


def test_list_requires_authentication(app):
    assert call(app, "GET", "/api/v1/drift/observations").status_code == 401


def test_list_store_failure_is_503(app, store):
    store.fail_list = True
    res = call(app, "GET", "/api/v1/drift/observations", "analyst-a")
    assert res.status_code == 503 and "db down" not in res.text


def test_missing_service_fails_closed():
    app = build_app(with_service=False)
    assert call(app, "GET", "/api/v1/drift/observations", "analyst-a").status_code == 503
    assert review(app, "obs-a1", "APPROVED").status_code == 503


# =============================================================================
# B. Review
# =============================================================================

@pytest.mark.parametrize("user,role", [("analyst-a", "SECURITY_ANALYST"), ("admin-a", "TENANT_ADMIN")])
@pytest.mark.parametrize("decision", ["APPROVED", "REJECTED"])
def test_authorized_review_persists_and_audits(app, store, user, role, decision):
    res = review(app, "obs-a1", decision, user, **{"X-Trace-ID": "tr-drift-01"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["outcome"] == "APPLIED" and body["previous_status"] == "PENDING"
    assert body["observation"]["reviewer_status"] == decision
    assert store.rows[(T_A, "obs-a1")].reviewer_status == decision            # persisted
    assert len(store.audit) == 1
    ev = store.audit[0]
    assert ev["id"] == body["audit_event_id"] and ev["event_type"] == "DRIFT_OBSERVATION_REVIEWED"
    assert ev["actor_id"] == user and ev["tenant_id"] == T_A and ev["trace_id"] == "tr-drift-01"
    d = ev["details_json"]
    assert (d["previous_status"], d["new_status"]) == ("PENDING", decision)
    assert d["actor_role"] == role and d["memory_trust_changed"] is False and d["reviewed_at"]
    assert "Vendor account replaced" not in repr(d)                         # no evidence text in audit
    assert body["follow_up"] == ("QUARANTINE_DECISION_REQUIRED" if decision == "REJECTED" else "NO_TRUST_CHANGE")


def test_review_preserves_evidence_fields(app, store):
    before = store.rows[(T_A, "obs-a1")]
    review(app, "obs-a1", "REJECTED")
    after = store.rows[(T_A, "obs-a1")]
    assert (after.classification, after.divergence_score, after.evidence_summary, after.record_id) == \
           (before.classification, before.divergence_score, before.evidence_summary, before.record_id)


@pytest.mark.parametrize("payload", [{"status": "PENDING"}, {"status": "approved"}, {"status": "ESCALATE"},
                                     {"status": None}, {}, {"status": "APPROVED", "tenant_id": T_B},
                                     {"status": "APPROVED", "actor_id": "admin-a"},
                                     {"status": "APPROVED", "reviewer_status": "APPROVED"}])
def test_invalid_review_payload_rejected_without_side_effects(app, store, payload):
    res = call(app, "POST", "/api/v1/drift/observations/obs-a1/review", "analyst-a", payload)
    assert res.status_code == 400
    assert store.rows[(T_A, "obs-a1")].reviewer_status == "PENDING" and store.audit == []


@pytest.mark.parametrize("obs_id", ["obs a1", "obs%2Fa1", "x" * 129])
def test_invalid_observation_id_rejected(app, store, obs_id):
    res = review(app, obs_id, "APPROVED")
    assert res.status_code in (400, 404) and store.audit == []


def test_missing_observation_is_404(app, store):
    res = review(app, "obs-ghost", "APPROVED")
    assert res.status_code == 404 and store.audit == []


def test_duplicate_review_is_idempotent_and_not_re_audited(app, store):
    first, second = review(app, "obs-a1", "APPROVED"), review(app, "obs-a1", "APPROVED")
    assert first.json()["outcome"] == "APPLIED" and second.json()["outcome"] == "UNCHANGED"
    assert second.json()["audit_event_id"] is None and len(store.audit) == 1


def test_conflicting_review_of_reviewed_observation_is_409(app, store):
    res = review(app, "obs-a3", "REJECTED")   # already APPROVED
    assert res.status_code == 409 and res.json()["error"]["code"] == "CONFLICT"
    assert store.rows[(T_A, "obs-a3")].reviewer_status == "APPROVED" and store.audit == []


def test_unknown_stored_status_fails_closed(app, store):
    store.add(T_A, "obs-weird", reviewer_status="ESCALATED")
    assert review(app, "obs-weird", "APPROVED").status_code == 409
    assert store.rows[(T_A, "obs-weird")].reviewer_status == "ESCALATED"


@pytest.mark.parametrize("user", ["dev-a", "aidev-a", "aud-a"])
def test_unauthorized_roles_cannot_review(app, store, user):
    res = review(app, "obs-a1", "APPROVED", user)
    assert res.status_code == 403
    assert store.rows[(T_A, "obs-a1")].reviewer_status == "PENDING" and store.audit == []
    assert ("review", T_A) not in store.calls       # rejected before any store access


def test_unauthenticated_review_rejected(app, store):
    res = call(app, "POST", "/api/v1/drift/observations/obs-a1/review", None, {"status": "APPROVED"})
    assert res.status_code == 401 and store.audit == [] and store.calls == []


def test_jwt_role_claim_cannot_grant_review(app, store):
    token = create_access_token(user_id="dev-a", tenant_id=T_A, role="SECURITY_ANALYST", settings=SETTINGS)
    res = call(app, "POST", "/api/v1/drift/observations/obs-a1/review", None, {"status": "APPROVED"},
               Authorization=f"Bearer {token}")
    assert res.status_code == 403 and store.audit == []


# =============================================================================
# C. Tenant isolation
# =============================================================================

def test_each_tenant_sees_only_its_observations(app):
    a = {o["id"] for o in call(app, "GET", "/api/v1/drift/observations", "analyst-a").json()}
    b = {o["id"] for o in call(app, "GET", "/api/v1/drift/observations", "analyst-b").json()}
    assert a == {"obs-a1", "obs-a2", "obs-a3"} and b == {"obs-b1"}


def test_cross_tenant_review_is_404_without_modification_or_audit(app, store):
    res = review(app, "obs-b1", "REJECTED", "analyst-a")
    missing = review(app, "obs-nope", "REJECTED", "analyst-a")
    assert res.status_code == missing.status_code == 404
    assert res.json()["error"]["message"] == missing.json()["error"]["message"]
    assert store.rows[(T_B, "obs-b1")].reviewer_status == "PENDING" and store.audit == []


def test_forged_tenant_header_rejected(app, store):
    assert call(app, "GET", "/api/v1/drift/observations", "analyst-a", **{"X-Tenant-ID": T_B}).status_code == 403
    assert review(app, "obs-b1", "APPROVED", "analyst-a", **{"X-Tenant-ID": T_B}).status_code == 403
    assert store.rows[(T_B, "obs-b1")].reviewer_status == "PENDING"


def test_tenant_query_parameter_is_ignored(app):
    res = call(app, "GET", f"/api/v1/drift/observations?tenant_id={T_B}", "analyst-a")
    assert {o["id"] for o in res.json()} == {"obs-a1", "obs-a2", "obs-a3"}


def test_store_returning_foreign_row_is_suppressed(app, store):
    original = store.list_observations

    async def leaky(tenant_id, **kw):
        rows = list(await original(tenant_id, **kw))
        return rows + [store.rows[(T_B, "obs-b1")]]

    store.list_observations = leaky
    res = call(app, "GET", "/api/v1/drift/observations", "analyst-a")
    assert res.status_code == 503 and "obs-b1" not in res.text


@pytest.mark.parametrize("role", ["DEVELOPER", "AI_DEVELOPER", "AUDITOR", "security_analyst", ""])
def test_service_enforces_reviewer_role_without_http_layer(store, role):
    """Defence in depth: non-HTTP callers of the service are also role-checked."""
    from backend.app.core.exceptions import ForbiddenError
    from backend.tests.security.conftest import make_ctx
    svc = DriftReviewService(store)
    with pytest.raises(ForbiddenError):
        asyncio.run(svc.review(make_ctx(role=role, user="u-x"), "obs-a1", "APPROVED"))
    assert store.calls == [] and store.rows[(T_A, "obs-a1")].reviewer_status == "PENDING"


@pytest.mark.parametrize("status_value", ["PENDING", "approved", "", None, 1, ["APPROVED"]])
@pytest.mark.parametrize("obs_id", ["obs-a1"])
def test_service_validates_status_without_http_layer(store, status_value, obs_id):
    from backend.app.core.exceptions import ValidationError
    from backend.tests.security.conftest import make_ctx
    svc = DriftReviewService(store)
    with pytest.raises(ValidationError):
        asyncio.run(svc.review(make_ctx(role="SECURITY_ANALYST", user="analyst-a"), obs_id, status_value))
    assert store.calls == []


@pytest.mark.parametrize("obs_id", ["obs a1", "../x", "", None, 7, "x" * 129])
def test_service_validates_observation_id_without_http_layer(store, obs_id):
    from backend.app.core.exceptions import ValidationError
    from backend.tests.security.conftest import make_ctx
    svc = DriftReviewService(store)
    with pytest.raises(ValidationError):
        asyncio.run(svc.review(make_ctx(role="SECURITY_ANALYST", user="analyst-a"), obs_id, "APPROVED"))
    assert store.calls == []


@pytest.mark.parametrize("kwargs", [dict(limit=0), dict(limit=101), dict(limit=True), dict(offset=-1),
                                    dict(classification="MALICIOUS"), dict(reviewer_status="DONE")])
def test_service_validates_list_arguments_without_http_layer(store, kwargs):
    from backend.app.core.exceptions import ValidationError
    from backend.tests.security.conftest import make_ctx
    svc = DriftReviewService(store)
    with pytest.raises(ValidationError):
        asyncio.run(svc.list_observations(make_ctx(role="DEVELOPER", user="d"), **kwargs))
    assert store.calls == []


def test_missing_tenant_context_never_reaches_store(store):
    svc = DriftReviewService(store)
    for ctx in (None, "tenant-a"):
        with pytest.raises(Exception):
            asyncio.run(svc.list_observations(ctx))
        with pytest.raises(Exception):
            asyncio.run(svc.review(ctx, "obs-a1", "APPROVED"))
    assert store.calls == []


# =============================================================================
# D/F. Audit atomicity, failure and concurrency
# =============================================================================

def test_audit_failure_rolls_back_review(app, store):
    store.fail_audit = True
    res = review(app, "obs-a1", "REJECTED")
    assert res.status_code == 503 and "audit insert failed" not in res.text
    assert store.rows[(T_A, "obs-a1")].reviewer_status == "PENDING" and store.audit == []


def test_lost_compare_and_set_is_409_without_side_effects(app, store):
    store.lose_cas = True
    res = review(app, "obs-a1", "APPROVED")
    assert res.status_code == 409
    assert store.rows[(T_A, "obs-a1")].reviewer_status == "PENDING" and store.audit == []


def test_concurrent_conflicting_reviews_one_wins(store):
    svc = DriftReviewService(store)
    from backend.tests.security.conftest import make_ctx
    a1 = make_ctx(role="SECURITY_ANALYST", user="analyst-a")
    a2 = make_ctx(role="TENANT_ADMIN", user="admin-a")

    async def both():
        return await asyncio.gather(svc.review(a1, "obs-a1", "APPROVED"), svc.review(a2, "obs-a1", "REJECTED"),
                                    return_exceptions=True)

    results = asyncio.run(both())
    winners = [r for r in results if not isinstance(r, Exception)]
    losers = [r for r in results if isinstance(r, Exception)]
    assert len(winners) == 1 and len(losers) == 1 and getattr(losers[0], "status_code", None) == 409
    assert store.rows[(T_A, "obs-a1")].reviewer_status == winners[0].observation.reviewer_status
    assert len(store.audit) == 1


def test_concurrent_identical_reviews_audited_once(store):
    svc = DriftReviewService(store)
    from backend.tests.security.conftest import make_ctx
    ctxs = [make_ctx(role="SECURITY_ANALYST", user=f"analyst-{i}") for i in range(5)]

    async def many():
        return await asyncio.gather(*[svc.review(c, "obs-a1", "REJECTED") for c in ctxs])

    outcomes = asyncio.run(many())
    assert sorted(o.kind.value for o in outcomes) == ["APPLIED"] + ["UNCHANGED"] * 4
    assert len(store.audit) == 1


def test_review_does_not_touch_memory_trust(app, store):
    from backend.tests.security.conftest import World
    w = World()
    rid = w.memory_in_state("SUSPICIOUS")
    store.add(T_A, "obs-mem", record_id=rid)
    assert review(app, "obs-mem", "APPROVED").status_code == 200
    assert w.repo.get_record(rid, T_A).trust_state == "SUSPICIOUS"   # approval never promotes trust
    store.add(T_A, "obs-mem2", record_id=rid)
    assert review(app, "obs-mem2", "REJECTED").status_code == 200
    assert w.repo.get_record(rid, T_A).trust_state == "SUSPICIOUS"   # rejection never auto-quarantines


def test_audit_chain_sequence_is_per_tenant(app, store):
    review(app, "obs-a1", "APPROVED")
    review(app, "obs-a2", "REJECTED")
    review(app, "obs-b1", "REJECTED", "analyst-b")
    assert [(e["tenant_id"], e["chain_seq"]) for e in store.audit] == [(T_A, 1), (T_A, 2), (T_B, 1)]
