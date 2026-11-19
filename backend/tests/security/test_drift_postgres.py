"""PostgreSQL integration tests for ``SqlDriftReviewStore`` (M4 Day 6).

Module: backend.tests.security.test_drift_postgres
Owner: M4 — Security Engine & Incident Response Lead

Runs against a throwaway database created and migrated to head with M6's own test
helpers (``backend/tests/database/helpers.py``). Requires ``TEST_DATABASE_URL`` exactly as
M6's suite does (see ``docs/database-design/INTEGRATION-GUIDE.md`` §1). Unlike M6's suite,
these tests SKIP when it is unset so the ordinary unit run is unaffected — a skip here
means "NOT TESTED", never "passed".
"""

import asyncio
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"),
                                reason="TEST_DATABASE_URL not set: PostgreSQL drift tests NOT RUN")

asyncpg = pytest.importorskip("asyncpg")

from backend.app.database.models import DriftObservation, MemoryRecord, Tenant  # noqa: E402
from backend.app.database.repositories.gateway import AuditEventRepository  # noqa: E402
from backend.app.database.session import create_engine, create_session_factory  # noqa: E402
from backend.app.database.unit_of_work import UnitOfWork  # noqa: E402
from backend.app.security.drift import DriftReviewService, SqlDriftReviewStore  # noqa: E402
from backend.tests.security.conftest import make_ctx  # noqa: E402

T_A, T_B = "tenant-drift-a", "tenant-drift-b"
ANALYST = make_ctx(role="SECURITY_ANALYST", tenant=T_A, user="analyst-a")
ADMIN = make_ctx(role="TENANT_ADMIN", tenant=T_A, user="admin-a")
ANALYST_B = make_ctx(role="SECURITY_ANALYST", tenant=T_B, user="analyst-b")


@pytest.fixture(scope="module")
def database():
    from backend.tests.database.helpers import create_temp_database, drop_temp_database, upgrade

    name = create_temp_database()
    try:
        upgrade(name)
        yield name
    finally:
        drop_temp_database(name)


@pytest.fixture
def env(database):
    from backend.tests.database.helpers import sqlalchemy_url

    async def setup():
        engine = create_engine(sqlalchemy_url(database))
        factory = create_session_factory(engine)
        ids = {}
        for tenant in (T_A, T_B):
            async with UnitOfWork(factory)(tenant) as tx:
                if await tx.session.get(Tenant, tenant) is None:
                    tx.session.add(Tenant(id=tenant, name=tenant, slug=tenant))
                    await tx.session.flush()
                rec = MemoryRecord(id=str(uuid.uuid4()), tenant_id=tenant)
                tx.session.add(rec)
                await tx.session.flush()
                obs = DriftObservation(id=f"obs-{uuid.uuid4().hex[:12]}", tenant_id=tenant, record_id=rec.id,
                                       classification="POTENTIAL_POISONING", divergence_score="0.78",
                                       evidence_summary="Vendor account replaced")
                tx.session.add(obs)
                await tx.session.flush()
                ids[tenant] = obs.id
        return engine, factory, ids

    engine, factory, ids = asyncio.run(setup())
    yield factory, ids
    asyncio.run(engine.dispose())


def run(coro):
    return asyncio.run(coro)


async def _status(factory, tenant, obs_id):
    async with UnitOfWork(factory)(tenant) as tx:
        row = await tx.session.get(DriftObservation, obs_id)
        return None if row is None or row.tenant_id != tenant else row.reviewer_status


async def _audit(factory, tenant):
    async with UnitOfWork(factory)(tenant) as tx:
        events = await tx.audit.list_recent(limit=100)
        return list(events), await tx.audit.chain_break()


def test_review_persists_status_and_appends_hash_chained_audit(env):
    factory, ids = env
    svc = DriftReviewService(SqlDriftReviewStore(factory))
    out = run(svc.review(ANALYST, ids[T_A], "REJECTED", trace_id="tr-pg-1"))
    assert out.kind.value == "APPLIED"
    assert run(_status(factory, T_A, ids[T_A])) == "REJECTED"           # committed, re-read in a new tx
    events, chain_break = run(_audit(factory, T_A))
    ev = next(e for e in events if e.id == out.audit_event_id)
    assert ev.event_type == "DRIFT_OBSERVATION_REVIEWED" and ev.actor_id == "analyst-a" and ev.trace_id == "tr-pg-1"
    assert ev.details_json["previous_status"] == "PENDING" and ev.details_json["new_status"] == "REJECTED"
    assert ev.chain_seq >= 1 and ev.event_hash and chain_break is None


def test_repeat_is_idempotent_and_conflict_refused(env):
    factory, ids = env
    svc = DriftReviewService(SqlDriftReviewStore(factory))
    run(svc.review(ANALYST, ids[T_A], "APPROVED"))
    before, _ = run(_audit(factory, T_A))
    assert run(svc.review(ADMIN, ids[T_A], "APPROVED")).kind.value == "UNCHANGED"
    with pytest.raises(Exception) as info:
        run(svc.review(ADMIN, ids[T_A], "REJECTED"))
    assert getattr(info.value, "status_code", None) == 409
    after, _ = run(_audit(factory, T_A))
    assert len(after) == len(before) and run(_status(factory, T_A, ids[T_A])) == "APPROVED"


def test_audit_failure_rolls_back_status(env, monkeypatch):
    factory, ids = env

    async def broken(self, event):
        raise RuntimeError("audit insert failed")

    monkeypatch.setattr(AuditEventRepository, "append", broken)
    svc = DriftReviewService(SqlDriftReviewStore(factory))
    with pytest.raises(Exception) as info:
        run(svc.review(ANALYST, ids[T_A], "REJECTED"))
    assert getattr(info.value, "status_code", None) == 503
    assert run(_status(factory, T_A, ids[T_A])) == "PENDING"


def test_cross_tenant_review_not_found_and_unmodified(env):
    factory, ids = env
    svc = DriftReviewService(SqlDriftReviewStore(factory))
    with pytest.raises(Exception) as info:
        run(svc.review(ANALYST, ids[T_B], "REJECTED"))
    assert getattr(info.value, "status_code", None) == 404
    assert run(_status(factory, T_B, ids[T_B])) == "PENDING"
    listed = run(svc.list_observations(ANALYST, limit=100))
    assert ids[T_B] not in {v.id for v, _ in listed} and all(v.tenant_id == T_A for v, _ in listed)


def test_concurrent_conflicting_reviews_one_wins(env):
    factory, ids = env
    svc = DriftReviewService(SqlDriftReviewStore(factory))

    async def both():
        return await asyncio.gather(svc.review(ANALYST, ids[T_A], "APPROVED"),
                                    svc.review(ADMIN, ids[T_A], "REJECTED"), return_exceptions=True)

    results = run(both())
    ok = [r for r in results if not isinstance(r, Exception)]
    assert len(ok) == 1 and run(_status(factory, T_A, ids[T_A])) == ok[0].observation.reviewer_status
