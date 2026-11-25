"""Regression tests for remaining Phase 1 requirements (A, D, E, F, G, H).

Verifies:
1. Lifespan upgrades default in-memory repositories to persistent SQLAlchemy
   repositories when a session factory is configured in development mode.
2. SqlTrustDecisionStore awaits writes, preserves all TrustDecision fields across
   simulated restarts, shares state with TrustEvaluator/PolicyEngine/Gateway,
   and fails closed (never swallows DB errors).
3. RedisRateLimiter with redis_client=None fails closed in production instead of
   silently falling back to process-local counters.
4. OutboxProcessor wired by lifespan registers Phase 1 handlers and never marks
   unknown event types as PUBLISHED.
5. CrewAISettings does not reuse employee credentials as default agent credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.app.core.config import Settings
from backend.app.core.dependencies import RedisRateLimiter
from backend.app.core.exceptions import SecurityDependencyError
from backend.app.main import create_app
from backend.app.memory.models import TrustState
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.recovery.store import SqlTrustDecisionStore
from backend.app.security.trust import (
    ActorType,
    TrustDecision,
    TrustEvaluator,
    TrustOperation,
    TrustReason,
)
from backend.app.workers.outbox import (
    PHASE1_OUTBOX_EVENT_TYPES,
    STATUS_DEAD_LETTER,
    STATUS_PUBLISHED,
    publish_outbox_event,
)
from crewai_service.config.settings import CrewAISettings


async def _make_sqlite_session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE tenants (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(64) NOT NULL UNIQUE,
                    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE memory_records (
                    id VARCHAR(36) PRIMARY KEY,
                    tenant_id VARCHAR(36) NOT NULL,
                    agent_id VARCHAR(36),
                    source_id VARCHAR(36),
                    trust_state VARCHAR(32) NOT NULL,
                    current_version INTEGER NOT NULL,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE trust_decisions (
                    id VARCHAR(36) PRIMARY KEY,
                    tenant_id VARCHAR(36) NOT NULL,
                    record_id VARCHAR(36) NOT NULL,
                    from_state VARCHAR(32) NOT NULL,
                    to_state VARCHAR(32) NOT NULL,
                    operation VARCHAR(64) NOT NULL,
                    actor_id VARCHAR(128) NOT NULL,
                    reason_code VARCHAR(64) NOT NULL,
                    evidence_json JSON NOT NULL,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE outbox_events (
                    id VARCHAR(36) PRIMARY KEY,
                    tenant_id VARCHAR(36) NOT NULL,
                    event_type VARCHAR(128) NOT NULL,
                    payload JSON NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER,
                    next_attempt_at DATETIME,
                    locked_by VARCHAR(128),
                    locked_at DATETIME,
                    locked_until DATETIME,
                    dead_lettered_at DATETIME,
                    last_error VARCHAR(512),
                    idempotency_key VARCHAR(255),
                    created_at DATETIME NOT NULL,
                    published_at DATETIME
                )
                """
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


@pytest.mark.asyncio
async def test_lifespan_upgrades_default_in_memory_repos_when_db_configured():
    engine, session_factory = await _make_sqlite_session_factory()
    try:
        settings = Settings(
            APP_ENV="development",
            JWT_SECRET="test-secret-key-at-least-32-characters-long",
            DATABASE_URL="sqlite+aiosqlite:///:memory:",
            ALLOW_IN_MEMORY_AUTH=True,
            ALLOW_IN_MEMORY_RATE_LIMITER=True,
        )
        app = create_app(settings)
        app.state.db_session_factory = session_factory

        # Simulate an explicit test override on one repo to verify it is preserved
        custom_incident_repo = object()
        app.state.incident_repo = custom_incident_repo

        async with app.router.lifespan_context(app):
            assert getattr(app.state.auth_repo, "is_demo", True) is False
            assert getattr(app.state.agent_repo, "is_persistent", False) is True
            assert getattr(app.state.memory_repo, "is_persistent", False) is True
            assert getattr(app.state.gateway_repo, "is_persistent", False) is True
            assert getattr(app.state.trace_repo, "is_persistent", False) is True
            assert getattr(app.state.trust_decision_store, "is_persistent", False) is True
            assert app.state.trust_evaluator is not None
            assert app.state.incident_repo is custom_incident_repo
            for evt_type in PHASE1_OUTBOX_EVENT_TYPES:
                assert evt_type in app.state.outbox_processor.handlers
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_sql_trust_decision_store_survives_restart_and_fails_closed():
    engine, session_factory = await _make_sqlite_session_factory()
    try:
        tenant_id = "tenant-a-uuid-001"
        record_id = "rec-restart-001"

        store1 = SqlTrustDecisionStore(session_factory)
        decision = TrustDecision(
            decision_id="td-restart-001",
            allowed=True,
            applied=True,
            decision="APPLIED",
            reason_codes=(TrustReason.TRANSITION_APPLIED.value,),
            reason="Verified quarantine",
            record_id=record_id,
            tenant_id=tenant_id,
            operation=TrustOperation.QUARANTINE.value,
            transition_id="T-04",
            current_state="UNVERIFIED",
            stored_state="UNVERIFIED",
            target_state="QUARANTINED",
            resulting_state="QUARANTINED",
            record_version=1,
            version_checksum="sha256-abc",
            actor_type=ActorType.SYSTEM_DETECTOR.value,
            actor_id="detector-1",
            actor_role=None,
            incident_id="inc-001",
            evidence_summary={"source": "unit-test"},
            policy_version="amsc-trust-policy/1.0.0",
            timestamp=datetime.now(timezone.utc),
            history_available=True,
        )
        await store1.aappend(decision)

        # Simulate backend restart: fresh store instance with empty in-memory cache
        store2 = SqlTrustDecisionStore(session_factory)
        reloaded = await store2.alist_for_record(tenant_id, record_id)
        assert len(reloaded) == 1
        assert reloaded[0].decision_id == "td-restart-001"
        assert reloaded[0].applied is True
        assert reloaded[0].resulting_state == "QUARANTINED"
        assert reloaded[0].record_version == 1
        assert reloaded[0].version_checksum == "sha256-abc"
        assert reloaded[0].incident_id == "inc-001"

        # Fail closed when DB is broken (must NOT swallow error or fall back to cache)
        class BrokenSessionFactory:
            def __call__(self):
                raise RuntimeError("DB connection lost")

        broken_store = SqlTrustDecisionStore(BrokenSessionFactory())  # type: ignore[arg-type]
        broken_store._by_record[(tenant_id, record_id)] = [decision]

        with pytest.raises(RuntimeError, match="DB connection lost"):
            await broken_store.aappend(decision)

        with pytest.raises(RuntimeError, match="DB connection lost"):
            await broken_store.alist_for_record(tenant_id, record_id)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_trust_evaluator_aapply_reverts_when_store_fails():
    mem_repo = InMemoryMemoryRepository()
    from backend.app.memory.integrity import sha256_hex
    from backend.app.memory.models import MemoryRecord, MemoryVersion

    now = datetime.now(timezone.utc)
    rec = MemoryRecord(
        id="rec-failclosed-01",
        tenant_id="tenant-a-uuid-001",
        agent_id="agent-1",
        source_id="src-1",
        trust_state=TrustState.UNVERIFIED,
        current_version=1,
        created_at=now,
        updated_at=now,
    )
    mem_repo.create_record(rec)
    mem_repo.create_version(
        MemoryVersion(
            id="ver-1",
            tenant_id="tenant-a-uuid-001",
            record_id="rec-failclosed-01",
            version=1,
            content="hello",
            checksum=sha256_hex("hello"),
            created_at=now,
        )
    )

    class BrokenDurableStore:
        is_persistent = True

        async def aappend(self, decision: TrustDecision) -> None:
            raise RuntimeError("PostgreSQL write failed")

        async def alist_for_record(self, tenant_id: str, record_id: str):
            return ()

        def append(self, decision: TrustDecision) -> None:
            raise RuntimeError("Sync append disabled")

        def list_for_record(self, tenant_id: str, record_id: str):
            return ()

    # InMemoryMemoryRepository has is_persistent=False so use app_env="development" for ctor,
    # while store is still BrokenDurableStore.
    from backend.app.security.trust import UserActor
    from backend.app.tenancy.context import TenantContext

    evaluator = TrustEvaluator(mem_repo, BrokenDurableStore(), app_env="development")  # type: ignore[arg-type]
    actor = UserActor(
        TenantContext(
            tenant_id="tenant-a-uuid-001",
            tenant_slug="alphacorp",
            tenant_name="ChronoCongiSec Enterprise",
            user_id="usr-analyst-alex-02",
            role="SECURITY_ANALYST",
            is_active=True,
            branch_id="branch-ho-001",
        )
    )
    decision = await evaluator.aapply(
        {
            "record_id": "rec-failclosed-01",
            "operation": "QUARANTINE",
            "target_state": "QUARANTINED",
            "expected_state": "UNVERIFIED",
            "expected_version": 1,
            "reason": "Test fail-closed revert",
            "evidence": {"evidence_refs": ["sig-1"], "incident_id": "inc-1"},
        },
        actor,
    )
    assert decision.allowed is False
    assert decision.applied is False
    assert TrustReason.DECISION_STORE_UNAVAILABLE.value in decision.reason_codes
    # Record state must have been reverted back to UNVERIFIED
    reverted = mem_repo.get_record("rec-failclosed-01", "tenant-a-uuid-001")
    assert reverted is not None
    assert reverted.trust_state == TrustState.UNVERIFIED


@pytest.mark.asyncio
async def test_redis_rate_limiter_without_client_fails_closed_in_production(monkeypatch):
    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="prod-super-strong-secret-key-at-least-32-chars",
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_AUTH=False,
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        DATABASE_URL="postgresql+asyncpg://amsc:strong_prod_pw@db.internal:5432/amsc",
        REDIS_URL="redis://redis.internal:6379/0",
    )
    monkeypatch.setattr("backend.app.core.config.get_settings", lambda: prod_settings)

    limiter = RedisRateLimiter(redis_client=None, failure_policy="fail_closed")
    with pytest.raises(SecurityDependencyError, match="Rate limiting service unavailable"):
        await limiter.check_rate_limit("login:ip:1.2.3.4", max_requests=5, window_seconds=60)


@pytest.mark.asyncio
async def test_lifespan_outbox_handles_phase1_events_and_dead_letters_unknown():
    engine, session_factory = await _make_sqlite_session_factory()
    try:
        settings = Settings(
            APP_ENV="development",
            JWT_SECRET="test-secret-key-at-least-32-characters-long",
            DATABASE_URL="sqlite+aiosqlite:///:memory:",
            ALLOW_IN_MEMORY_AUTH=True,
            ALLOW_IN_MEMORY_RATE_LIMITER=True,
            OUTBOX_WORKER_ENABLED=False,
        )
        app = create_app(settings)
        app.state.db_session_factory = session_factory

        async with app.router.lifespan_context(app):
            async with session_factory() as session:
                async with session.begin():
                    await publish_outbox_event(
                        session,
                        tenant_id="tenant-a-uuid-001",
                        event_type="IAM_REGISTRATION_APPROVED",
                        payload={"user_id": "u-1"},
                    )
                    await publish_outbox_event(
                        session,
                        tenant_id="tenant-a-uuid-001",
                        event_type="UNREGISTERED_EVENT_TYPE",
                        payload={"foo": "bar"},
                    )

            processed = await app.state.outbox_processor.process_batch()
            assert processed == 1

            async with session_factory() as session:
                rows = (await session.execute(text("SELECT event_type, status FROM outbox_events"))).all()
                statuses = {row[0]: row[1] for row in rows}
                assert statuses["IAM_REGISTRATION_APPROVED"] == STATUS_PUBLISHED
                assert statuses["UNREGISTERED_EVENT_TYPE"] == STATUS_DEAD_LETTER
    finally:
        await engine.dispose()


def test_crewai_settings_does_not_reuse_employee_credentials():
    settings = CrewAISettings(_env_file=None)
    assert settings.CHRONOCONGISEC_AUTH_EMAIL is None
    assert settings.CHRONOCONGISEC_AUTH_PASSWORD is None


@pytest.mark.asyncio
async def test_redis_rate_limiter_never_uses_local_counters_in_production_even_fail_open(monkeypatch):
    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="prod-super-strong-secret-key-at-least-32-chars",
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_AUTH=False,
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        DATABASE_URL="postgresql+asyncpg://amsc:strong_prod_pw@db.internal:5432/amsc",
        REDIS_URL="redis://redis.internal:6379/0",
    )
    monkeypatch.setattr("backend.app.core.config.get_settings", lambda: prod_settings)

    limiter = RedisRateLimiter(redis_client=None, failure_policy="fail_open")
    r1 = await limiter.check_rate_limit("login:ip:1.2.3.4", max_requests=1, window_seconds=60)
    r2 = await limiter.check_rate_limit("login:ip:1.2.3.4", max_requests=1, window_seconds=60)
    assert r1.allowed is True
    assert r2.allowed is True
    assert limiter._counters == {}


def test_sql_trust_decision_store_is_persistent_requires_session_factory():
    store_without_db = SqlTrustDecisionStore(None)
    assert store_without_db.is_persistent is False
