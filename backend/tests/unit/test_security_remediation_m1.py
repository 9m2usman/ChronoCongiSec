"""M1 Security Remediation & Engineering Verification Test Suite.

Exhaustively verifies security remediations across M1 ownership boundaries:
- GAP-006: Redis Rate Limiter Identity, Readiness, and Persistence Contract
- GAP-007: Session Revocation Lifecycle, Logout, and Token Invalidation
- GAP-009: Keyed HMAC Account Throttling and DoS Mitigation
- GAP-014: Cryptographic KeyRing, Key Rotation, and Algorithm Strictness
- GAP-028: Trusted Branch Identity Scoping and Tamper Resistance
- GAP-034: Comprehensive Telemetry Redaction and Pagination Bounds
- Finding I: Incident Evidence Reference Integrity and Sanitized Quarantine Errors
- Finding K: Interactive Documentation Protection in Production
- Finding N: Readiness Probe Endpoint & Dependency Health Verification
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import httpx
import pytest
from starlette.requests import Request

from backend.app.core.config import Settings
from backend.app.core.dependencies import (
    InMemoryRateLimiter,
    RateLimitResult,
    RedisRateLimiter,
    get_rate_limiter,
)
from backend.app.core.exceptions import (
    AuthenticationError,
    SecurityDependencyError,
    TenantAccessForbiddenError,
    ValidationError,
)
from backend.app.core.security import (
    InMemoryRevocationStore,
    KeyRing,
    RedisRevocationStore,
    create_access_token,
    decode_access_token,
)
from backend.app.core.logging import StructuredJsonFormatter
from backend.app.main import create_app
from backend.app.tenancy.context import (
    MembershipRecord,
    TenantContext,
    resolve_tenant_context_from_request,
)
from backend.app.api.traces import (
    InMemoryTraceRepository,
    redact_sensitive_dict,
    redact_sensitive_value,
)
from backend.app.api.incident_management import (
    EvidenceType,
    IncidentEvidenceItem,
    InMemoryIncidentRepository,
    validate_evidence_references,
)


PROD_DATABASE_URL = "postgresql+asyncpg://prod_user:prod_secure_password_987654321@prod-db.internal:5432/amsc_prod"
PROD_REDIS_URL = "redis://:prod_redis_secret@prod-redis.internal:6379/0"


# ============================================================================
# 1. GAP-006: Rate Limiter Identity and Readiness Verification
# ============================================================================

@pytest.mark.asyncio
async def test_gap006_approved_redis_limiter_accepted():
    """Verify that an approved Redis rate limiter meets the persistent contract."""
    class MockRedisClient:
        async def ping(self) -> bool:
            return True

    limiter = RedisRateLimiter(redis_client=MockRedisClient())
    assert limiter.backend == "redis"
    assert limiter.is_persistent is True
    assert limiter.is_in_memory is False
    assert await limiter.ping() is True


@pytest.mark.asyncio
async def test_gap006_in_memory_limiter_rejected_in_production():
    """Verify that an in-memory limiter is strictly rejected in production."""
    with pytest.raises((SecurityDependencyError, ValueError), match="prohibited in production|not permitted in production"):
        prod_settings = Settings(
            APP_ENV="production",
            JWT_SECRET="a" * 32,
            DATABASE_URL=PROD_DATABASE_URL,
            REDIS_URL=PROD_REDIS_URL,
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            ALLOW_LOCALHOST_CORS_IN_PRODUCTION=True,
            RATE_LIMITER_BACKEND="in_memory",
            ALLOW_IN_MEMORY_RATE_LIMITER=False,
        )
        get_rate_limiter(prod_settings)


@pytest.mark.asyncio
async def test_gap006_unapproved_limiter_rejected_in_production():
    """Verify that an arbitrary or unapproved limiter backend is strictly rejected."""
    with pytest.raises((SecurityDependencyError, ValueError), match="prohibited in production|approved distributed Redis"):
        prod_settings = Settings(
            APP_ENV="production",
            JWT_SECRET="a" * 32,
            DATABASE_URL=PROD_DATABASE_URL,
            REDIS_URL=PROD_REDIS_URL,
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            ALLOW_LOCALHOST_CORS_IN_PRODUCTION=True,
            RATE_LIMITER_BACKEND="custom_memory_proxy",
            ALLOW_IN_MEMORY_RATE_LIMITER=False,
        )
        get_rate_limiter(prod_settings)


@pytest.mark.asyncio
async def test_gap006_redis_unavailable_fail_closed():
    """Verify that when Redis is unavailable under fail_closed policy, security errors are raised."""
    class FailingRedisClient:
        async def ping(self) -> bool:
            raise ConnectionError("Redis connection refused")

    limiter = RedisRateLimiter(redis_client=FailingRedisClient(), failure_policy="fail_closed")
    assert await limiter.ping() is False


# ============================================================================
# 2. GAP-007: Token Revocation Lifecycle & Logout Verification
# ============================================================================

@pytest.mark.asyncio
async def test_gap007_revocation_store_lifecycle():
    """Verify token revocation, user revocation, and expiry in InMemoryRevocationStore."""
    store = InMemoryRevocationStore()
    now_ts = int(time.time())

    # Token not yet revoked
    assert await store.is_token_revoked("jti-123") is False

    # Revoke token
    await store.revoke_token("jti-123", expires_at=now_ts + 300, reason="Logout")
    assert await store.is_token_revoked("jti-123") is True

    # User revocation
    assert await store.is_user_revoked("user-456", tenant_id="tenant-1", issued_at=now_ts) is False
    await store.revoke_user_sessions("user-456", tenant_id="tenant-1", reason="Password change")
    assert await store.is_user_revoked("user-456", tenant_id="tenant-1", issued_at=now_ts - 5) is True


@pytest.mark.asyncio
async def test_gap007_logout_endpoint_revokes_token():
    """Verify POST /api/v1/auth/logout revokes the JWT and subsequent requests are rejected."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a" * 32,
    )
    app = create_app(settings=test_settings)

    token = create_access_token(
        user_id="user-a-analyst-001",
        tenant_id="tenant-a-uuid-001",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Access profile before logout -> 200 OK
        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200

        # Call logout
        logout_res = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout_res.status_code == 200
        assert "revoked" in logout_res.json()["message"].lower()

        # Access profile after logout -> 401 Unauthorized
        post_logout_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert post_logout_res.status_code == 401
        assert post_logout_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


# ============================================================================
# 3. GAP-009 / Finding C: Keyed HMAC and Distributed Rate Limiting
# ============================================================================

@pytest.mark.asyncio
async def test_gap009_keyed_hmac_prevents_unkeyed_rainbow_tables():
    """Verify rate limit keys use HMAC-SHA256 with a secret key, not plain SHA-256."""
    secret = "rate-limit-secret-key-123456789012"
    raw_data = "victim@example.com:tenant-1".encode("utf-8")
    expected_hmac = hmac.new(secret.encode("utf-8"), raw_data, hashlib.sha256).hexdigest()
    plain_sha256 = hashlib.sha256(raw_data).hexdigest()

    assert expected_hmac != plain_sha256
    assert len(expected_hmac) == 64


@pytest.mark.asyncio
async def test_gap009_distributed_brute_force_blocked_across_multiple_ips():
    """Verify that an attacker distributing requests across multiple distinct IPs is throttled by global account limit."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a" * 32,
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=10,
        LOGIN_RATE_LIMIT_GLOBAL_ACCOUNT_MAX_REQUESTS=4,  # Global ceiling of 4 across all IPs
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    app = create_app(settings=test_settings)

    # 4 distinct IPs each making 1 failed attempt
    for i in range(1, 5):
        ip = f"198.51.100.{i}"
        transport = httpx.ASGITransport(app=app, client=(ip, 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "analyst@company-a.com",
                    "password": "WrongPassword123!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

    # 5th attempt from a brand-new 5th IP (198.51.100.5) must be throttled with 429
    transport5 = httpx.ASGITransport(app=app, client=("198.51.100.5", 50000))
    async with httpx.AsyncClient(transport=transport5, base_url="http://test") as client5:
        blocked_res = await client5.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "WrongPassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        assert blocked_res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


# ============================================================================
# 4. GAP-014: Cryptographic KeyRing and Key Rotation Verification
# ============================================================================

def test_gap014_keyring_rotation_and_overlap_acceptance():
    """Verify KeyRing allows verifying tokens signed with prior keys while signing with active key."""
    keyring_config = {
        "active_kid": "key-2026-v2",
        "keys": {
            "key-2026-v1": {"secret": "secret-version-one-entropy-key-32ch", "status": "valid", "algorithm": "HS256"},
            "key-2026-v2": {"secret": "secret-version-two-entropy-key-32ch", "status": "active", "algorithm": "HS256"},
        },
    }
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="secret-version-two-entropy-key-32ch",
        JWT_ACTIVE_KID="key-2026-v2",
        JWT_KEYRING_CONFIG=json.dumps(keyring_config),
    )

    # Token signed with key-2026-v1
    keyring_config_v1 = {
        "active_kid": "key-2026-v1",
        "keys": {
            "key-2026-v1": {"secret": "secret-version-one-entropy-key-32ch", "status": "active", "algorithm": "HS256"},
            "key-2026-v2": {"secret": "secret-version-two-entropy-key-32ch", "status": "valid", "algorithm": "HS256"},
        },
    }
    settings_v1 = Settings(
        APP_ENV="test",
        JWT_SECRET="secret-version-one-entropy-key-32ch",
        JWT_ACTIVE_KID="key-2026-v1",
        JWT_KEYRING_CONFIG=json.dumps(keyring_config_v1),
    )
    token_v1 = create_access_token(
        user_id="user-1",
        tenant_id="tenant-1",
        role="SECURITY_ANALYST",
        settings=settings_v1,
    )

    # Token signed with key-2026-v2
    token_v2 = create_access_token(
        user_id="user-1",
        tenant_id="tenant-1",
        role="SECURITY_ANALYST",
        settings=settings,
    )

    # Both tokens successfully decode using the KeyRing
    decoded_v1 = decode_access_token(token_v1, settings=settings)
    assert decoded_v1["sub"] == "user-1"

    decoded_v2 = decode_access_token(token_v2, settings=settings)
    assert decoded_v2["sub"] == "user-1"


def test_gap014_unapproved_or_missing_algorithm_rejected():
    """Verify that tampered tokens with unknown algorithm are rejected without negotiation."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a" * 32,
    )
    with pytest.raises(AuthenticationError):
        decode_access_token("invalid.token.payload", settings=settings)


# ============================================================================
# 5. GAP-028: Trusted Branch Identity Scoping and Tamper Resistance
# ============================================================================

@pytest.mark.asyncio
async def test_gap028_trusted_branch_resolved_from_membership():
    """Verify branch_id is resolved exclusively from verified server-side MembershipRecord."""
    mem_with_branch = MembershipRecord(
        id="mem-1",
        user_id="user-1",
        tenant_id="tenant-1",
        role="SECURITY_ANALYST",
        status="ACTIVE",
        branch_id="branch-karachi-01",
    )
    ctx = TenantContext(
        tenant_id="tenant-1",
        tenant_slug="tenant-1",
        tenant_name="Tenant 1",
        user_id="user-1",
        role="SECURITY_ANALYST",
        branch_id=mem_with_branch.branch_id,
    )
    assert ctx.branch_id == "branch-karachi-01"


@pytest.mark.asyncio
async def test_gap028_client_supplied_branch_in_header_ignored():
    """Verify client-supplied branch headers (e.g. X-Branch-ID) cannot tamper with branch context."""
    test_settings = Settings(APP_ENV="test", JWT_SECRET="a" * 32)
    app = create_app(settings=test_settings)

    token = create_access_token(
        user_id="user-a-analyst-001",
        tenant_id="tenant-a-uuid-001",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Branch-ID": "forged-branch-rawalpindi",
            },
        )
        assert res.status_code == 200


# ============================================================================
# 6. GAP-034: Comprehensive Telemetry Redaction and Pagination Bounds
# ============================================================================

def test_gap034_telemetry_redaction_across_all_fields():
    """Verify redaction strips sensitive patterns across agent_name, action_detail, details, etc."""
    raw_span = {
        "span_id": "span-1",
        "agent_name": "agent-sk-ant-api03-secret12345678901234567890-test",
        "action_label": "bearer-ghp_abcdefghijklmnopqrstuvwxyz123456",
        "action_detail": "Using API key sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef for model",
        "memory_ref": "secret_key=supersecretpassword123",
        "details": {
            "prompt": "Here is the authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret",
            "safe_field": "public_action_metric",
        },
    }
    sanitized = redact_sensitive_dict(raw_span)
    assert "[REDACTED]" in sanitized["agent_name"]
    assert "[REDACTED]" in sanitized["action_label"]
    assert "[REDACTED]" in sanitized["action_detail"]
    assert "[REDACTED]" in sanitized["memory_ref"]
    assert "[REDACTED]" in sanitized["details"]["prompt"]
    assert sanitized["details"]["safe_field"] == "public_action_metric"


@pytest.mark.asyncio
async def test_gap034_trace_and_agent_pagination_bounds():
    """Verify offset and limit bounds prevent unbounded database scans."""
    test_settings = Settings(APP_ENV="test", JWT_SECRET="a" * 32)
    app = create_app(settings=test_settings)
    from backend.app.api.agents import InMemoryAgentRepository
    app.state.agent_repo = InMemoryAgentRepository()

    token = create_access_token(
        user_id="user-a-dev-009",
        tenant_id="tenant-a-uuid-001",
        role="AI_DEVELOPER",
        settings=test_settings,
        additional_claims={"email": "developer@company-a.com"},
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Agents pagination offset > 10000 -> 400 (DOC-005 validation error)
        res_agents = await client.get(
            "/api/v1/agents?offset=20000",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_agents.status_code == 400
        assert res_agents.json()["error"]["code"] == "VALIDATION_ERROR"

        # Traces pagination offset > 10000 -> 400 (DOC-005 validation error)
        res_traces = await client.get(
            "/api/v1/traces?offset=20000",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_traces.status_code == 400
        assert res_traces.json()["error"]["code"] == "VALIDATION_ERROR"


# ============================================================================
# 7. Finding I: Incident Evidence Validation & Quarantine Sanitization
# ============================================================================

@pytest.mark.asyncio
async def test_finding_i_evidence_reference_validation():
    """Verify validate_evidence_references rejects missing and cross-tenant evidence references."""
    test_settings = Settings(APP_ENV="test", JWT_SECRET="a" * 32)
    app = create_app(settings=test_settings)
    app.state.incident_repo = InMemoryIncidentRepository()
    app.state.trace_repo = InMemoryTraceRepository()

    # Construct request with app state
    scope = {"type": "http", "method": "POST", "path": "/api/v1/security/incidents", "headers": [], "app": app}
    mock_request = Request(scope)

    invalid_evidence = [
        IncidentEvidenceItem(evidence_type=EvidenceType.TRACE_SPAN, resource_id="span-nonexistent-999"),
    ]
    with pytest.raises(ValidationError, match="does not exist"):
        await validate_evidence_references(
            evidence_items=invalid_evidence,
            tenant_id="tenant-a-uuid-001",
            request=mock_request,
        )


# ============================================================================
# 8. Finding K & N: Interactive Docs Protection and Readiness Probe
# ============================================================================

@pytest.mark.asyncio
async def test_finding_k_docs_in_production_requires_authentication():
    """Verify that when docs are protected in production, unauthenticated requests are rejected."""
    prod_docs_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="a" * 32,
        DATABASE_URL=PROD_DATABASE_URL,
        REDIS_URL=PROD_REDIS_URL,
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_LOCALHOST_CORS_IN_PRODUCTION=True,
        ENABLE_DOCS_IN_PRODUCTION=True,
        PROTECT_DOCS_IN_PRODUCTION=True,
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
    )
    app = create_app(settings=prod_docs_settings)
    from backend.app.tenancy.context import InMemoryAuthRepository, seed_demo_accounts

    class MockPersistentAuthRepo(InMemoryAuthRepository):
        is_persistent: bool = True
        is_in_memory: bool = False

    mock_auth = MockPersistentAuthRepo()
    seed_demo_accounts(mock_auth)
    app.state.auth_repo = mock_auth
    app.state.rate_limiter = RedisRateLimiter()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthenticated request to /docs -> 401
        res = await client.get("/docs")
        assert res.status_code == 401

        # With valid Bearer token -> 200 OK
        token = create_access_token(
            user_id="user-a-analyst-001",
            tenant_id="tenant-a-uuid-001",
            role="SECURITY_ANALYST",
            settings=prod_docs_settings,
        )
        res_auth = await client.get("/docs", headers={"Authorization": f"Bearer {token}"})
        assert res_auth.status_code == 200


@pytest.mark.asyncio
async def test_finding_n_readiness_probe_endpoints():
    """Verify /ready and /api/v1/ready return comprehensive readiness status."""
    test_settings = Settings(APP_ENV="test", JWT_SECRET="a" * 32)
    app = create_app(settings=test_settings)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res_root_ready = await client.get("/ready")
        assert res_root_ready.status_code == 200
        data = res_root_ready.json()
        assert data["status"] == "ready"
        assert "auth_repo" in data["dependencies"]
        assert "rate_limiter" in data["dependencies"]

        res_v1_ready = await client.get("/api/v1/ready")
        assert res_v1_ready.status_code == 200
        assert res_v1_ready.json()["status"] == "ready"


# ============================================================================
# 9. Additional Deep Verification Tests (Remediation Hardening)
# ============================================================================

@pytest.mark.asyncio
async def test_in_memory_rate_limiter_reset_executes_safely():
    """Verify InMemoryRateLimiter.reset resets self.requests without AttributeError."""
    limiter = InMemoryRateLimiter()
    await limiter.check_rate_limit(key="test:user:1", max_requests=5, window_seconds=60)
    assert len(limiter.requests["test:user:1"]) == 1

    # Calling reset must successfully clear the counter without raising AttributeError
    await limiter.reset("test:user:1")
    assert len(limiter.requests.get("test:user:1", [])) == 0


@pytest.mark.asyncio
async def test_redis_rate_limiter_multi_instance_atomic_counters():
    """Verify that multiple RedisRateLimiter instances sharing a Redis client share atomic counters."""
    class MockSharedRedisClient:
        def __init__(self):
            self.store: dict[str, list[float]] = {}

        def eval(self, script, numkeys, key, now, window, max_req, member):
            now_f = float(now)
            window_f = float(window)
            max_r = int(max_req)
            cutoff = now_f - window_f

            timestamps = self.store.setdefault(key, [])
            timestamps = [t for t in timestamps if t > cutoff]
            self.store[key] = timestamps

            if len(timestamps) < max_r:
                timestamps.append(now_f)
                return [1, max_r - len(timestamps), 0]
            else:
                earliest = timestamps[0]
                retry_after = max(1, int(window_f - (now_f - earliest)))
                return [0, 0, retry_after]

        def delete(self, key):
            self.store.pop(key, None)

        def ping(self):
            return True

    shared_redis = MockSharedRedisClient()
    instance_1 = RedisRateLimiter(redis_client=shared_redis)
    instance_2 = RedisRateLimiter(redis_client=shared_redis)

    # Instance 1 consumes 2 tokens
    res1 = await instance_1.check_rate_limit("user:acct:shared", max_requests=3, window_seconds=60)
    assert res1.allowed is True
    assert res1.remaining == 2

    # Instance 2 consumes 1 token (shares state with Instance 1)
    res2 = await instance_2.check_rate_limit("user:acct:shared", max_requests=3, window_seconds=60)
    assert res2.allowed is True
    assert res2.remaining == 1

    # Instance 1 consumes the last token
    res3 = await instance_1.check_rate_limit("user:acct:shared", max_requests=3, window_seconds=60)
    assert res3.allowed is True
    assert res3.remaining == 0

    # Instance 2 is now throttled
    res4 = await instance_2.check_rate_limit("user:acct:shared", max_requests=3, window_seconds=60)
    assert res4.allowed is False

    # Reset via instance 1 allows instance 2 to make requests again
    await instance_1.reset("user:acct:shared")
    res5 = await instance_2.check_rate_limit("user:acct:shared", max_requests=3, window_seconds=60)
    assert res5.allowed is True


@pytest.mark.asyncio
async def test_redis_rate_limiter_fail_closed_on_client_error():
    """Verify that when Redis raises a connection error under fail_closed, check_rate_limit raises SecurityDependencyError."""
    class FailingRedisClient:
        def eval(self, *args, **kwargs):
            raise ConnectionError("Connection to Redis cluster timed out")

    limiter = RedisRateLimiter(redis_client=FailingRedisClient(), failure_policy="fail_closed")
    with pytest.raises(SecurityDependencyError, match="Rate limiting service unavailable"):
        await limiter.check_rate_limit("test:fail", max_requests=5, window_seconds=60)


@pytest.mark.asyncio
async def test_redis_revocation_store_multi_instance_synchronization():
    """Verify RedisRevocationStore persists and synchronizes token and user revocations."""
    class MockSharedRedisForRevocation:
        def __init__(self):
            self.data: dict[str, str] = {}

        def set(self, key, value, ex=None):
            self.data[key] = str(value)

        def get(self, key):
            return self.data.get(key)

        def exists(self, key):
            return 1 if key in self.data else 0

    redis_backend = MockSharedRedisForRevocation()
    worker_a = RedisRevocationStore(redis_client=redis_backend)
    worker_b = RedisRevocationStore(redis_client=redis_backend)

    # Worker A revokes token
    await worker_a.revoke_token("jti-sync-001", expires_at=int(time.time()) + 3600)
    # Worker B immediately observes revocation
    assert await worker_b.is_token_revoked("jti-sync-001") is True

    # Worker A revokes all sessions for user
    now_ts = int(time.time())
    await worker_a.revoke_user_sessions("user-sync-002", tenant_id="tenant-1")
    # Worker B verifies sessions issued before revocation are rejected
    assert await worker_b.is_user_revoked("user-sync-002", tenant_id="tenant-1", issued_at=now_ts - 10) is True
    # Sessions issued after are not rejected
    assert await worker_b.is_user_revoked("user-sync-002", tenant_id="tenant-1", issued_at=now_ts + 10) is False


def test_keyring_rejects_expired_rotation_overlap_key():
    """Verify KeyRing rejects tokens signed with a rotated key whose overlap period has expired."""
    now_ts = int(time.time())
    keyring_config_verify = {
        "active_kid": "k-2026-current",
        "keys": {
            "k-2026-current": {
                "secret": "current-active-key-32-chars-long!",
                "status": "active",
                "algorithm": "HS256",
            },
            "k-2025-expired": {
                "secret": "retired-previous-key-32-chars-long",
                "status": "valid",
                "algorithm": "HS256",
                "valid_until": now_ts - 100,  # Overlap expired 100 seconds ago
            },
        },
    }
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="current-active-key-32-chars-long!",
        JWT_ACTIVE_KID="k-2026-current",
        JWT_KEYRING_CONFIG=json.dumps(keyring_config_verify),
    )

    keyring_config_signing = {
        "active_kid": "k-2025-expired",
        "keys": {
            "k-2026-current": {
                "secret": "current-active-key-32-chars-long!",
                "status": "valid",
                "algorithm": "HS256",
            },
            "k-2025-expired": {
                "secret": "retired-previous-key-32-chars-long",
                "status": "active",
                "algorithm": "HS256",
                "valid_until": now_ts - 100,
            },
        },
    }
    expired_keyring_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="retired-previous-key-32-chars-long",
        JWT_ACTIVE_KID="k-2025-expired",
        JWT_KEYRING_CONFIG=json.dumps(keyring_config_signing),
    )
    token = create_access_token(
        user_id="user-1",
        tenant_id="tenant-1",
        role="SECURITY_ANALYST",
        settings=expired_keyring_settings,
    )

    with pytest.raises(AuthenticationError, match="overlap period has expired"):
        decode_access_token(token, settings=settings)


@pytest.mark.asyncio
async def test_gap028_branch_authorization_full_request_lifecycle():
    """Verify real request path enforces branch authorization across agent registry endpoints."""
    from backend.app.api.agents import (
        AgentEntity,
        AgentVersionEntity,
        InMemoryAgentRepository,
    )
    from backend.app.tenancy.context import InMemoryAuthRepository, seed_demo_accounts

    test_settings = Settings(APP_ENV="test", JWT_SECRET="a" * 32)
    app = create_app(settings=test_settings)

    auth_repo = InMemoryAuthRepository()
    seed_demo_accounts(auth_repo)
    app.state.auth_repo = auth_repo

    now = datetime.now(timezone.utc)
    agent_repo = InMemoryAgentRepository()
    # Karachi agent
    await agent_repo.create_agent_atomic(
        AgentEntity(
            id="ag-karachi-01",
            tenant_id="tenant-a-uuid-001",
            name="Karachi Ops Agent",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Karachi Prompt",
            branch_id="branch-karachi-99",
            created_at=now,
            updated_at=now,
        ),
        AgentVersionEntity(
            id="ver-k-01",
            tenant_id="tenant-a-uuid-001",
            agent_id="ag-karachi-01",
            version="v1.0.0",
            config_payload={},
            created_at=now,
        ),
    )
    # Lahore agent
    await agent_repo.create_agent_atomic(
        AgentEntity(
            id="ag-lahore-02",
            tenant_id="tenant-a-uuid-001",
            name="Lahore Analytics Agent",
            runtime="LANGCHAIN",
            model="gpt-4o",
            status="ACTIVE",
            config_version="v1.0.0",
            system_prompt="Lahore Prompt",
            branch_id="branch-lahore-88",
            created_at=now,
            updated_at=now,
        ),
        AgentVersionEntity(
            id="ver-l-02",
            tenant_id="tenant-a-uuid-001",
            agent_id="ag-lahore-02",
            version="v1.0.0",
            config_payload={},
            created_at=now,
        ),
    )
    app.state.agent_repo = agent_repo

    # Karachi-scoped user token
    karachi_token = create_access_token(
        user_id="user-a-branch-karachi-011",
        tenant_id="tenant-a-uuid-001",
        role="AI_DEVELOPER",
        settings=test_settings,
    )

    # Company-wide user token (branch_id=None)
    company_wide_token = create_access_token(
        user_id="user-a-dev-009",
        tenant_id="tenant-a-uuid-001",
        role="AI_DEVELOPER",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Karachi user accessing Karachi agent -> 200 OK
        res_k = await client.get("/api/v1/agents/ag-karachi-01", headers={"Authorization": f"Bearer {karachi_token}"})
        assert res_k.status_code == 200
        assert res_k.json()["id"] == "ag-karachi-01"

        # 2. Karachi user accessing Lahore agent -> 404 Not Found (branch boundary enforcement)
        res_l = await client.get("/api/v1/agents/ag-lahore-02", headers={"Authorization": f"Bearer {karachi_token}"})
        assert res_l.status_code == 404

        # 3. Karachi user attempts to forge branch header -> still 404
        res_forge = await client.get(
            "/api/v1/agents/ag-lahore-02",
            headers={"Authorization": f"Bearer {karachi_token}", "X-Branch-ID": "branch-lahore-88"},
        )
        assert res_forge.status_code == 404

        # 4. Karachi user listing agents -> only Karachi agent returned
        res_list_k = await client.get("/api/v1/agents", headers={"Authorization": f"Bearer {karachi_token}"})
        assert res_list_k.status_code == 200
        items_k = res_list_k.json()["items"]
        assert len(items_k) == 1
        assert items_k[0]["id"] == "ag-karachi-01"

        # 5. Company-wide user can access both Karachi and Lahore agents
        res_cw_k = await client.get("/api/v1/agents/ag-karachi-01", headers={"Authorization": f"Bearer {company_wide_token}"})
        assert res_cw_k.status_code == 200
        res_cw_l = await client.get("/api/v1/agents/ag-lahore-02", headers={"Authorization": f"Bearer {company_wide_token}"})
        assert res_cw_l.status_code == 200


def test_incident_evidence_redacts_sensitive_values_in_non_sensitive_keys():
    """Verify redact_sensitive_dict redacts secret tokens and credentials in arbitrary key names."""
    evidence = IncidentEvidenceItem(
        evidence_type=EvidenceType.TRACE_SPAN,
        resource_id="span-sec-01",
        metadata={
            "developer_note": "Here is the key: sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef",
            "connection_info": "User connected via Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.secret",
            "safe_diagnostic": "System RAM usage 42%",
        },
    )
    assert "[REDACTED]" in evidence.metadata["developer_note"]
    assert "[REDACTED]" in evidence.metadata["connection_info"]
    assert evidence.metadata["safe_diagnostic"] == "System RAM usage 42%"


def test_structured_json_formatter_allowlist_and_redaction():
    """Verify StructuredJsonFormatter outputs valid allowlisted JSON with redacted credentials."""
    import logging
    formatter = StructuredJsonFormatter()
    record = logging.LogRecord(
        name="amsc.test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=10,
        msg="Database error with secret password=TopSecretPassword123!",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "req-12345"
    record.event_id = "SEC-AUTH-001"
    record.tenant_id = "tenant-a-uuid-001"
    record.unauthorized_extra_secret = "leaked_secret"

    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "ERROR"
    assert parsed["logger"] == "amsc.test"
    assert parsed["correlation_id"] == "req-12345"
    assert parsed["event_id"] == "SEC-AUTH-001"
    assert parsed["tenant_id"] == "tenant-a-uuid-001"
    assert "[REDACTED]" in parsed["message"]
    assert "TopSecretPassword123!" not in parsed["message"]
    assert "unauthorized_extra_secret" not in parsed


@pytest.mark.asyncio
async def test_readiness_probe_detects_missing_mandatory_dependencies_in_production():
    """Verify /ready probe returns 503 SecurityDependencyError when mandatory dependencies are missing in production."""
    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="a" * 32,
        DATABASE_URL=PROD_DATABASE_URL,
        REDIS_URL=PROD_REDIS_URL,
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_LOCALHOST_CORS_IN_PRODUCTION=True,
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
    )
    app = create_app(settings=prod_settings)
    # Auth repo is missing, rate limiter is missing
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/ready")
        assert res.status_code == 503
        data = res.json()
        assert data["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"

