"""Comprehensive Security Remediation Tests for AMSC Day 1 & Day 2 Baseline.

Module: backend.tests.unit.test_remediation
Owner: M1 — Platform Backend & API Integration Lead

Verifies all critical audit findings:
1. Critical Finding 1: Strict separation of in-memory demo authentication from production.
2. High Finding 2: Sanitization of all exception responses (domain, HTTP, unhandled).
3. High Finding 3: Configuration and secret hardening (production validation, placeholder rejection).
4. High Finding 4: Login rate limiting protocol, source/account throttling, 429 envelopes, and Redis failure policies.
"""

import pytest
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError as PydanticValidationError

from backend.app.core.config import Settings
from backend.app.core.dependencies import (
    InMemoryRateLimiter,
)
from backend.app.core.exceptions import (
    AMSCException,
    AuthenticationError,
    register_exception_handlers,
)
from backend.app.main import create_app
from backend.app.tenancy.context import (
    InMemoryAuthRepository,
    create_demo_auth_repository,
    get_default_auth_repository,
)


# ============================================================================
# 1. Critical Finding 1: In-Memory Demo Auth Production Restriction Tests
# ============================================================================

def test_production_cannot_start_with_in_memory_auth_setting():
    """Verify production settings reject ALLOW_IN_MEMORY_AUTH=True or in_memory_demo backend."""
    # 1. ALLOW_IN_MEMORY_AUTH must be False in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            ALLOW_IN_MEMORY_AUTH=True,
            AUTH_BACKEND="database",
            JWT_SECRET="a" * 40,
            DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "ALLOW_IN_MEMORY_AUTH must be False in production" in str(exc.value)

    # 2. AUTH_BACKEND must be 'database' in production
    with pytest.raises(PydanticValidationError) as exc2:
        Settings(
            APP_ENV="production",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="in_memory_demo",
            JWT_SECRET="a" * 40,
            DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "AUTH_BACKEND 'in_memory_demo' is prohibited in production" in str(exc2.value)


def test_production_get_default_auth_repo_raises_runtime_error():
    """Verify calling get_default_auth_repository or create_demo_auth_repository in production raises RuntimeError."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        JWT_SECRET="a" * 40,
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
    )
    with pytest.raises(RuntimeError) as exc:
        get_default_auth_repository(prod_settings)
    assert "In-memory demo authentication repository cannot be accessed in production" in str(exc.value)

    with pytest.raises(RuntimeError) as exc2:
        create_demo_auth_repository(prod_settings)
    assert "In-memory demo authentication repository cannot be created in production" in str(exc2.value)


@pytest.mark.asyncio
async def test_production_endpoint_fails_closed_without_database_repo():
    """Verify production application fails closed safely and refuses login if database repo is not provided."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        JWT_SECRET="a" * 40,
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=100,
    )
    app = create_app(settings=prod_settings)
    # Notice: app.state.auth_repo is NOT set (simulating M6's pending DB repo)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Attempt login using known demo credentials
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        # Must fail closed with 503 Service Unavailable, NEVER authenticating via demo accounts
        assert res.status_code == 503
        data = res.json()
        assert data["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"


def test_production_lifespan_wires_database_auth_before_rate_limiter_guard():
    """Verify application lifespan in production raises RuntimeError if real database repo is missing."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        JWT_SECRET="a" * 40,
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
    )
    app = create_app(settings=prod_settings)
    # Lifespan startup check without real repo
    with pytest.raises(RuntimeError) as exc:
        with TestClient(app):
            pass
    assert "Redis-backed rate limiter initialization failed" in str(exc.value)
    assert getattr(app.state.auth_repo, "is_demo", False) is False


def test_development_mode_permits_explicit_demo_configuration():
    """Verify local development with ALLOW_IN_MEMORY_AUTH=True initializes demo repository successfully."""
    dev_settings = Settings(
        APP_ENV="development",
        ALLOW_IN_MEMORY_AUTH=True,
        AUTH_BACKEND="in_memory_demo",
    )
    repo = create_demo_auth_repository(dev_settings)
    assert isinstance(repo, InMemoryAuthRepository)
    assert repo.is_demo is True
    # Demo accounts are seeded
    assert "user-a-analyst-001" in repo.users


# ============================================================================
# 2. High Finding 2: Exception Response Sanitization Tests
# ============================================================================

def test_domain_exception_sanitizes_internal_diagnostics():
    """Verify custom domain exception containing SQL or database table details is sanitized."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-sql-leak")
    def trigger_sql():
        # Exception with internal query syntax and table information
        raise AMSCException(
            message="SELECT * FROM users WHERE password_hash = 'secret' failed on table 'users'",
            code="DATABASE_QUERY_ERROR",
            status_code=500,
        )

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-sql-leak")
    assert response.status_code == 500
    payload = response.json()
    assert "error" in payload
    # Message must be generic safe message, NOT the SQL query
    assert "SELECT" not in payload["error"]["message"]
    assert "password_hash" not in payload["error"]["message"]
    assert payload["error"]["message"] == "An application error occurred. The incident has been recorded."


def test_http_exception_detail_sanitizes_database_connection_string():
    """Verify HTTPException detail with sensitive connection URI is scrubbed from public response."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-http-leak")
    def trigger_http():
        raise HTTPException(
            status_code=500,
            detail="Connection failed: postgresql+asyncpg://admin:SuperSecretPass@db.internal:5432/prod_db",
        )

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-http-leak")
    assert response.status_code == 500
    payload = response.json()
    assert "SuperSecretPass" not in payload["error"]["message"]
    assert "postgresql" not in payload["error"]["message"]
    assert payload["error"]["message"] == "An unexpected server error occurred. The incident has been recorded."


def test_unexpected_exception_never_leaks_traceback_or_secrets():
    """Verify raw Python exception does not disclose file paths, variables, or tracebacks."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-crash")
    def trigger_crash():
        local_api_key = "sk-live-99999999999999999999"
        raise ValueError(f"Crash with private key: {local_api_key} in /var/secrets/keys.json")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-crash")
    assert response.status_code == 500
    payload = response.json()
    assert "sk-live" not in payload["error"]["message"]
    assert "/var/secrets" not in payload["error"]["message"]
    assert payload["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert payload["error"]["details"] is None


# ============================================================================
# 3. High Finding 3: Configuration & Secrets Hardening Tests
# ============================================================================

def test_production_rejects_missing_or_short_jwt_secret():
    """Verify production requires non-empty JWT secret >= 32 characters."""
    with pytest.raises(PydanticValidationError):
        Settings(
            APP_ENV="production",
            JWT_SECRET="",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
        )

    with pytest.raises(PydanticValidationError):
        Settings(
            APP_ENV="production",
            JWT_SECRET="too-short",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
        )


def test_production_rejects_placeholder_and_insecure_jwt_secrets():
    """Verify production rejects example placeholders containing 'replace', 'example', 'default', 'dev'."""
    placeholders = [
        "replace-with-a-secure-random-secret-key-min-32-chars",
        "insecure-dev-secret-key-change-in-production-min-32-chars",
        "default-super-secret-key-with-plenty-of-entropy-123456",
        "my-example-production-key-that-should-not-be-accepted-at-all",
    ]
    for ph in placeholders:
        with pytest.raises(PydanticValidationError) as exc:
            Settings(
                APP_ENV="production",
                JWT_SECRET=ph,
                ALLOW_IN_MEMORY_AUTH=False,
                AUTH_BACKEND="database",
                DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
                REDIS_URL="redis://prod-redis.internal:6379/0",
                CORS_ORIGINS=["https://app.example.com"],
            )
        assert "JWT_SECRET cannot be used in production" in str(exc.value)


def test_production_rejects_development_database_and_redis_defaults():
    """Verify production rejects dev database password 'amsc_dev_password' and localhost URLs."""
    # 1. Dev DB password rejection
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            JWT_SECRET="a" * 40,
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            DATABASE_URL="postgresql+asyncpg://amsc:amsc_dev_password@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "Production DATABASE_URL must use production credentials" in str(exc.value)

    # 2. Localhost DB rejection
    with pytest.raises(PydanticValidationError) as exc2:
        Settings(
            APP_ENV="production",
            JWT_SECRET="a" * 40,
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            DATABASE_URL="postgresql+asyncpg://prod_user:strong_pass@localhost:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "Production DATABASE_URL must use production credentials and a non-localhost host" in str(exc2.value)

    # 3. Localhost Redis rejection
    with pytest.raises(PydanticValidationError) as exc3:
        Settings(
            APP_ENV="production",
            JWT_SECRET="a" * 40,
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            DATABASE_URL="postgresql+asyncpg://prod_user:strong_pass@prod-db.internal:5432/amsc",
            REDIS_URL="redis://localhost:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "Production REDIS_URL must use a non-localhost host" in str(exc3.value)


# ============================================================================
# 4. High Finding 4: Login Rate Limiting Integration Tests
# ============================================================================

@pytest.mark.asyncio
async def test_repeated_login_attempts_from_one_ip_triggers_429():
    """Verify exceeding source IP rate limit returns HTTP 429 and Retry-After header."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=3,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    app = create_app(settings=settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # First 3 attempts permitted (even if credentials fail)
        for _ in range(3):
            res = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "analyst@company-a.com",
                    "password": "WrongPassword!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

        # 4th attempt must be throttled with HTTP 429
        blocked_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "WrongPassword!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        assert blocked_res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert "Retry-After" in blocked_res.headers
        assert int(blocked_res.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_repeated_login_attempts_against_target_account_triggers_429():
    """Verify target account brute force triggers rate limit regardless of IP."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=3,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    app = create_app(settings=settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 3 attempts against target account
        for _ in range(3):
            res = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@company-a.com",
                    "password": "WrongPassword!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

        # 4th attempt against same account triggers 429
        blocked_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@company-a.com",
                "password": "WrongPassword!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        assert blocked_res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_redis_failure_behavior_fails_closed():
    """Verify rate limiter dependency failure triggers fail-closed security response."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
    )
    app = create_app(settings=settings)
    # Simulate Redis connection failure on the rate limiter
    limiter = InMemoryRateLimiter()
    limiter.is_available = False
    app.state.rate_limiter = limiter

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        # Fails closed with 503 Service Unavailable
        assert res.status_code == 503
        assert res.json()["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_no_sensitive_info_in_rate_limit_responses():
    """Verify 429 responses adhere strictly to canonical schema without leaking usernames or system state."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1,
    )
    app = create_app(settings=settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        blocked_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        body = blocked_res.json()
        assert set(body.keys()) == {"error"}
        err = body["error"]
        assert set(err.keys()) == {"code", "message", "request_id", "details"}
        assert err["code"] == "RATE_LIMIT_EXCEEDED"
        assert err["details"] is None


# ============================================================================
# 5. Fix 1: Production Rate Limiter Guardrail Tests
# ============================================================================

def test_production_rejects_in_memory_rate_limiter_setting():
    """Verify production settings strictly reject in-memory rate limiting and fail-open policies."""
    # 1. ALLOW_IN_MEMORY_RATE_LIMITER=True rejected in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            ALLOW_IN_MEMORY_RATE_LIMITER=True,
            RATE_LIMITER_BACKEND="redis",
            RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
            JWT_SECRET="a" * 40,
            DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "ALLOW_IN_MEMORY_RATE_LIMITER must be False in production" in str(exc.value)

    # 2. RATE_LIMITER_BACKEND='in_memory' rejected in production
    with pytest.raises(PydanticValidationError) as exc2:
        Settings(
            APP_ENV="production",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            ALLOW_IN_MEMORY_RATE_LIMITER=False,
            RATE_LIMITER_BACKEND="in_memory",
            RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
            JWT_SECRET="a" * 40,
            DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "RATE_LIMITER_BACKEND 'in_memory' is prohibited in production" in str(exc2.value)

    # 3. RATE_LIMIT_REDIS_FAILURE_POLICY='fail_open' rejected in production
    with pytest.raises(PydanticValidationError) as exc3:
        Settings(
            APP_ENV="production",
            ALLOW_IN_MEMORY_AUTH=False,
            AUTH_BACKEND="database",
            ALLOW_IN_MEMORY_RATE_LIMITER=False,
            RATE_LIMITER_BACKEND="redis",
            RATE_LIMIT_REDIS_FAILURE_POLICY="fail_open",
            JWT_SECRET="a" * 40,
            DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
            REDIS_URL="redis://prod-redis.internal:6379/0",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "Production RATE_LIMIT_REDIS_FAILURE_POLICY must be 'fail_closed'" in str(exc3.value)


def test_production_lifespan_detects_missing_or_in_memory_rate_limiter():
    """Verify application lifespan in production raises RuntimeError if Redis rate limiter is missing."""
    prod_settings = Settings(
        APP_ENV="production",
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        JWT_SECRET="a" * 40,
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
    )
    app = create_app(settings=prod_settings)
    # Simulate valid DB repo present
    class DummyDbRepo:
        is_demo = False
    app.state.auth_repo = DummyDbRepo()
    # But rate_limiter is missing
    app.state.rate_limiter = None

    with pytest.raises(RuntimeError) as exc:
        with TestClient(app):
            pass
    assert "Redis-backed rate limiter initialization failed" in str(exc.value)


# ============================================================================
# 6. Fix 2: Strict Allowlist Exception Sanitization Tests
# ============================================================================

def test_domain_exception_with_injected_secrets_strictly_returns_allowlisted_message():
    """Verify arbitrary injected secrets in domain exception are completely replaced with allowlisted text."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-injected-domain-secret")
    def trigger_injected():
        raise AuthenticationError(
            message="SELECT secret_key FROM credentials WHERE pass='SuperSecret123' at /var/secrets/key.pem",
            details={"private_token": "bearer-secret-xyz-12345"},
        )

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-injected-domain-secret")
    assert response.status_code == 401
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "AUTHENTICATION_FAILED"
    assert err["message"] == "Invalid email, password, or tenant access."
    assert err["details"] is None
    # None of the injected secrets or paths must appear anywhere in the body
    assert "SuperSecret" not in response.text
    assert "SELECT" not in response.text
    assert "bearer-secret" not in response.text
    assert "/var/secrets" not in response.text


def test_http_exception_with_injected_db_details_strictly_returns_allowlisted_message():
    """Verify arbitrary injected details in HTTPException are completely replaced with allowlisted text."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-injected-http-secret")
    def trigger_http_injected():
        raise HTTPException(
            status_code=400,
            detail="Syntax error on table 'accounts' column 'password_hash': connection postgresql://user:pass@db",
        )

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-injected-http-secret")
    assert response.status_code == 400
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "BAD_REQUEST"
    assert err["message"] == "Invalid request parameters."
    assert err["details"] is None
    assert "accounts" not in response.text
    assert "password_hash" not in response.text
    assert "postgresql" not in response.text


def test_unexpected_exception_code_strictly_returns_default_safe_message():
    """Verify any unmapped domain code returns DEFAULT_SAFE_PUBLIC_MESSAGE."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-unknown-code")
    def trigger_unknown():
        raise AMSCException(
            message="Very sensitive internal error in payment processing gateway /internal/v2/cards",
            code="UNMAPPED_PRIVATE_INTERNAL_ERROR",
            status_code=500,
            details={"leaked_variable": "value"},
        )

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/trigger-unknown-code")
    assert response.status_code == 500
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "UNMAPPED_PRIVATE_INTERNAL_ERROR"
    assert err["message"] == "An application error occurred. The incident has been recorded."
    assert err["details"] is None
    assert "payment" not in response.text
    assert "internal/v2/cards" not in response.text

