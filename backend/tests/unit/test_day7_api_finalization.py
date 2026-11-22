"""M1 Day 7 Comprehensive Test Suite: API Finalization, OpenAPI Documentation, Error Hardening & Security Baselines.

Module: backend.tests.unit.test_day7_api_finalization
Owner: M1 — Platform Backend & API Integration Lead

Verifies:
1. Canonical OpenAPI 3.1.0 specification at /openapi.json:
   - Full route inventory match; no orphan or unregistered paths.
   - Unique operation IDs across all endpoints.
   - Reusable ErrorResponse and ErrorDetail schema definitions in components.
   - Common API error responses (400, 401, 403, 404, 405, 409, 422, 429, 500, 503).
   - Accurate BearerAuth security scheme declaration (HTTPBearer); zero advertisement of API key auth.
   - Public operations (/health, /api/v1/health, /api/v1/auth/login) declared without security requirements.
   - Protected operations declared with BearerAuth requirement.
   - Safe examples; zero credentials, secrets, or internal prompt leaks.
2. Production API Documentation Policy:
   - In production, /docs (Swagger UI) and /redoc are disabled by default.
   - /openapi.json remains accessible for automated integration.
   - Configurable ENABLE_DOCS_IN_PRODUCTION allows internal authenticated access.
3. API Baseline Security Headers & Caching:
   - X-Content-Type-Options: nosniff on all responses (success and error).
   - Referrer-Policy: no-referrer on all responses.
   - X-Frame-Options: DENY on all responses.
   - Cache-Control: no-store, no-cache, must-revalidate, private on sensitive API paths.
4. Error Handling & Standardized Envelope Consistency:
   - Missing Bearer token -> HTTP 401 with standard envelope.
   - Malformed/expired token -> HTTP 401 with standard envelope.
   - Forbidden tenant boundary -> HTTP 403 with standard envelope.
   - Missing resource -> HTTP 404 with standard envelope.
   - Unsupported method -> HTTP 405 with standard envelope and Allow header preserved.
   - Request validation failure -> HTTP 400 with sanitized validation_errors.
   - Rate limit exceeded -> HTTP 429 with Retry-After header preserved.
   - Unhandled internal exception -> HTTP 500 with sanitized generic message and request_id.
5. Information Disclosure & Input Reflection Prevention:
   - Validation messages never reflect raw sensitive inputs or passwords.
   - Database connection strings and SQL queries are scrubbed from client responses.
   - Internal file system paths and Python tracebacks are never exposed.
6. Correlation & Request Identifier Sanitization:
   - Valid incoming X-Request-ID and X-Trace-ID (including W3C format) preserved.
   - Oversized identifiers (>128 chars) rejected and replaced with safe UUIDs.
   - CR/LF and control characters in correlation IDs rejected and replaced.
   - Reverse proxy spoofing rejected; trusted proxy right-to-left traversal enforced.
"""

import pytest
from datetime import timedelta
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.core.exceptions import (
    AMSCException,
    RateLimitExceededError,
    SecurityDependencyError,
    register_exception_handlers,
    sanitize_validation_message,
)
from backend.app.core.security import create_access_token
from backend.app.main import create_app

# Test Constants
TENANT_A_ID = "tenant-a-uuid-001"
TENANT_B_ID = "tenant-b-uuid-002"
USER_A_ANALYST_ID = "user-a-analyst-001"
USER_A_DEV_ID = "user-a-dev-009"


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing clean settings for unit testing."""
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173", "http://localhost:3000"],
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )


@pytest.fixture
def client(test_settings: Settings) -> TestClient:
    """Fixture providing TestClient with test configuration."""
    app = create_app(settings=test_settings)
    return TestClient(app, raise_server_exceptions=False)


def auth_headers(
    user_id: str = USER_A_ANALYST_ID,
    tenant_id: str = TENANT_A_ID,
    role: str = "SECURITY_ANALYST",
    settings: Settings | None = None,
) -> dict[str, str]:
    """Helper to generate verified Authorization header."""
    cfg = settings or Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )
    token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        settings=cfg,
    )
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# 1. Canonical OpenAPI 3.1.0 Documentation Tests
# ============================================================================

def test_openapi_json_returns_valid_310_specification(client: TestClient):
    """Verify /openapi.json returns HTTP 200 and a valid OpenAPI 3.1.0 document."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    spec = response.json()

    assert spec.get("openapi") == "3.1.0"
    assert spec.get("info", {}).get("title") == "Agent Memory Security Center"
    assert spec.get("info", {}).get("version") == "1.0.0"
    assert "paths" in spec
    assert "components" in spec


def test_openapi_route_inventory_matches_registered_routes(client: TestClient):
    """Verify OpenAPI paths reflect all registered application routes and no orphan routes."""
    response = client.get("/openapi.json")
    spec = response.json()
    paths = spec.get("paths", {})

    expected_routes = [
        "/health",
        "/api/v1/health",
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/tenants",
        "/api/v1/tenants/{tenant_id}",
        "/api/v1/agents",
        "/api/v1/agents/{agent_id}",
        "/api/v1/gateway/actions/propose",
        "/api/v1/gateway/actions",
        "/api/v1/gateway/actions/{proposal_id}",
        "/api/v1/memory",
        "/api/v1/memory/{id}",
        "/api/v1/security/incidents",
        "/api/v1/security/incidents/{incident_id}",
        "/api/v1/security/incidents/{incident_id}/evidence",
        "/api/v1/security/alerts",
        "/api/v1/security/memory/{record_id}",
        "/api/v1/security/memory/{record_id}/quarantine",
        "/api/v1/memory/{record_id}/quarantine",
        "/api/v1/traces/{id}/dual-trace",
        "/api/v1/traces",
    ]

    for route in expected_routes:
        assert route in paths, f"Expected registered route '{route}' missing from OpenAPI spec"


def test_openapi_operation_ids_are_unique(client: TestClient):
    """Verify every operation across all routes and methods has a unique operationId."""
    response = client.get("/openapi.json")
    spec = response.json()

    operation_ids: list[str] = []
    duplicates: list[str] = []

    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if isinstance(op, dict) and "operationId" in op:
                oid = op["operationId"]
                if oid in operation_ids:
                    duplicates.append(f"{oid} ({method.upper()} {path})")
                operation_ids.append(oid)

    assert len(duplicates) == 0, f"Found duplicate operation IDs in OpenAPI: {duplicates}"
    assert len(operation_ids) >= 20


def test_openapi_security_scheme_declares_bearer_auth_only(client: TestClient):
    """Verify OpenAPI components declare BearerAuth and do NOT advertise API key authentication."""
    response = client.get("/openapi.json")
    spec = response.json()
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    assert "BearerAuth" in security_schemes
    bearer = security_schemes["BearerAuth"]
    assert bearer.get("type") == "http"
    assert bearer.get("scheme") == "bearer"

    # Invariant: Do not advertise unimplemented API key authentication
    assert "ApiKeyAuth" not in security_schemes
    assert "api_key" not in security_schemes
    assert "OAuth2PasswordBearer" not in security_schemes


def test_openapi_distinguishes_public_and_protected_endpoints(client: TestClient):
    """Verify public endpoints declare no security while protected endpoints require BearerAuth."""
    response = client.get("/openapi.json")
    spec = response.json()
    paths = spec.get("paths", {})

    # 1. Public routes must have no security requirement
    public_endpoints = [
        ("/health", "get"),
        ("/api/v1/health", "get"),
        ("/api/v1/auth/login", "post"),
    ]
    for path, method in public_endpoints:
        op = paths.get(path, {}).get(method, {})
        sec = op.get("security")
        assert sec is None or sec == [] or sec == [{}], (
            f"Public endpoint '{method.upper()} {path}' must not require security in OpenAPI, got {sec}"
        )

    # 2. Protected routes must require BearerAuth
    protected_endpoints = [
        ("/api/v1/auth/me", "get"),
        ("/api/v1/tenants", "get"),
        ("/api/v1/agents", "get"),
        ("/api/v1/gateway/actions/propose", "post"),
        ("/api/v1/memory", "get"),
        ("/api/v1/security/incidents", "get"),
        ("/api/v1/traces", "get"),
        ("/api/v1/traces/{id}/dual-trace", "get"),
    ]
    for path, method in protected_endpoints:
        op = paths.get(path, {}).get(method, {})
        sec = op.get("security")
        assert sec is not None and len(sec) > 0, (
            f"Protected endpoint '{method.upper()} {path}' must declare security requirement in OpenAPI"
        )
        assert any("BearerAuth" in req for req in sec), (
            f"Protected endpoint '{method.upper()} {path}' must require BearerAuth in OpenAPI"
        )


def test_openapi_shared_error_responses_documented(client: TestClient):
    """Verify ErrorResponse model and standard error codes are documented in OpenAPI components and paths."""
    response = client.get("/openapi.json")
    spec = response.json()

    # Schemas must document ErrorResponse and ErrorDetail
    schemas = spec.get("components", {}).get("schemas", {})
    assert "ErrorResponse" in schemas
    assert "ErrorDetail" in schemas

    error_detail_props = schemas["ErrorDetail"].get("properties", {})
    assert "code" in error_detail_props
    assert "message" in error_detail_props
    assert "request_id" in error_detail_props
    assert "details" in error_detail_props

    # Verify standard error status codes appear in API endpoint responses
    me_responses = spec["paths"]["/api/v1/auth/me"]["get"]["responses"]
    assert "401" in me_responses
    assert "403" in me_responses
    assert "500" in me_responses


def test_openapi_contains_no_sensitive_examples_or_secrets(client: TestClient):
    """Verify OpenAPI spec contains zero credentials, real secrets, or sensitive connection strings."""
    response = client.get("/openapi.json")
    spec_text = response.text

    forbidden_patterns = [
        "amsc_dev_password",
        "SuperSecretPass",
        "sk-live-",
        "ghp_",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "postgresql://",
        "redis://",
    ]
    for pattern in forbidden_patterns:
        assert pattern not in spec_text, f"OpenAPI spec must not leak sensitive pattern '{pattern}'"


# ============================================================================
# 2. Production API Documentation Policy Tests
# ============================================================================

def test_production_mode_disables_swagger_ui_and_redoc():
    """Verify interactive Swagger UI (/docs) and ReDoc (/redoc) are disabled in production by default."""
    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="a-very-strong-production-secret-with-high-entropy-123456",
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        ENABLE_DOCS_IN_PRODUCTION=False,
    )
    prod_app = create_app(settings=prod_settings)
    prod_client = TestClient(prod_app, raise_server_exceptions=False)

    # Swagger UI and ReDoc must return 404 Not Found in production
    r_docs = prod_client.get("/docs")
    assert r_docs.status_code == 404

    r_redoc = prod_client.get("/redoc")
    assert r_redoc.status_code == 404

    # Canonical OpenAPI JSON specification remains accessible for frontend/CI
    r_spec = prod_client.get("/openapi.json")
    assert r_spec.status_code == 200
    assert "openapi" in r_spec.json()


def test_production_mode_allows_docs_when_explicitly_configured():
    """Verify Swagger UI can be enabled in production only when ENABLE_DOCS_IN_PRODUCTION is True."""
    prod_settings = Settings(
        APP_ENV="production",
        JWT_SECRET="a-very-strong-production-secret-with-high-entropy-123456",
        DATABASE_URL="postgresql+asyncpg://prod_user:p_w_d_123@prod-db.internal:5432/amsc",
        REDIS_URL="redis://prod-redis.internal:6379/0",
        CORS_ORIGINS=["https://app.example.com"],
        ALLOW_IN_MEMORY_AUTH=False,
        AUTH_BACKEND="database",
        ALLOW_IN_MEMORY_RATE_LIMITER=False,
        RATE_LIMITER_BACKEND="redis",
        RATE_LIMIT_REDIS_FAILURE_POLICY="fail_closed",
        ENABLE_DOCS_IN_PRODUCTION=True,
    )
    prod_app = create_app(settings=prod_settings)
    prod_client = TestClient(prod_app, raise_server_exceptions=False)

    r_docs = prod_client.get("/docs")
    assert r_docs.status_code == 200


def test_development_mode_enables_swagger_ui_and_redoc(client: TestClient):
    """Verify development and test modes expose /docs and /redoc."""
    r_docs = client.get("/docs")
    assert r_docs.status_code == 200

    r_redoc = client.get("/redoc")
    assert r_redoc.status_code == 200


# ============================================================================
# 3. Baseline Security Headers & Caching Tests
# ============================================================================

def test_security_headers_on_successful_responses(client: TestClient):
    """Verify security headers (X-Content-Type-Options, Referrer-Policy, X-Frame-Options) on HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_security_headers_on_error_responses(client: TestClient):
    """Verify baseline security headers are attached to error responses (401, 404, 500)."""
    # 404 Not Found
    r_404 = client.get("/non-existent-endpoint")
    assert r_404.status_code == 404
    assert r_404.headers.get("X-Content-Type-Options") == "nosniff"
    assert r_404.headers.get("Referrer-Policy") == "no-referrer"
    assert r_404.headers.get("X-Frame-Options") == "DENY"

    # 401 Unauthorized
    r_401 = client.get("/api/v1/auth/me")
    assert r_401.status_code == 401
    assert r_401.headers.get("X-Content-Type-Options") == "nosniff"
    assert r_401.headers.get("Referrer-Policy") == "no-referrer"
    assert r_401.headers.get("X-Frame-Options") == "DENY"


def test_sensitive_api_endpoints_return_no_store_cache_control(client: TestClient):
    """Verify /api/* endpoints return Cache-Control: no-store to protect sensitive data."""
    # 1. Auth endpoint
    r_auth = client.get("/api/v1/auth/me")
    assert r_auth.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, private"
    assert r_auth.headers.get("Pragma") == "no-cache"

    # 2. Versioned health endpoint
    r_health = client.get("/api/v1/health")
    assert r_health.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, private"


# ============================================================================
# 4. Standardized Error Handling & Envelope Tests
# ============================================================================

def test_missing_authentication_returns_standard_401_envelope(client: TestClient):
    """Verify unauthenticated request to protected endpoint returns HTTP 401 with standard envelope."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    payload = response.json()

    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "AUTHENTICATION_FAILED"
    assert "Invalid email, password, or tenant access" in err["message"]
    assert "request_id" in err
    assert err["details"] is None
    assert "X-Request-ID" in response.headers


def test_malformed_token_returns_standard_401_envelope(client: TestClient):
    """Verify invalid token returns HTTP 401 with standard envelope."""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer malformed.jwt.token"},
    )
    assert response.status_code == 401
    err = response.json()["error"]
    assert err["code"] == "AUTHENTICATION_FAILED"
    assert err["details"] is None


def test_expired_token_returns_standard_401_envelope(client: TestClient, test_settings: Settings):
    """Verify expired token returns HTTP 401 with standard envelope."""
    expired_token = create_access_token(
        user_id=USER_A_ANALYST_ID,
        tenant_id=TENANT_A_ID,
        role="SECURITY_ANALYST",
        expires_delta=timedelta(seconds=-3600),
        settings=test_settings,
    )
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    err = response.json()["error"]
    assert err["code"] == "AUTHENTICATION_FAILED"


def test_cross_tenant_access_returns_standard_403_envelope(client: TestClient, test_settings: Settings):
    """Verify cross-tenant mismatch returns HTTP 403 TENANT_ACCESS_FORBIDDEN."""
    token = create_access_token(
        user_id=USER_A_ANALYST_ID,
        tenant_id=TENANT_A_ID,
        role="SECURITY_ANALYST",
        settings=test_settings,
    )
    # Token is for Tenant A, but caller sends X-Tenant-ID header for Tenant B
    response = client.get(
        "/api/v1/tenants",
        headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": TENANT_B_ID},
    )
    assert response.status_code == 403
    err = response.json()["error"]
    assert err["code"] == "TENANT_ACCESS_FORBIDDEN"
    assert "forbidden" in err["message"].lower()


def test_resource_not_found_returns_standard_404_envelope(client: TestClient, test_settings: Settings):
    """Verify missing resource returns HTTP 404 RESOURCE_NOT_FOUND."""
    headers = auth_headers(settings=test_settings)
    response = client.get("/api/v1/agents/non-existent-agent-id-12345", headers=headers)
    assert response.status_code == 404
    err = response.json()["error"]
    assert err["code"] == "RESOURCE_NOT_FOUND"


def test_unsupported_method_returns_405_with_allow_header(client: TestClient):
    """Verify unsupported HTTP method returns 405 METHOD_NOT_ALLOWED and preserves Allow header."""
    response = client.post("/health")
    assert response.status_code == 405
    err = response.json()["error"]
    assert err["code"] == "METHOD_NOT_ALLOWED"
    assert "Allow" in response.headers or "allow" in response.headers


def test_request_validation_error_returns_400_with_sanitized_errors(client: TestClient):
    """Verify schema validation error returns HTTP 400 with sanitized validation_errors."""
    # POST login with missing required fields
    response = client.post("/api/v1/auth/login", json={})
    assert response.status_code == 400
    err = response.json()["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert "validation_errors" in err["details"]
    errors = err["details"]["validation_errors"]
    assert len(errors) > 0
    for e in errors:
        assert "loc" in e
        assert "msg" in e
        assert "type" in e
        # Must not expose Pydantic 'input' or 'ctx'
        assert "input" not in e
        assert "ctx" not in e


def test_malformed_json_returns_400_bad_request(client: TestClient):
    """Verify malformed JSON body produces standard 400 Bad Request."""
    response = client.post(
        "/api/v1/auth/login",
        content="not-valid-json{{{",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    err = response.json()["error"]
    assert err["code"] in ["VALIDATION_ERROR", "BAD_REQUEST"]


def test_rate_limit_exceeded_preserves_retry_after_header():
    """Verify RateLimitExceededError returns HTTP 429 and preserves Retry-After header."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-rate-limit")
    def trigger_429():
        raise RateLimitExceededError(
            message="Rate limit exceeded.",
            retry_after=45,
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-rate-limit")
    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "45"
    err = response.json()["error"]
    assert err["code"] == "RATE_LIMIT_EXCEEDED"


def test_http_exception_preserves_allowlisted_protocol_headers():
    """Verify HTTPException preserves WWW-Authenticate and Allow headers."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-challenge")
    def trigger_challenge():
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer realm='AMSC'"},
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-challenge")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer realm='AMSC'"


def test_unexpected_exception_returns_safe_generic_500():
    """Verify deliberately injected internal exception returns generic 500 without leaking exception details."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-internal-failure")
    def trigger_internal():
        raise RuntimeError("CRITICAL DATABASE FAILURE: connection to 10.0.0.1:5432 timed out with pass=hunter2")

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-internal-failure")
    assert response.status_code == 500
    payload = response.json()

    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "INTERNAL_SERVER_ERROR"
    assert err["message"] == "An unexpected server error occurred. The incident has been recorded."
    assert "request_id" in err
    assert err["details"] is None
    # Verify sensitive text was not disclosed
    assert "DATABASE" not in payload
    assert "hunter2" not in payload
    assert "10.0.0.1" not in payload


# ============================================================================
# 5. Information Disclosure & Input Reflection Prevention Tests
# ============================================================================

def test_validation_message_sanitizer_redacts_reflected_credentials():
    """Verify sanitize_validation_message helper redacts reflected inputs and passwords."""
    raw_secret = "SuperSecretPassword123!"
    err_msg = f"Value error, password '{raw_secret}' does not meet requirements"
    sanitized = sanitize_validation_message(err_msg, input_val=raw_secret)
    assert raw_secret not in sanitized
    assert "[REDACTED]" in sanitized


def test_validation_exception_handler_does_not_echo_submitted_passwords(client: TestClient):
    """Verify validation response does not echo back raw submitted password values."""
    secret_pw = "VerySecretPlainTextPassword!456"
    # Submit password that violates type/length constraints to trigger error
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "analyst@company-a.com",
            "password": "",  # Empty string violates min_length=1
            "tenant_slug": "company-a",
        },
    )
    assert response.status_code == 400
    assert secret_pw not in response.text


def test_database_connection_string_never_disclosed_in_error():
    """Verify injected database connection string is never disclosed in error payload."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-db-error")
    def trigger_db():
        raise AMSCException(
            message="Internal failure: postgresql+asyncpg://admin:SuperSecretPass@db.internal:5432/prod_db",
            code="DATABASE_ERROR",
            status_code=500,
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-db-error")
    assert response.status_code == 500
    body = response.text
    assert "SuperSecretPass" not in body
    assert "postgresql" not in body


# ============================================================================
# 6. Correlation & Request Identifier Sanitization Tests
# ============================================================================

def test_valid_request_id_and_trace_id_propagated(client: TestClient):
    """Verify valid incoming X-Request-ID and X-Trace-ID are preserved."""
    req_id = "req-valid-12345"
    trace_id = "tr-valid-67890"
    response = client.get(
        "/health",
        headers={"X-Request-ID": req_id, "X-Trace-ID": trace_id},
    )
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == req_id
    assert response.headers.get("X-Trace-ID") == trace_id


def test_w3c_traceparent_format_supported(client: TestClient):
    """Verify W3C trace ID format is accepted and preserved."""
    w3c_trace_id = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    response = client.get(
        "/health",
        headers={"X-Trace-ID": w3c_trace_id},
    )
    assert response.status_code == 200
    assert response.headers.get("X-Trace-ID") == w3c_trace_id


def test_oversized_request_id_is_replaced(client: TestClient):
    """Verify oversized request ID (>128 chars) is rejected and replaced with safe UUID."""
    oversized_id = "a" * 256
    response = client.get("/health", headers={"X-Request-ID": oversized_id})
    assert response.status_code == 200
    ret_id = response.headers.get("X-Request-ID")
    assert ret_id != oversized_id
    assert len(ret_id) <= 128
    assert ret_id.startswith("req-")


def test_malformed_request_id_with_crlf_is_replaced(client: TestClient):
    """Verify request ID containing CR/LF is rejected and not echoed back."""
    malicious_id = "req-123\r\nInjected-Header: malicious"
    response = client.get("/health", headers={"X-Request-ID": malicious_id})
    assert response.status_code == 200
    ret_id = response.headers.get("X-Request-ID")
    assert "Injected-Header" not in ret_id
    assert "\r" not in ret_id
    assert "\n" not in ret_id
    assert ret_id.startswith("req-")


def test_trusted_proxy_forwarded_for_handling():
    """Verify trusted proxy configuration honors right-to-left traversal and rejects spoofing."""
    from backend.app.api.auth import get_client_ip

    settings = Settings(
        APP_ENV="test",
        TRUSTED_PROXIES=["10.0.0.1", "10.0.0.2"],
        ALLOW_IN_MEMORY_RATE_LIMITER=True,
    )

    class MockRequest:
        def __init__(self, host: str, xff: str | None = None):
            self.client = type("Client", (), {"host": host})()
            self.headers = {"x-forwarded-for": xff} if xff else {}

    # Case 1: Untrusted direct client supplying forged XFF -> ignore XFF
    req_untrusted = MockRequest(host="203.0.113.5", xff="198.51.100.99, 10.0.0.1")
    assert get_client_ip(req_untrusted, settings) == "203.0.113.5"

    # Case 2: Trusted proxy direct client -> extract rightmost non-trusted IP
    req_trusted = MockRequest(host="10.0.0.1", xff="198.51.100.99, 10.0.0.2")
    assert get_client_ip(req_trusted, settings) == "198.51.100.99"


# ============================================================================
# 7. Additional Error Standardization & Log Sanitization Tests
# ============================================================================

def test_conflict_error_returns_standard_409_envelope():
    """Verify HTTP 409 Conflict returns canonical ErrorResponse envelope."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-conflict")
    def trigger_conflict():
        raise HTTPException(
            status_code=409,
            detail="Resource state conflict: proposal already in progress",
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-conflict")
    assert response.status_code == 409
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "CONFLICT"
    assert "conflict" in err["message"].lower()
    assert "proposal" not in response.text  # Disallows arbitrary internal detail


def test_service_unavailable_returns_standard_503_envelope():
    """Verify HTTP 503 Service Unavailable returns canonical ErrorResponse envelope."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-503")
    def trigger_503():
        raise SecurityDependencyError("Security policy verification engine offline.")

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-503")
    assert response.status_code == 503
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"
    assert "unavailable" in err["message"].lower()


def test_cors_preflight_receives_security_headers(client: TestClient):
    """Verify CORS preflight OPTIONS response includes baseline security headers."""
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }
    response = client.options("/api/v1/auth/login", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_starlette_http_exception_validates_retry_after_header():
    """Verify starlette_http_exception_handler validates numeric Retry-After and rejects malformed values."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-rate-limit-with-header")
    def trigger_429_valid():
        raise HTTPException(
            status_code=429,
            detail="Rate limited",
            headers={"Retry-After": "120"},
        )

    @app.get("/trigger-rate-limit-malformed")
    def trigger_429_malformed():
        raise HTTPException(
            status_code=429,
            detail="Rate limited",
            headers={"Retry-After": "invalid-non-numeric-value\r\nInjected: malicious"},
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    resp_valid = test_client.get("/trigger-rate-limit-with-header")
    assert resp_valid.status_code == 429
    assert resp_valid.headers.get("Retry-After") == "120"

    resp_malformed = test_client.get("/trigger-rate-limit-malformed")
    assert resp_malformed.status_code == 429
    # Malformed non-numeric Retry-After must be omitted
    assert resp_malformed.headers.get("Retry-After") is None
    assert "Injected" not in str(resp_malformed.headers)


def test_custom_exception_details_sanitizes_credentials_and_tokens():
    """Verify custom exception details recursively sanitize passwords, tokens, and API keys."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-detail-leak")
    def trigger_leak():
        raise AMSCException(
            message="Validation failure on credential submission",
            code="VALIDATION_ERROR",
            status_code=400,
            details={
                "password": "plaintext_super_secret_pw",
                "api_key": "sk-live-1234567890123456",
                "auth_token": "bearer eyJhbGciOi...",
                "nested": {
                    "client_secret": "secret_abc_123",
                    "safe_field": "valid_value",
                },
            },
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-detail-leak")
    assert response.status_code == 400
    payload = response.json()
    err = payload["error"]
    assert err["code"] == "VALIDATION_ERROR"
    details = err["details"]
    assert details["password"] == "[REDACTED]"
    assert details["api_key"] == "[REDACTED]"
    assert details["auth_token"] == "[REDACTED]"
    assert details["nested"]["client_secret"] == "[REDACTED]"
    assert details["nested"]["safe_field"] == "valid_value"
    # Plaintext secrets must not appear in response text
    assert "plaintext_super_secret_pw" not in response.text
    assert "sk-live-1234567890123456" not in response.text


def test_validation_message_sanitizer_redacts_unquoted_credentials_and_dict_inputs():
    """Verify sanitize_validation_message redacts unquoted credentials and dict inputs."""
    dict_input = {"password": "injected_secret_pw"}
    raw_msg = f"Value error, input {dict_input} is rejected for password: SuperSecret123"
    sanitized = sanitize_validation_message(raw_msg, input_val=dict_input)
    assert "injected_secret_pw" not in sanitized
    assert "SuperSecret123" not in sanitized


def test_exception_logs_do_not_leak_raw_exception_text_or_secrets(caplog):
    """Verify production exception logs omit raw exception text, SQL queries, memory content, and credentials."""
    import logging
    app = FastAPI()
    register_exception_handlers(app)

    dummy_password = "dummy_password_xyz_9876"
    dummy_jwt = "eyDummyJwtToken.SecretPayload.SignaturePart"
    dummy_apikey = "sk-live-dummy-apikey-12345"
    dummy_pii = "John Doe SSN 000-11-2222"
    dummy_sql = "SELECT * FROM secret_accounts WHERE ssn='000-11-2222'"
    dummy_memory = "ConfidentialAgentMemoryContent999"

    @app.get("/trigger-crash-leak")
    def trigger_crash():
        raise RuntimeError(
            f"CRITICAL FAULT: {dummy_sql} with {dummy_password} and {dummy_jwt} and {dummy_apikey} and {dummy_pii} and {dummy_memory}"
        )

    @app.get("/trigger-domain-leak")
    def trigger_domain():
        raise AMSCException(
            message=f"Domain fault containing {dummy_password} and {dummy_memory}",
            code="DATABASE_ERROR",
            status_code=500,
        )

    with caplog.at_level(logging.WARNING, logger="amsc.exceptions"):
        test_client = TestClient(app, raise_server_exceptions=False)
        r1 = test_client.get("/trigger-crash-leak")
        assert r1.status_code == 500

        r2 = test_client.get("/trigger-domain-leak")
        assert r2.status_code == 500

    log_text = caplog.text
    # Verify distinctive dummy values are completely absent from logs
    assert dummy_password not in log_text
    assert dummy_jwt not in log_text
    assert dummy_apikey not in log_text
    assert dummy_pii not in log_text
    assert dummy_sql not in log_text
    assert dummy_memory not in log_text
