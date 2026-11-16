"""Unit Test Suite for M1 Day 1 Platform Baseline.

Module: backend.tests.unit.test_day1_baseline
Owner: M1 — Platform Backend & API Integration Lead

Verifies:
1. Python module imports and FastAPI initialization
2. GET /health and GET /api/v1/health endpoints (HTTP 200, contract response)
3. CORS headers behavior on approved origins
4. CORS headers behavior on unapproved origins
5. CORS headers exposure (X-Request-ID, X-Trace-ID)
6. Global exception handling:
   - Standard error envelope matching AMSC-DOC-005 Section 7
   - Starlette HTTPException mapping
   - RequestValidationError mapped to HTTP 400 Bad Request per AMSC-DOC-005
   - Domain errors (AuthenticationError, TenantAccessForbiddenError, SecurityDependencyError)
   - Unhandled 500 exceptions (no tracebacks or secrets leaked to client, X-Request-ID in headers)
   - Incoming X-Request-ID and X-Trace-ID propagation
7. OpenAPI contract generation at /openapi.json
8. Central configuration parsing, defaults, environment validation, and production security guardrails
9. Sensitive log redaction including database URIs and exception tracebacks
"""

import logging
import pytest
from fastapi import FastAPI, Body
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, ValidationError as PydanticValidationError

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import (
    AMSCException,
    AuthenticationError,
    ForbiddenError,
    NotFoundError,
    PolicyDeniedError,
    SecurityDependencyError,
    TenantAccessForbiddenError,
    ValidationError as AMSCValidationError,
    register_exception_handlers,
)
from backend.app.core.logging import SensitiveDataFilter, RedactingFormatter, setup_logging
from backend.app.main import create_app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a Starlette TestClient with default test settings."""
    test_settings = Settings(
        APP_ENV="test",
        CORS_ORIGINS=["http://localhost:5173", "http://localhost:3000"],
    )
    app = create_app(settings=test_settings)
    return TestClient(app, raise_server_exceptions=False)


# ============================================================================
# 1. Health Endpoint Tests
# ============================================================================

def test_health_endpoint_root(client: TestClient):
    """Verify GET /health returns HTTP 200 and matches AMSC contract."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "status": "healthy",
        "service": "amsc-api",
    }
    # Verify tracing headers are populated
    assert "X-Request-ID" in response.headers


def test_health_endpoint_versioned(client: TestClient):
    """Verify GET /api/v1/health returns HTTP 200 and matches AMSC contract."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "status": "healthy",
        "service": "amsc-api",
    }


def test_request_id_propagation(client: TestClient):
    """Verify incoming X-Request-ID is preserved and echoed back."""
    custom_req_id = "req-custom-uuid-12345"
    response = client.get("/health", headers={"X-Request-ID": custom_req_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_req_id


def test_trace_id_and_request_id_both_propagated(client: TestClient):
    """Verify both X-Request-ID and X-Trace-ID are preserved and returned in headers."""
    custom_req_id = "req-id-777"
    custom_trace_id = "trace-w3c-999"
    response = client.get(
        "/health",
        headers={"X-Request-ID": custom_req_id, "X-Trace-ID": custom_trace_id},
    )
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_req_id
    assert response.headers.get("X-Trace-ID") == custom_trace_id


# ============================================================================
# 2. CORS Behavior Tests
# ============================================================================

def test_cors_approved_origin(client: TestClient):
    """Verify approved origin receives Access-Control-Allow-Origin header."""
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_unapproved_origin(client: TestClient):
    """Verify unapproved origin does NOT receive Access-Control-Allow-Origin header."""
    headers = {
        "Origin": "http://malicious-site.com",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/health", headers=headers)
    # Browsers reject CORS preflight when allow-origin is missing or origin does not match
    assert response.headers.get("access-control-allow-origin") is None


def test_cors_expose_headers(client: TestClient):
    """Verify X-Request-ID and X-Trace-ID are exposed to browser clients."""
    headers = {
        "Origin": "http://localhost:5173",
    }
    response = client.get("/health", headers=headers)
    assert response.status_code == 200
    expose_header = response.headers.get("access-control-expose-headers", "")
    assert "X-Request-ID" in expose_header
    assert "X-Trace-ID" in expose_header


# ============================================================================
# 3. OpenAPI Contract Generation Tests
# ============================================================================

def test_openapi_json_generation(client: TestClient):
    """Verify OpenAPI 3.1.0 schema is generated and conforms to specifications."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    assert "openapi" in schema
    assert schema["info"]["title"] == "Agent Memory Security Center"
    assert schema["info"]["version"] == "1.0.0"

    paths = schema["paths"]
    # Check that canonical health endpoints are documented
    assert "/health" in paths
    assert "/api/v1/health" in paths
    assert "get" in paths["/health"]
    assert "get" in paths["/api/v1/health"]


# ============================================================================
# 4. Standardized Exception Handling Tests
# ============================================================================

def test_custom_amsc_exception_envelope():
    """Verify AMSCException returns canonical error envelope matching AMSC-DOC-005."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/trigger-policy-denied")
    def trigger_denied():
        raise PolicyDeniedError(
            message="The action violates security parameter ceilings.",
            reasons=["Amount $450 exceeds ceiling $300."],
        )

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-policy-denied")
    assert response.status_code == 403
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "POLICY_EVALUATION_DENIED"
    assert err["message"] == "The action violates security parameter ceilings."
    assert "request_id" in err
    assert err["details"] == {"reasons": ["Amount $450 exceeds ceiling $300."]}
    assert "X-Request-ID" in response.headers


def test_domain_security_exceptions_status_codes():
    """Verify specific domain security exceptions map to canonical HTTP status codes."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/auth-err")
    def auth_err():
        raise AuthenticationError("Missing Bearer token.")

    @app.get("/tenant-err")
    def tenant_err():
        raise TenantAccessForbiddenError("Cross-tenant access attempted.")

    @app.get("/dep-err")
    def dep_err():
        raise SecurityDependencyError("Redis lock service partitioned.")

    test_client = TestClient(app, raise_server_exceptions=False)

    r_auth = test_client.get("/auth-err")
    assert r_auth.status_code == 401
    assert r_auth.json()["error"]["code"] == "AUTHENTICATION_FAILED"
    assert "X-Request-ID" in r_auth.headers

    r_tenant = test_client.get("/tenant-err")
    assert r_tenant.status_code == 403
    assert r_tenant.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"
    assert "X-Request-ID" in r_tenant.headers

    r_dep = test_client.get("/dep-err")
    assert r_dep.status_code == 503
    assert r_dep.json()["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"
    assert "X-Request-ID" in r_dep.headers


def test_http_404_not_found_envelope(client: TestClient):
    """Verify 404 returns standard error envelope instead of default Starlette HTML/plain text."""
    response = client.get("/non-existent-endpoint")
    assert response.status_code == 404
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert "Not Found" in payload["error"]["message"]
    assert "request_id" in payload["error"]
    assert "X-Request-ID" in response.headers


def test_request_validation_error_envelope():
    """Verify Pydantic request validation error returns 400 with canonical error envelope (AMSC-DOC-005)."""
    app = FastAPI()
    register_exception_handlers(app)

    class SampleInput(BaseModel):
        amount: float = Field(gt=0)
        currency: str = Field(min_length=3, max_length=3)

    @app.post("/test-validation")
    def test_val(body: SampleInput):
        return {"status": "ok"}

    test_client = TestClient(app, raise_server_exceptions=False)
    # Send invalid body (negative amount and invalid currency length)
    response = test_client.post("/test-validation", json={"amount": -50, "currency": "US"})
    assert response.status_code == 400
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "VALIDATION_ERROR"
    assert "validation_errors" in err["details"]
    assert len(err["details"]["validation_errors"]) >= 1
    assert "X-Request-ID" in response.headers


def test_unhandled_exception_safe_envelope():
    """Verify 500 error does NOT expose traceback, secret, or internal paths, and preserves headers."""
    app = create_app()

    @app.get("/trigger-panic")
    def trigger_panic():
        # Simulate unexpected crash with sensitive internal variable
        internal_secret = "SUPER_SECRET_DB_PASSWORD_12345"
        raise RuntimeError(f"Unexpected internal failure with secret: {internal_secret}")

    test_client = TestClient(app, raise_server_exceptions=False)
    response = test_client.get("/trigger-panic", headers={"X-Trace-ID": "trace-panic-123"})
    assert response.status_code == 500
    payload = response.json()
    assert "error" in payload
    err = payload["error"]
    assert err["code"] == "INTERNAL_SERVER_ERROR"
    # Ensure sensitive details are not leaked in response
    assert "SUPER_SECRET_DB_PASSWORD" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text
    assert err["message"] == "An unexpected server error occurred. The incident has been recorded."
    # Verify correlation headers in response
    assert "X-Request-ID" in response.headers
    assert response.headers.get("X-Trace-ID") == "trace-panic-123"


# ============================================================================
# 5. Configuration & Security Validation Tests
# ============================================================================

def test_settings_cors_origins_parsing():
    """Verify CORS_ORIGINS parses strings, lists, and JSON strings, normalizing trailing slashes."""
    # Comma-separated string with trailing slash
    s1 = Settings(CORS_ORIGINS="http://localhost:5173/,http://localhost:3000/")
    assert s1.CORS_ORIGINS == ["http://localhost:5173", "http://localhost:3000"]

    # JSON array string
    s2 = Settings(CORS_ORIGINS='["http://example.com/", "http://app.internal"]')
    assert s2.CORS_ORIGINS == ["http://example.com", "http://app.internal"]

    # List of strings
    s3 = Settings(CORS_ORIGINS=["http://test.com/"])
    assert s3.CORS_ORIGINS == ["http://test.com"]


def test_settings_wildcard_cors_with_credentials_prohibited():
    """Verify wildcard CORS combined with credentials is rejected in all environments."""
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="development",
            CORS_ORIGINS=["*"],
            CORS_ALLOW_CREDENTIALS=True,
        )
    assert "cannot be combined with credentialed requests" in str(exc.value)


def test_settings_app_env_validation():
    """Verify APP_ENV validates allowed environments and rejects unknown values."""
    s = Settings(APP_ENV="DEVELOPMENT ")
    assert s.APP_ENV == "development"

    with pytest.raises(PydanticValidationError) as exc:
        Settings(APP_ENV="invalid_env")
    assert "APP_ENV must be one of" in str(exc.value)


def test_production_security_validation_catches_insecure_defaults():
    """Verify production mode rejects default JWT secret, short secret, debug mode, and wildcard origins."""
    # Rejects insecure default JWT secret in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET="insecure-dev-secret-key-change-in-production-min-32-chars",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "JWT_SECRET cannot be used in production" in str(exc.value)

    # Rejects short JWT secret in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET="a-short-production-key-99",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "JWT_SECRET must be at least 32 characters in production" in str(exc.value)

    # Rejects wildcard CORS in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            JWT_SECRET="a-very-strong-production-signing-secret-with-64-bytes-entropy",
            CORS_ORIGINS=["*"],
            CORS_ALLOW_CREDENTIALS=False,
        )
    assert "Wildcard ('*') CORS origins are prohibited in production" in str(exc.value)

    # Rejects DEBUG=True in production
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=True,
            JWT_SECRET="a-very-strong-production-signing-secret-with-64-bytes-entropy",
            CORS_ORIGINS=["https://app.example.com"],
        )
    assert "DEBUG mode must be False in production" in str(exc.value)


# ============================================================================
# 6. Sensitive Data Redaction Tests
# ============================================================================

def test_log_sensitive_redaction():
    """Verify SensitiveDataFilter redacts Bearer tokens, passwords, and database connection URIs."""
    raw_message = (
        "User login attempt with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret "
        "and password='my_super_secret_password' "
        "connecting to postgresql://amsc_admin:super_secret_db_pass@127.0.0.1:5432/amsc"
    )
    redacted = SensitiveDataFilter.redact(raw_message)
    assert "eyJhbGciOiJIUzI1Ni" not in redacted
    assert "my_super_secret_password" not in redacted
    assert "super_secret_db_pass" not in redacted
    assert "[REDACTED]" in redacted
    assert "postgresql://amsc_admin:[REDACTED]@127.0.0.1:5432/amsc" in redacted


def test_log_numeric_formatting_preserves_int_args():
    """Verify SensitiveDataFilter preserves int/float arguments without breaking %d string formatting."""
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="HTTP status: %s %d %s",
        args=("GET", 200, "OK"),
        exc_info=None,
    )
    data_filter = SensitiveDataFilter()
    assert data_filter.filter(record) is True
    formatted = record.getMessage()
    assert formatted == "HTTP status: GET 200 OK"


def test_redacting_formatter_scrubs_exception_traceback():
    """Verify RedactingFormatter scrubs database credentials and tokens from exception tracebacks."""
    formatter = RedactingFormatter(fmt="%(message)s")
    try:
        raise RuntimeError("DB connect failure: postgresql://admin:leaked_secret@db:5432/prod")
    except RuntimeError:
        import sys
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Exception caught",
            args=(),
            exc_info=sys.exc_info(),
        )
        formatted = formatter.format(record)
        assert "leaked_secret" not in formatted
        assert "postgresql://admin:[REDACTED]@db:5432/prod" in formatted
