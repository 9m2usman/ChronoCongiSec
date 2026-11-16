"""Unit and Integration Tests for Authentication Endpoints.

Module: backend.tests.unit.test_auth
Owner: M1 — Platform Backend & API Integration Lead

Verifies:
1. POST /api/v1/auth/login for Company A, Company B, and Company C.
2. Contract validation: access_token, token_type, user_id, active_tenant, role, expires_in.
3. Safe generic errors on invalid password, unknown user, inactive user, unknown tenant, and inactive tenant.
4. Cross-tenant login denial when user lacks membership in requested tenant.
5. GET /api/v1/auth/me protected profile inspection.
6. Validation errors on malformed payloads.
"""

import pytest
import httpx

from backend.app.core.config import Settings
from backend.app.main import create_app


@pytest.fixture
def auth_client():
    """Test client fixture using ASGITransport for fast, non-blocking in-process test execution."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=test_settings)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ============================================================================
# 1. Successful Authentication Tests (Multi-Tenant Workspaces)
# ============================================================================

@pytest.mark.asyncio
async def test_login_success_company_a_analyst(auth_client: httpx.AsyncClient):
    """Verify Company A security analyst logs in successfully with contract response."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == "user-a-analyst-001"
        assert data["role"] == "SECURITY_ANALYST"
        assert data["expires_in"] == 3600

        active_tenant = data["active_tenant"]
        assert active_tenant["id"] == "tenant-a-uuid-001"
        assert active_tenant["slug"] == "company-a"
        assert "Company A" in active_tenant["name"]


@pytest.mark.asyncio
async def test_login_success_company_a_admin(auth_client: httpx.AsyncClient):
    """Verify Company A administrator logs in with TENANT_ADMIN role."""
    async with auth_client as client:
        payload = {
            "email": "admin@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "TENANT_ADMIN"
        assert data["user_id"] == "user-a-admin-002"


@pytest.mark.asyncio
async def test_login_success_company_b(auth_client: httpx.AsyncClient):
    """Verify Company B user logs into Company B workspace."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-b.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-b",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["active_tenant"]["slug"] == "company-b"
        assert data["user_id"] == "user-b-analyst-003"


@pytest.mark.asyncio
async def test_login_success_company_c(auth_client: httpx.AsyncClient):
    """Verify Company C user logs into Company C workspace."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-c.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-c",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["active_tenant"]["slug"] == "company-c"
        assert data["user_id"] == "user-c-analyst-004"


@pytest.mark.asyncio
async def test_login_case_insensitivity(auth_client: httpx.AsyncClient):
    """Verify email and tenant slug normalization is case-insensitive."""
    async with auth_client as client:
        payload = {
            "email": "ANALYST@Company-A.COM ",
            "password": "SecurePassword123!",
            "tenant_slug": "COMPANY-A ",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 200
        assert response.json()["user_id"] == "user-a-analyst-001"


# ============================================================================
# 2. Authentication Rejection & Generic Error Tests
# ============================================================================

@pytest.mark.asyncio
async def test_login_wrong_password_rejected(auth_client: httpx.AsyncClient):
    """Verify incorrect password returns generic 401 error."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "WrongPassword999!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        data = response.json()
        assert data["error"]["code"] == "AUTHENTICATION_FAILED"
        assert data["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_unknown_user_rejected(auth_client: httpx.AsyncClient):
    """Verify non-existent user returns generic 401 without revealing user absence."""
    async with auth_client as client:
        payload = {
            "email": "nonexistent@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_inactive_user_rejected(auth_client: httpx.AsyncClient):
    """Verify disabled/inactive user cannot authenticate."""
    async with auth_client as client:
        payload = {
            "email": "inactive@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_unknown_tenant_rejected(auth_client: httpx.AsyncClient):
    """Verify invalid tenant slug returns generic 401 error."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "non-existent-tenant-slug",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_suspended_tenant_rejected(auth_client: httpx.AsyncClient):
    """Verify inactive/suspended tenant cannot be logged into."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "suspended-corp",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_cross_tenant_membership_rejected(auth_client: httpx.AsyncClient):
    """Verify Company A user cannot log into Company B workspace without membership."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "SecurePassword123!",
            "tenant_slug": "company-b",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email, password, or tenant access."


# ============================================================================
# 3. Request Validation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_login_invalid_email_format(auth_client: httpx.AsyncClient):
    """Verify malformed email string fails validation with 400 Bad Request."""
    async with auth_client as client:
        payload = {
            "email": "not-an-email",
            "password": "SecurePassword123!",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_login_empty_password(auth_client: httpx.AsyncClient):
    """Verify empty password fails validation."""
    async with auth_client as client:
        payload = {
            "email": "analyst@company-a.com",
            "password": "",
            "tenant_slug": "company-a",
        }
        response = await client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 400


# ============================================================================
# 4. Protected Route: GET /api/v1/auth/me
# ============================================================================

@pytest.mark.asyncio
async def test_get_me_success(auth_client: httpx.AsyncClient):
    """Verify GET /api/v1/auth/me returns current user profile and active tenant."""
    async with auth_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user-a-analyst-001"
        assert data["email"] == "analyst@company-a.com"
        assert data["full_name"] == "Alice Analyst"
        assert data["active_tenant"]["slug"] == "company-a"
        assert data["role"] == "SECURITY_ANALYST"


@pytest.mark.asyncio
async def test_get_me_unauthorized_missing_token(auth_client: httpx.AsyncClient):
    """Verify GET /api/v1/auth/me without token returns HTTP 401."""
    async with auth_client as client:
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"
