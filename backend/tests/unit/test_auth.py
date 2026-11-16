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


# ============================================================================
# 5. Membership Status Enforcement Tests (M1 Day 2 Security Hardening)
# ============================================================================

@pytest.mark.asyncio
async def test_login_revoked_membership_rejected(auth_client: httpx.AsyncClient):
    """Verify user with REVOKED membership status is rejected at login with 401."""
    async with auth_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "revoked-mem@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        assert res.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_suspended_membership_rejected(auth_client: httpx.AsyncClient):
    """Verify user with SUSPENDED membership status is rejected at login with 401."""
    async with auth_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "suspended-mem@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        assert res.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_inactive_membership_rejected(auth_client: httpx.AsyncClient):
    """Verify user with INACTIVE membership status is rejected at login with 401."""
    async with auth_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "inactive-mem@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        assert res.json()["error"]["message"] == "Invalid email, password, or tenant access."


@pytest.mark.asyncio
async def test_login_membership_database_failure_fails_closed():
    """Verify repository/database failure during membership check fails closed with HTTP 503."""
    from backend.app.tenancy.context import InMemoryAuthRepository, set_default_auth_repository

    class FailingMembershipRepo(InMemoryAuthRepository):
        async def get_membership(self, user_id: str, tenant_id: str):
            raise RuntimeError("Simulated database outage during membership check")

    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=test_settings)
    failing_repo = FailingMembershipRepo()
    from backend.app.tenancy.context import seed_demo_accounts
    seed_demo_accounts(failing_repo)
    app.state.auth_repo = failing_repo

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
        assert res.status_code == 503
        assert res.json()["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_protected_request_denied_when_membership_revoked():
    """Verify protected endpoint denies access with 403 Forbidden after membership is revoked."""
    from backend.app.core.security import create_access_token
    from backend.app.tenancy.context import (
        InMemoryAuthRepository,
        MembershipRecord,
        seed_demo_accounts,
    )

    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=test_settings)
    repo = InMemoryAuthRepository()
    seed_demo_accounts(repo)
    app.state.auth_repo = repo

    # Issue token for user whose membership is active
    token = create_access_token(
        user_id="user-a-analyst-001",
        tenant_id="tenant-a-uuid-001",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # First request succeeds
        res_ok = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_ok.status_code == 200

        # Now revoke the membership in repository
        repo.add_membership(
            MembershipRecord(
                id="mem-001",
                tenant_id="tenant-a-uuid-001",
                user_id="user-a-analyst-001",
                role="SECURITY_ANALYST",
                status="REVOKED",
            )
        )

        # Subsequent request with previously valid token must be denied with HTTP 403
        res_revoked = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_revoked.status_code == 403
        assert res_revoked.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_protected_request_denied_when_membership_suspended():
    """Verify protected endpoint denies access with 403 Forbidden when membership is suspended."""
    from backend.app.core.security import create_access_token
    from backend.app.tenancy.context import (
        InMemoryAuthRepository,
        MembershipRecord,
        seed_demo_accounts,
    )

    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=test_settings)
    repo = InMemoryAuthRepository()
    seed_demo_accounts(repo)
    app.state.auth_repo = repo

    token = create_access_token(
        user_id="user-suspended-mem-007",
        tenant_id="tenant-a-uuid-001",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_protected_request_denied_when_membership_missing():
    """Verify protected endpoint denies access with 403 Forbidden when membership record does not exist."""
    from backend.app.core.security import create_access_token
    from backend.app.tenancy.context import (
        InMemoryAuthRepository,
        seed_demo_accounts,
    )

    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=test_settings)
    repo = InMemoryAuthRepository()
    seed_demo_accounts(repo)
    app.state.auth_repo = repo

    # Token claims tenant B, but user A has no membership in tenant B
    token = create_access_token(
        user_id="user-a-analyst-001",
        tenant_id="tenant-b-uuid-002",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


# ============================================================================
# 6. Account Rate Limiting DoS Prevention & Proxy Tests (M1 Day 2)
# ============================================================================

@pytest.mark.asyncio
async def test_repeated_attacks_on_victim_account_do_not_block_victim_from_other_ip():
    """Verify an attacker exhausting attempts on victim email from IP A does NOT lock out victim from IP B."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=3,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    app = create_app(settings=test_settings)

    # Attacker on client transport A (simulating IP 198.51.100.1)
    transport_attacker = httpx.ASGITransport(app=app, client=("198.51.100.1", 50000))
    # Legitimate victim on client transport B (simulating IP 203.0.113.5)
    transport_victim = httpx.ASGITransport(app=app, client=("203.0.113.5", 50000))

    async with httpx.AsyncClient(transport=transport_attacker, base_url="http://test") as attacker_client:
        # Attacker exhausts 3 attempts with wrong password
        for _ in range(3):
            res = await attacker_client.post(
                "/api/v1/auth/login",
                json={
                    "email": "analyst@company-a.com",
                    "password": "AttackerWrongPassword123!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

        # Attacker's 4th attempt is throttled with HTTP 429
        blocked_res = await attacker_client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "AttackerWrongPassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        assert blocked_res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Now legitimate user logs in from their own IP with valid credentials
    async with httpx.AsyncClient(transport=transport_victim, base_url="http://test") as victim_client:
        victim_res = await victim_client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        # Victim is NOT locked out and logs in successfully
        assert victim_res.status_code == 200
        assert victim_res.json()["user_id"] == "user-a-analyst-001"


@pytest.mark.asyncio
async def test_arbitrary_client_forwarded_headers_cannot_bypass_ip_rate_limit():
    """Verify spoofed X-Forwarded-For headers from untrusted clients are ignored and do not bypass rate limits."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=3,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
        TRUSTED_PROXIES=[],  # No proxies trusted
    )
    app = create_app(settings=test_settings)
    transport = httpx.ASGITransport(app=app, client=("192.0.2.10", 40000))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Attacker sends spoofed X-Forwarded-For with a different fake IP on each request
        for i in range(3):
            res = await client.post(
                "/api/v1/auth/login",
                headers={"X-Forwarded-For": f"10.0.0.{i+1}"},
                json={
                    "email": "analyst@company-a.com",
                    "password": "WrongPassword!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

        # 4th request with yet another fake IP must STILL be throttled because direct IP is rate limited
        blocked_res = await client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": "10.0.0.99"},
            json={
                "email": "analyst@company-a.com",
                "password": "WrongPassword!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked_res.status_code == 429
        assert blocked_res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_trusted_proxy_correctly_resolves_forwarded_ip():
    """Verify requests arriving from explicitly trusted proxy use the forwarded client IP."""
    trusted_proxy_ip = "10.200.0.1"
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=2,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=100,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
        TRUSTED_PROXIES=[trusted_proxy_ip],
    )
    app = create_app(settings=test_settings)
    # Peer IP is the trusted proxy
    transport = httpx.ASGITransport(app=app, client=(trusted_proxy_ip, 55000))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Client 1 forwarded through proxy
        for _ in range(2):
            res = await client.post(
                "/api/v1/auth/login",
                headers={"X-Forwarded-For": "203.0.113.199"},
                json={
                    "email": "analyst@company-a.com",
                    "password": "WrongPassword!",
                    "tenant_slug": "company-a",
                },
            )
            assert res.status_code == 401

        # 3rd request for Client 1 is blocked
        blocked = await client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": "203.0.113.199"},
            json={
                "email": "analyst@company-a.com",
                "password": "WrongPassword!",
                "tenant_slug": "company-a",
            },
        )
        assert blocked.status_code == 429

        # But a DIFFERENT client through the same trusted proxy is NOT blocked
        diff_client = await client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": "203.0.113.200"},
            json={
                "email": "analyst@company-a.com",
                "password": "WrongPassword!",
                "tenant_slug": "company-a",
            },
        )
        assert diff_client.status_code == 401
