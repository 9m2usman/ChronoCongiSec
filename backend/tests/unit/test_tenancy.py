"""Unit and Integration Tests for Multi-Tenant Isolation & Context Resolution.

Module: backend.tests.unit.test_tenancy
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 5: Multi-Tenant Architecture
- AMSC-DOC-005 Section 3.1 & 5.1: Tenancy Endpoints & Identity Model
- AMSC-DOC-006 Day 2 Multi-Tenant Isolation Verification Matrix
"""

import asyncio
import pytest
import httpx
from fastapi import FastAPI, Depends

from backend.app.core.config import Settings
from backend.app.core.dependencies import (
    require_roles,
)
from backend.app.tenancy.context import (
    InMemoryAuthRepository,
    TenantContext,
    TenantRecord,
    UserRecord,
    get_default_auth_repository,
    set_default_auth_repository,
)
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.security import create_access_token
from backend.app.main import create_app


@pytest.fixture
def tenancy_client():
    """Test client fixture initialized with standard settings and default Company A/B/C fixtures."""
    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=1000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=1000,
    )
    app = create_app(settings=settings)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ============================================================================
# 1. Multi-Tenant Login & Token Generation Verification
# ============================================================================

@pytest.mark.asyncio
async def test_company_a_user_authenticates_into_company_a(tenancy_client: httpx.AsyncClient):
    """Verify Company A user successfully accesses Company A workspace."""
    async with tenancy_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["active_tenant"]["slug"] == "company-a"
        assert data["role"] == "SECURITY_ANALYST"


@pytest.mark.asyncio
async def test_company_a_user_cannot_authenticate_into_company_b(tenancy_client: httpx.AsyncClient):
    """Verify Company A user is strictly rejected when attempting to authenticate into Company B."""
    async with tenancy_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-b",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


# ============================================================================
# 2. Cross-Tenant Header Spoofing & Header Validation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_matching_tenant_header_allowed(tenancy_client: httpx.AsyncClient):
    """Verify X-Tenant-ID matching the token's authorized tenant is accepted."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]
        tenant_id = login_res.json()["active_tenant"]["id"]

        res = await client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": tenant_id,
            },
        )
        assert res.status_code == 200
        assert res.json()["active_tenant"]["id"] == tenant_id


@pytest.mark.asyncio
async def test_mismatched_tenant_header_rejected_with_403(tenancy_client: httpx.AsyncClient):
    """Verify X-Tenant-ID spoofing (mismatch with JWT claim) is rejected with HTTP 403."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        # Attempt cross-tenant spoofing by requesting Company B's tenant ID
        res = await client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": "tenant-b-uuid-002",
            },
        )
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


# ============================================================================
# 3. Tenant Workspaces API Tests (/api/v1/tenants)
# ============================================================================

@pytest.mark.asyncio
async def test_list_user_tenants(tenancy_client: httpx.AsyncClient):
    """Verify GET /api/v1/tenants lists only authorized workspaces for current user."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        res = await client.get(
            "/api/v1/tenants",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        tenants = res.json()
        assert len(tenants) == 1
        assert tenants[0]["slug"] == "company-a"


@pytest.mark.asyncio
async def test_get_tenant_details_authorized(tenancy_client: httpx.AsyncClient):
    """Verify querying details of authorized tenant succeeds."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]
        tenant_id = login_res.json()["active_tenant"]["id"]

        res = await client.get(
            f"/api/v1/tenants/{tenant_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        assert res.json()["slug"] == "company-a"


@pytest.mark.asyncio
async def test_get_other_tenant_details_forbidden(tenancy_client: httpx.AsyncClient):
    """Verify Company A user querying Company B's tenant ID directly is rejected with HTTP 403."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        res = await client.get(
            "/api/v1/tenants/tenant-b-uuid-002",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


# ============================================================================
# 4. Role Authorization & RBAC Integration Boundary (M4 Integration)
# ============================================================================

@pytest.mark.asyncio
async def test_role_enforcement_boundary():
    """Verify require_roles dependency permits authorized role and denies unauthorized role."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/admin-only")
    async def admin_only(
        ctx: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    ):
        return {"status": "ok", "user": ctx.user_id}

    settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
    )
    app.state.settings = settings

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Analyst token should be rejected (403)
        analyst_token = create_access_token(
            user_id="user-a-analyst-001",
            tenant_id="tenant-a-uuid-001",
            role="SECURITY_ANALYST",
            settings=settings,
        )
        res_analyst = await client.get(
            "/admin-only",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_analyst.status_code == 403
        assert res_analyst.json()["error"]["code"] == "FORBIDDEN_ACTION"

        # 2. Admin token should be allowed (200)
        admin_token = create_access_token(
            user_id="user-a-admin-002",
            tenant_id="tenant-a-uuid-001",
            role="TENANT_ADMIN",
            settings=settings,
        )
        res_admin = await client.get(
            "/admin-only",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_admin.status_code == 200
        assert res_admin.json()["status"] == "ok"


# ============================================================================
# 5. Request-Scoped Context Isolation
# ============================================================================

@pytest.mark.asyncio
async def test_request_scoped_tenant_isolation(tenancy_client: httpx.AsyncClient):
    """Verify context does not bleed across consecutive requests with different identities."""
    async with tenancy_client as client:
        # 1. Request as Company A
        res_a = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token_a = res_a.json()["access_token"]

        # 2. Request as Company C
        res_c = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-c.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-c",
            },
        )
        token_c = res_c.json()["access_token"]

        # 3. Interleaved requests asserting distinct tenant context
        me_a = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_a}"})
        me_c = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_c}"})

        assert me_a.json()["active_tenant"]["slug"] == "company-a"
        assert me_c.json()["active_tenant"]["slug"] == "company-c"


# ============================================================================
# 6. Lifecycle & Dynamic Revocation Security Tests (Section 10 Requirements)
# ============================================================================

@pytest.mark.asyncio
async def test_deactivated_user_token_rejected_on_protected_routes(tenancy_client: httpx.AsyncClient):
    """Verify an existing valid token is rejected when user is deactivated in database."""
    repo = get_default_auth_repository()
    async with tenancy_client as client:
        # 1. Login while active
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        # 2. Deactivate user in repository
        original_user = await repo.get_user_by_email("analyst@company-a.com")
        assert original_user is not None
        deactivated_user = UserRecord(
            id=original_user.id,
            email=original_user.email,
            hashed_password=original_user.hashed_password,
            full_name=original_user.full_name,
            status="INACTIVE",
        )
        if isinstance(repo, InMemoryAuthRepository):
            repo.add_user(deactivated_user)

        try:
            # 3. Access protected route with prior valid token
            res = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 401
            assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        finally:
            # Restore user state
            if isinstance(repo, InMemoryAuthRepository):
                repo.add_user(original_user)


@pytest.mark.asyncio
async def test_revoked_membership_token_rejected_on_protected_routes(tenancy_client: httpx.AsyncClient):
    """Verify an existing valid token is rejected when user's membership in tenant is removed."""
    repo = get_default_auth_repository()
    async with tenancy_client as client:
        # 1. Login while member
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-b.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-b",
            },
        )
        token = login_res.json()["access_token"]
        user_id = login_res.json()["user_id"]
        tenant_id = login_res.json()["active_tenant"]["id"]

        # 2. Revoke membership in repository
        original_membership = await repo.get_membership(user_id, tenant_id)
        assert original_membership is not None
        if isinstance(repo, InMemoryAuthRepository):
            repo.memberships.pop((user_id, tenant_id), None)

        try:
            # 3. Access protected route with revoked membership
            res = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 403
            assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"
        finally:
            # Restore membership
            if isinstance(repo, InMemoryAuthRepository):
                repo.add_membership(original_membership)


@pytest.mark.asyncio
async def test_suspended_tenant_token_rejected_on_protected_routes(tenancy_client: httpx.AsyncClient):
    """Verify an existing valid token is rejected when tenant organization is suspended."""
    repo = get_default_auth_repository()
    async with tenancy_client as client:
        # 1. Login while tenant active
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-c.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-c",
            },
        )
        token = login_res.json()["access_token"]
        tenant_id = login_res.json()["active_tenant"]["id"]

        # 2. Suspend tenant in repository
        original_tenant = await repo.get_tenant_by_id(tenant_id)
        assert original_tenant is not None
        suspended_tenant = TenantRecord(
            id=original_tenant.id,
            name=original_tenant.name,
            slug=original_tenant.slug,
            status="SUSPENDED",
        )
        if isinstance(repo, InMemoryAuthRepository):
            repo.add_tenant(suspended_tenant)

        try:
            # 3. Access protected route
            res = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 403
            assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"
        finally:
            # Restore tenant
            if isinstance(repo, InMemoryAuthRepository):
                repo.add_tenant(original_tenant)


@pytest.mark.asyncio
async def test_database_failure_fails_closed(tenancy_client: httpx.AsyncClient):
    """Verify database repository exceptions fail closed and do not grant access."""
    class FailingAuthRepository(InMemoryAuthRepository):
        async def get_user_by_id(self, user_id: str):
            raise RuntimeError("Database connection timed out during verification")

    original_repo = get_default_auth_repository()
    set_default_auth_repository(FailingAuthRepository())

    try:
        # Validly generated token
        settings = Settings(
            APP_ENV="test",
            JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        )
        token = create_access_token(
            user_id="user-a-analyst-001",
            tenant_id="tenant-a-uuid-001",
            role="SECURITY_ANALYST",
            settings=settings,
        )

        async with tenancy_client as client:
            res = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            # Fails closed with 503 error, never grants access or exposes details
            assert res.status_code == 503
            assert res.json()["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"
            assert "Database connection timed out" not in res.text
    finally:
        set_default_auth_repository(original_repo)


@pytest.mark.asyncio
async def test_concurrent_requests_strict_isolation(tenancy_client: httpx.AsyncClient):
    """Verify simultaneous concurrent requests across different tenants do not leak context."""
    async with tenancy_client as client:
        # Obtain tokens for Company A, Company B, and Company C
        res_a = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token_a = res_a.json()["access_token"]

        res_b = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-b.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-b",
            },
        )
        token_b = res_b.json()["access_token"]

        res_c = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-c.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-c",
            },
        )
        token_c = res_c.json()["access_token"]

        # Run 30 concurrent requests interleaved across A, B, and C
        async def fetch_me(token: str, expected_slug: str):
            res = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["active_tenant"]["slug"] == expected_slug

        tasks = []
        for _ in range(10):
            tasks.append(fetch_me(token_a, "company-a"))
            tasks.append(fetch_me(token_b, "company-b"))
            tasks.append(fetch_me(token_c, "company-c"))

        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_correlation_id_propagation_and_sanitization(tenancy_client: httpx.AsyncClient):
    """Verify incoming X-Correlation-ID is preserved and returned."""
    async with tenancy_client as client:
        res = await client.get(
            "/health",
            headers={"X-Correlation-ID": "corr-uuid-trace-4242"},
        )
        assert res.status_code == 200
        assert res.headers.get("X-Correlation-ID") == "corr-uuid-trace-4242"
        assert "X-Request-ID" in res.headers


@pytest.mark.asyncio
async def test_malicious_x_tenant_id_header_not_reflected(tenancy_client: httpx.AsyncClient):
    """Verify header injection or script payloads in X-Tenant-ID are safely rejected without reflection."""
    async with tenancy_client as client:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "analyst@company-a.com",
                "password": "SecurePassword123!",
                "tenant_slug": "company-a",
            },
        )
        token = login_res.json()["access_token"]

        malicious_header = "<script>alert('xss')</script>\r\nInjected-Header: evil"
        res = await client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": malicious_header,
            },
        )
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"
        assert "<script>" not in res.text
        assert "Injected-Header" not in res.text
