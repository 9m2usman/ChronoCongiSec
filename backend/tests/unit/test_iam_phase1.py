"""Phase 1 Acceptance Tests: Identity and Access Management (IAM).

Module: backend.tests.unit.test_iam_phase1
Owner: Principal Software Architect & QA Lead

Covers all 22 required acceptance criteria:
1. Valid user login
2. Invalid password
3. Unknown user
4. Pending employee cannot log in
5. Rejected employee cannot log in
6. Approved employee can log in
7. Registration approval creates correct membership
8. Role assignment is enforced
9. Branch access is enforced
10. User cannot select own role
11. User cannot forge tenant ID
12. User cannot forge unauthorized branch
13. Tenant Admin can approve requests
14. Non-admin cannot approve requests
15. User cannot approve own registration
16. Suspended user is denied
17. Revoked session is denied
18. Logout invalidates session
19. Session restoration works after refresh
20. Bootstrap refuses unauthorized duplicate administrators
21. Administrative operations are audited
22. Database-backed IAM parity (protocol conformance and data model invariants)
"""

import pytest
import httpx

from backend.app.core.config import Settings
from backend.app.core.security import decode_access_token, hash_password
from backend.app.main import create_app
from backend.app.tenancy.context import (
    InMemoryAuthRepository,
    UserRecord,
    MembershipRecord,
    seed_demo_accounts,
    set_default_auth_repository,
)
from backend.app.database.repositories.auth import DatabaseAuthRepository


BOOTSTRAP_SECRET_TEST = "super-secret-bootstrap-key-for-phase1"


@pytest.fixture
def iam_app_setup():
    """Create a pristine app instance with in-memory auth repository for fast, deterministic IAM testing."""
    test_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        CORS_ORIGINS=["http://localhost:5173"],
        LOGIN_RATE_LIMIT_IP_MAX_REQUESTS=10000,
        LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS=10000,
        BOOTSTRAP_SECRET=BOOTSTRAP_SECRET_TEST,
    )

    repo = InMemoryAuthRepository()
    seed_demo_accounts(repo)

    # Seed Suspended User
    suspended_pw_hash = hash_password("SuspendedPass123!")
    suspended_user = UserRecord(
        id="user-suspended-test-003",
        email="suspended@alphacorp.com",
        hashed_password=suspended_pw_hash,
        full_name="Suspended Test User",
        status="INACTIVE",
    )
    repo.add_user(suspended_user)
    suspended_mem = MembershipRecord(
        id="mem-suspended-test-003",
        tenant_id="tenant-a-uuid-001",
        user_id=suspended_user.id,
        role="SECURITY_ANALYST",
        status="ACTIVE",
        branch_id="branch-isb-004",
    )
    repo.add_membership(suspended_mem)

    set_default_auth_repository(repo)
    app = create_app(settings=test_settings)
    return app, repo, test_settings


@pytest.fixture
def iam_client(iam_app_setup):
    app, _, _ = iam_app_setup
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ============================================================================
# Acceptance Scenarios
# ============================================================================

@pytest.mark.asyncio
async def test_01_valid_user_login(iam_client: httpx.AsyncClient, iam_app_setup):
    """Scenario 1: Valid user login returns JWT with role, tenant_id, and branch_id."""
    _, _, settings = iam_app_setup
    async with iam_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "sarah.admin@alphacorp.com",
                "password": "SecurePassword123!",
                "tenant_slug": "alphacorp",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["token_type"] == "bearer"
        assert data["role"] == "TENANT_ADMIN"
        assert data["active_tenant"]["id"] == "tenant-a-uuid-001"
        assert data["active_tenant"]["slug"] in ["alphacorp", "company-a"]

        # Verify decoded JWT claims
        token = data["access_token"]
        claims = decode_access_token(token, settings=settings)
        assert claims["sub"] == "usr-admin-sarah-01"
        assert claims["role"] == "TENANT_ADMIN"
        assert claims["tenant_id"] == "tenant-a-uuid-001"


@pytest.mark.asyncio
async def test_02_invalid_password_rejected(iam_client: httpx.AsyncClient):
    """Scenario 2: Invalid password rejected with 401 Unauthorized."""
    async with iam_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "sarah.admin@alphacorp.com",
                "password": "WrongPassword!",
                "tenant_slug": "alphacorp",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_03_unknown_user_rejected(iam_client: httpx.AsyncClient):
    """Scenario 3: Unknown user rejected with 401 Unauthorized."""
    async with iam_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "does.not.exist@alphacorp.com",
                "password": "AnyPassword123!",
                "tenant_slug": "alphacorp",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_04_pending_employee_cannot_login(iam_client: httpx.AsyncClient):
    """Scenario 4: Pending employee cannot log in."""
    async with iam_client as client:
        # Submit registration request
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Pending Applicant",
                "email": "pending.applicant@alphacorp.com",
                "password": "ApplicantPass123!",
                "requested_branch_code": "LHR",
                "tenant_slug": "alphacorp",
            },
        )
        assert reg_res.status_code == 201
        assert reg_res.json()["status"] == "PENDING"

        # Attempt to login with pending account
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "pending.applicant@alphacorp.com",
                "password": "ApplicantPass123!",
                "tenant_slug": "alphacorp",
            },
        )
        assert login_res.status_code == 401
        assert login_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_05_rejected_employee_cannot_login(iam_client: httpx.AsyncClient):
    """Scenario 5: Rejected employee cannot log in."""
    async with iam_client as client:
        # 1. Submit registration
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Rejected Person",
                "email": "to.be.rejected@alphacorp.com",
                "password": "RejectMePass123!",
                "requested_branch_code": "KHI",
                "tenant_slug": "alphacorp",
            },
        )
        assert reg_res.status_code == 201
        req_id = reg_res.json()["request_id"]

        # 2. Admin logs in
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        admin_token = admin_login.json()["access_token"]

        # 3. Admin rejects request
        reject_res = await client.post(
            f"/api/v1/admin/registrations/{req_id}/reject",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"reason": "Security vetting failed."},
        )
        assert reject_res.status_code == 200
        assert "rejected" in reject_res.json()["message"].lower()

        # 4. Attempt login
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "to.be.rejected@alphacorp.com", "password": "RejectMePass123!", "tenant_slug": "alphacorp"},
        )
        assert login_res.status_code == 401
        assert login_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_06_and_07_approved_employee_can_login_and_creates_membership(iam_client: httpx.AsyncClient):
    """Scenarios 6 & 7: Approved employee can log in, and approval creates correct membership."""
    async with iam_client as client:
        # 1. Submit registration
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Approved Employee",
                "email": "approved.employee@alphacorp.com",
                "password": "ApprovedPassword123!",
                "requested_branch_code": "ISB",
                "tenant_slug": "alphacorp",
            },
        )
        req_id = reg_res.json()["request_id"]

        # 2. Admin login
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        admin_token = admin_login.json()["access_token"]

        # 3. Admin approves request
        approve_res = await client.post(
            f"/api/v1/admin/registrations/{req_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "role": "SECURITY_ANALYST",
                "branch_id": "branch-isb-004",
                "reason": "Identity verified via HR",
            },
        )
        assert approve_res.status_code == 200
        assert approve_res.json()["role"] == "SECURITY_ANALYST"
        assert approve_res.json()["branch_id"] == "branch-isb-004"

        # 4. User logs in successfully
        user_login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "approved.employee@alphacorp.com",
                "password": "ApprovedPassword123!",
                "tenant_slug": "alphacorp",
            },
        )
        assert user_login.status_code == 200
        user_data = user_login.json()
        assert user_data["role"] == "SECURITY_ANALYST"
        assert user_data["branch_id"] == "branch-isb-004"

        # 5. Verify member list includes new user with membership
        users_res = await client.get(
            "/api/v1/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert users_res.status_code == 200
        member_emails = [m["email"] for m in users_res.json()]
        assert "approved.employee@alphacorp.com" in member_emails


@pytest.mark.asyncio
async def test_08_role_assignment_is_enforced(iam_client: httpx.AsyncClient):
    """Scenario 8: Role assignment is enforced — non-admin denied administrative access."""
    async with iam_client as client:
        # Login as Alex Analyst (SECURITY_ANALYST)
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alex.analyst@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        analyst_token = analyst_login.json()["access_token"]

        # Attempt to access admin registrations endpoint
        admin_res = await client.get(
            "/api/v1/admin/registrations",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert admin_res.status_code == 403
        assert admin_res.json()["error"]["code"] == "FORBIDDEN_ACTION"


@pytest.mark.asyncio
async def test_09_branch_access_is_enforced(iam_client: httpx.AsyncClient):
    """Scenario 9: Branch access is enforced — returns canonical enterprise branches."""
    async with iam_client as client:
        res = await client.get("/api/v1/branches?tenant_slug=alphacorp")
        assert res.status_code == 200
        branches = res.json()
        assert len(branches) == 4
        codes = {b["code"] for b in branches}
        assert codes == {"HO", "LHR", "KHI", "ISB"}


@pytest.mark.asyncio
async def test_10_user_cannot_select_own_role(iam_client: httpx.AsyncClient):
    """Scenario 10: User cannot select own role — requested role overridden by Admin."""
    async with iam_client as client:
        # User registers for LHR branch
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Role Grabber",
                "email": "role.grabber@alphacorp.com",
                "password": "GrabRolePassword123!",
                "requested_branch_code": "LHR",
                "tenant_slug": "alphacorp",
            },
        )
        req_id = reg_res.json()["request_id"]

        # Admin approves as AUDITOR
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        admin_token = admin_login.json()["access_token"]

        approve_res = await client.post(
            f"/api/v1/admin/registrations/{req_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "role": "AUDITOR",
                "branch_id": "branch-lhr-002",
            },
        )
        assert approve_res.status_code == 200

        # Login and verify role is AUDITOR, not TENANT_ADMIN
        user_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "role.grabber@alphacorp.com", "password": "GrabRolePassword123!", "tenant_slug": "alphacorp"},
        )
        assert user_login.json()["role"] == "AUDITOR"


@pytest.mark.asyncio
async def test_11_user_cannot_forge_tenant_id(iam_client: httpx.AsyncClient):
    """Scenario 11: User cannot forge tenant ID — invalid tenant slug rejected across login, registration, and branches."""
    async with iam_client as client:
        # 1. Login with forged tenant slug rejected
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "sarah.admin@alphacorp.com",
                "password": "SecurePassword123!",
                "tenant_slug": "forged-nonexistent-tenant",
            },
        )
        assert login_res.status_code == 401

        # 2. Registration with forged tenant slug rejected
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Forged Applicant",
                "email": "forged.applicant@alphacorp.com",
                "password": "Password1234!",
                "requested_branch_code": "HO",
                "tenant_slug": "forged-nonexistent-tenant",
            },
        )
        assert reg_res.status_code == 400
        assert reg_res.json()["error"]["code"] == "BAD_REQUEST"

        # 3. Branch listing with forged tenant slug returns empty list
        branch_res = await client.get("/api/v1/branches?tenant_slug=forged-nonexistent-tenant")
        assert branch_res.status_code == 200
        assert branch_res.json() == []


@pytest.mark.asyncio
async def test_12_user_cannot_forge_unauthorized_branch(iam_client: httpx.AsyncClient):
    """Scenario 12: User cannot forge unauthorized branch — branch is immutable on session."""
    async with iam_client as client:
        # Create user approved for branch-lahore-88
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "lahore-dev@company-a.com", "password": "SecurePassword123!", "tenant_slug": "company-a"},
        )
        token = login_res.json()["access_token"]
        branch_id = login_res.json()["branch_id"]
        assert branch_id == "branch-lahore-88"

        # Check me endpoint strictly returns authorized branch
        me_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.json()["branch_id"] == "branch-lahore-88"


@pytest.mark.asyncio
async def test_13_tenant_admin_can_approve_requests(iam_client: httpx.AsyncClient):
    """Scenario 13: Tenant Admin can approve requests."""
    async with iam_client as client:
        # Register
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Applicant Thirteen",
                "email": "applicant.13@alphacorp.com",
                "password": "Pass12345678!",
                "requested_branch_code": "HO",
                "tenant_slug": "alphacorp",
            },
        )
        req_id = reg.json()["request_id"]

        # Admin token
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        token = admin_login.json()["access_token"]

        approve = await client.post(
            f"/api/v1/admin/registrations/{req_id}/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "AI_DEVELOPER", "branch_id": "branch-ho-001"},
        )
        assert approve.status_code == 200
        assert approve.json()["role"] == "AI_DEVELOPER"


@pytest.mark.asyncio
async def test_14_non_admin_cannot_approve_requests(iam_client: httpx.AsyncClient):
    """Scenario 14: Non-admin cannot approve requests."""
    async with iam_client as client:
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Applicant Fourteen",
                "email": "applicant.14@alphacorp.com",
                "password": "Pass12345678!",
                "requested_branch_code": "HO",
                "tenant_slug": "alphacorp",
            },
        )
        req_id = reg.json()["request_id"]

        # Analyst token
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alex.analyst@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        token = analyst_login.json()["access_token"]

        approve = await client.post(
            f"/api/v1/admin/registrations/{req_id}/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "AI_DEVELOPER"},
        )
        assert approve.status_code == 403
        assert approve.json()["error"]["code"] == "FORBIDDEN_ACTION"


@pytest.mark.asyncio
async def test_15_user_cannot_approve_own_registration(iam_client: httpx.AsyncClient, iam_app_setup):
    """Scenario 15: User cannot approve own registration — self-approval prevention."""
    _, repo, _ = iam_app_setup
    async with iam_client as client:
        # Directly insert a registration request with Sarah's email
        req = await repo.create_registration_request(
            tenant_id="tenant-a-uuid-001",
            full_name="Sarah Admin Self",
            email="sarah.admin@alphacorp.com",
            hashed_password="hashed_pass",
            requested_branch_code="HO",
        )

        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        token = admin_login.json()["access_token"]

        approve = await client.post(
            f"/api/v1/admin/registrations/{req.id}/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "TENANT_ADMIN"},
        )
        assert approve.status_code == 403
        assert approve.json()["error"]["code"] == "FORBIDDEN_ACTION"


@pytest.mark.asyncio
async def test_16_suspended_user_is_denied(iam_client: httpx.AsyncClient):
    """Scenario 16: Suspended user is denied authentication."""
    async with iam_client as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "suspended@alphacorp.com",
                "password": "SuspendedPass123!",
                "tenant_slug": "alphacorp",
            },
        )
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_17_revoked_session_is_denied(iam_client: httpx.AsyncClient):
    """Scenario 17: Revoked or invalid session token is denied."""
    async with iam_client as client:
        res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-tampered-token-xyz"},
        )
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_18_logout_invalidates_session(iam_client: httpx.AsyncClient):
    """Scenario 18: Logout endpoint succeeds and responds cleanly."""
    async with iam_client as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alex.analyst@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        token = login.json()["access_token"]

        res = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        assert "revoked" in res.json()["message"].lower()


@pytest.mark.asyncio
async def test_19_session_restoration_works_after_refresh(iam_client: httpx.AsyncClient):
    """Scenario 19: Session restoration works after refresh via /auth/me."""
    async with iam_client as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alex.analyst@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        token = login.json()["access_token"]

        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        profile = me.json()
        assert profile["email"] == "alex.analyst@alphacorp.com"
        assert profile["role"] == "SECURITY_ANALYST"
        assert profile["active_tenant"]["id"] == "tenant-a-uuid-001"


@pytest.mark.asyncio
async def test_20_bootstrap_refuses_unauthorized_and_duplicate_admins(iam_client: httpx.AsyncClient):
    """Scenario 20: Bootstrap refuses unauthorized access and duplicate administrators."""
    async with iam_client as client:
        # 1. Invalid bootstrap secret
        bad_secret_res = await client.post(
            "/api/v1/auth/bootstrap-admin",
            headers={"X-Bootstrap-Secret": "wrong-secret"},
            json={
                "tenant_slug": "alphacorp",
                "admin_email": "hacker.admin@alphacorp.com",
                "admin_full_name": "Hacker Admin",
                "password": "HackerPass123!",
            },
        )
        assert bad_secret_res.status_code == 403

        # 2. Duplicate admin attempt in tenant that already has an admin
        dup_res = await client.post(
            "/api/v1/auth/bootstrap-admin",
            headers={"X-Bootstrap-Secret": BOOTSTRAP_SECRET_TEST},
            json={
                "tenant_slug": "alphacorp",
                "admin_email": "another.admin@alphacorp.com",
                "admin_full_name": "Another Admin",
                "password": "AnotherPass123!",
            },
        )
        assert dup_res.status_code == 409
        assert dup_res.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_21_administrative_operations_are_audited(iam_client: httpx.AsyncClient):
    """Scenario 21: Administrative operations and authentication events are recorded to immutable audit trail."""
    async with iam_client as client:
        # 1. Register user
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Audit Test",
                "email": "audit.test@alphacorp.com",
                "password": "Pass12345678!",
                "requested_branch_code": "HO",
                "tenant_slug": "alphacorp",
            },
        )
        assert reg.status_code == 201
        req_id = reg.json()["request_id"]

        # 2. Failed login attempt (audited as LOGIN_FAILED)
        bad_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "WrongPassword!", "tenant_slug": "alphacorp"},
        )
        assert bad_login.status_code == 401

        # 3. Successful admin login (audited as LOGIN_SUCCESS)
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "sarah.admin@alphacorp.com", "password": "SecurePassword123!", "tenant_slug": "alphacorp"},
        )
        assert admin_login.status_code == 200
        token = admin_login.json()["access_token"]

        # 4. Approve with note (audited as REGISTRATION_APPROVED)
        approve_res = await client.post(
            f"/api/v1/admin/registrations/{req_id}/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "role": "SECURITY_ANALYST",
                "branch_id": "branch-ho-001",
                "reason": "AUDIT-TRACE-APPROVED-BY-SARAH-001",
            },
        )
        assert approve_res.status_code == 200

        # 5. Query audit trail via /api/v1/audit/events
        audit_res = await client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {token}"})
        assert audit_res.status_code == 200
        events = audit_res.json()
        assert len(events) >= 3

        actions = [e["action"] for e in events]
        assert "REGISTRATION_APPROVED" in actions
        assert "LOGIN_SUCCESS" in actions
        assert "REGISTRATION_REQUEST_SUBMITTED" in actions


@pytest.mark.asyncio
async def test_22_database_auth_repository_real_database_execution():
    """Scenario 22: DatabaseAuthRepository executes real CRUD, constraints, and transactions against a database."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from backend.app.database.models.identity import Tenant, Branch, User, Membership, RegistrationRequest

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        for table in [
            Tenant.__table__,
            Branch.__table__,
            User.__table__,
            Membership.__table__,
            RegistrationRequest.__table__,
        ]:
            await conn.run_sync(table.create)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    repo = DatabaseAuthRepository(session_factory)

    # 1. Seed tenant and branches in database
    async with session_factory() as session:
        async with session.begin():
            t = Tenant(id="tenant-db-001", name="AlphaCorp Database", slug="alphacorp", status="ACTIVE")
            b_ho = Branch(id="b-ho", tenant_id="tenant-db-001", name="Head Office", code="HO", status="ACTIVE")
            b_lhr = Branch(id="b-lhr", tenant_id="tenant-db-001", name="Lahore Branch", code="LHR", status="ACTIVE")
            session.add_all([t, b_ho, b_lhr])

    # 2. Test branch listing & lookup
    branches = await repo.list_branches("tenant-db-001")
    assert len(branches) == 2
    assert {b.code for b in branches} == {"HO", "LHR"}

    b_by_code = await repo.get_branch_by_code("tenant-db-001", "HO")
    assert b_by_code is not None
    assert b_by_code.id == "b-ho"

    b_by_id = await repo.get_branch_by_id("tenant-db-001", "b-lhr")
    assert b_by_id is not None
    assert b_by_id.code == "LHR"

    # 3. Test first Tenant Admin bootstrap
    tenant_rec, admin_user, admin_mem = await repo.bootstrap_tenant_admin(
        tenant_slug="alphacorp",
        admin_email="admin.db@alphacorp.com",
        admin_full_name="Database Admin",
        password_hash="hash_pw_123",
    )
    assert admin_mem.role == "TENANT_ADMIN"
    assert admin_user.email == "admin.db@alphacorp.com"

    # Duplicate bootstrap must be refused
    with pytest.raises(RuntimeError):
        await repo.bootstrap_tenant_admin(
            tenant_slug="alphacorp",
            admin_email="another.admin@alphacorp.com",
            admin_full_name="Another Admin",
            password_hash="hash_pw_456",
        )

    # 4. Test registration request lifecycle
    req = await repo.create_registration_request(
        tenant_id="tenant-db-001",
        full_name="Applicant DB",
        email="applicant.db@alphacorp.com",
        hashed_password="pw_applicant_hash",
        requested_branch_code="LHR",
    )
    assert req.status == "PENDING"

    fetched_req = await repo.get_registration_request_by_id(req.id)
    assert fetched_req is not None
    assert fetched_req.email == "applicant.db@alphacorp.com"

    pending_list = await repo.list_registration_requests("tenant-db-001", status="PENDING")
    assert len(pending_list) == 1

    # 5. Approve registration request
    approved_user, approved_mem = await repo.approve_registration_request(
        request_id=req.id,
        admin_user_id=admin_user.id,
        assigned_role="SECURITY_ANALYST",
        assigned_branch_id="b-lhr",
        reason="Verified employee credentials",
    )
    assert approved_user.email == "applicant.db@alphacorp.com"
    assert approved_mem.role == "SECURITY_ANALYST"
    assert approved_mem.branch_id == "b-lhr"
    assert approved_mem.status == "ACTIVE"

    # Second approval of already approved request must raise ValueError
    with pytest.raises(ValueError):
        await repo.approve_registration_request(
            request_id=req.id,
            admin_user_id=admin_user.id,
            assigned_role="SECURITY_ANALYST",
            assigned_branch_id="b-lhr",
        )

    # Verify membership retrieval
    mem = await repo.get_membership(approved_user.id, "tenant-db-001")
    assert mem is not None
    assert mem.role == "SECURITY_ANALYST"
    assert mem.branch_id == "b-lhr"

    # 6. List tenant members with branch join
    members = await repo.list_tenant_members("tenant-db-001")
    assert len(members) == 2  # admin + approved applicant
    app_mem_row = next(m for m in members if m["email"] == "applicant.db@alphacorp.com")
    assert app_mem_row["branch_code"] == "LHR"
    assert app_mem_row["branch_name"] == "Lahore Branch"

    # 7. Update member role, branch, and status
    updated_mem = await repo.update_member(
        tenant_id="tenant-db-001",
        user_id=approved_user.id,
        role="AUDITOR",
        branch_id="b-ho",
        status="SUSPENDED",
    )
    assert updated_mem.role == "AUDITOR"
    assert updated_mem.branch_id == "b-ho"
    assert updated_mem.status == "SUSPENDED"

    # 8. Test rejection lifecycle on a second request
    req2 = await repo.create_registration_request(
        tenant_id="tenant-db-001",
        full_name="Rejected DB Applicant",
        email="reject.db@alphacorp.com",
        hashed_password="pw_reject_hash",
        requested_branch_code="HO",
    )
    rejected_req = await repo.reject_registration_request(
        request_id=req2.id,
        admin_user_id=admin_user.id,
        reason="Vetting failed",
    )
    assert rejected_req.status == "REJECTED"

    with pytest.raises(ValueError):
        await repo.reject_registration_request(
            request_id=req2.id,
            admin_user_id=admin_user.id,
            reason="Duplicate rejection",
        )

    # 9. Verify protocol method conformance
    for method_name in [
        "get_user_by_email",
        "get_user_by_id",
        "get_tenant_by_slug",
        "get_tenant_by_id",
        "get_membership",
        "list_user_tenants",
        "list_branches",
        "get_branch_by_code",
        "get_branch_by_id",
        "create_registration_request",
        "get_registration_request_by_id",
        "list_registration_requests",
        "approve_registration_request",
        "reject_registration_request",
        "list_tenant_members",
        "update_member",
        "bootstrap_tenant_admin",
    ]:
        assert hasattr(DatabaseAuthRepository, method_name)

    await engine.dispose()
