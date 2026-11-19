"""HTTP integration tests: M4 RBAC evaluator behind M1's real authentication.

Module: backend.tests.security.test_rbac_integration
Owner: M4 — Security Engine & Incident Response Lead

Requests travel through M1's ``get_tenant_context`` (JWT verification, user /
tenant / membership re-verification) and M1's global exception handlers, then the
M4 ``require_role_access`` dependency. Nothing in M1-owned code is modified; a
test-only FastAPI app and an injected auth repository are used, following the
pattern in ``backend/tests/unit/test_tenancy.py``.
"""

import asyncio

import httpx
import pytest
from fastapi import Depends, FastAPI

from backend.app.core.config import Settings
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.security import create_access_token
from backend.app.security.authorization import Role, authorize, require_role_access
from backend.app.tenancy.context import (
    InMemoryAuthRepository,
    MembershipRecord,
    TenantContext,
    TenantRecord,
    UserRecord,
)
from backend.app.core.dependencies import get_tenant_context

TENANT_A = "tenant-a-uuid-001"
TENANT_B = "tenant-b-uuid-002"
JWT_SECRET = "m4-rbac-test-secret-with-more-than-thirty-two-characters"

# user_id -> {tenant_id: (role, membership_status)}
MEMBERSHIPS = {
    "u-admin": {TENANT_A: ("TENANT_ADMIN", "ACTIVE")},
    "u-analyst": {TENANT_A: ("SECURITY_ANALYST", "ACTIVE")},
    "u-dev": {TENANT_A: ("DEVELOPER", "ACTIVE")},
    "u-aidev": {TENANT_A: ("AI_DEVELOPER", "ACTIVE")},
    "u-auditor": {TENANT_A: ("AUDITOR", "ACTIVE")},
    "u-lower": {TENANT_A: ("tenant_admin", "ACTIVE")},
    "u-empty": {TENANT_A: ("", "ACTIVE")},
    "u-revoked-admin": {TENANT_A: ("TENANT_ADMIN", "REVOKED")},
    "u-inactive-admin": {TENANT_A: ("TENANT_ADMIN", "INACTIVE")},
    # Same person, different roles per tenant.
    "u-multi": {TENANT_A: ("TENANT_ADMIN", "ACTIVE"), TENANT_B: ("SECURITY_ANALYST", "ACTIVE")},
    "u-admin-b": {TENANT_B: ("TENANT_ADMIN", "ACTIVE")},
}


def build_repo() -> InMemoryAuthRepository:
    repo = InMemoryAuthRepository()
    repo.add_tenant(TenantRecord(id=TENANT_A, name="Company A", slug="company-a"))
    repo.add_tenant(TenantRecord(id=TENANT_B, name="Company B", slug="company-b"))
    for user_id, tenants in MEMBERSHIPS.items():
        repo.add_user(UserRecord(id=user_id, email=f"{user_id}@example.test", hashed_password="x", full_name=user_id))
        for tenant_id, (role, status) in tenants.items():
            repo.add_membership(
                MembershipRecord(
                    id=f"m-{user_id}-{tenant_id}", tenant_id=tenant_id, user_id=user_id, role=role, status=status
                )
            )
    return repo


def build_app(repo=None) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.state.settings = Settings(APP_ENV="test", JWT_SECRET=JWT_SECRET)
    app.state.auth_repo = repo if repo is not None else build_repo()

    @app.get("/rbac/admin")
    async def admin_only(ctx: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN))):
        return {"tenant_id": ctx.tenant_id, "user_id": ctx.user_id, "role": ctx.role}

    @app.get("/rbac/analyst")
    async def analyst_only(ctx: TenantContext = Depends(require_role_access(Role.SECURITY_ANALYST))):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    @app.get("/rbac/developer")
    async def developer_only(ctx: TenantContext = Depends(require_role_access(Role.DEVELOPER))):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    @app.get("/rbac/any-day2-role")
    async def any_day2_role(
        ctx: TenantContext = Depends(require_role_access(Role.TENANT_ADMIN, Role.SECURITY_ANALYST, Role.DEVELOPER)),
    ):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    # Resource addressed by tenant: the tenant id identifies a server-side resource and
    # is checked against the authenticated tenant (object-level guard, API1:2023).
    @app.get("/rbac/tenants/{resource_tenant_id}/settings")
    async def tenant_settings(resource_tenant_id: str, ctx: TenantContext = Depends(get_tenant_context)):
        authorize(ctx, [Role.TENANT_ADMIN], expected_tenant_id=resource_tenant_id)
        return {"tenant_id": ctx.tenant_id}

    return app


def token(user_id: str, tenant_id: str = TENANT_A, role_claim: str = "SECURITY_ANALYST") -> str:
    # role_claim is deliberately arbitrary: M1 takes the effective role from the membership repository.
    settings = Settings(APP_ENV="test", JWT_SECRET=JWT_SECRET)
    return create_access_token(user_id=user_id, tenant_id=tenant_id, role=role_claim, settings=settings)


def auth(user_id: str, tenant_id: str = TENANT_A, role_claim: str = "SECURITY_ANALYST", **extra) -> dict:
    headers = {"Authorization": f"Bearer {token(user_id, tenant_id, role_claim)}"}
    headers.update(extra)
    return headers


@pytest.fixture
def client():
    transport = httpx.ASGITransport(app=build_app())
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def assert_forbidden(res: httpx.Response) -> None:
    assert res.status_code == 403
    body = res.json()
    assert body["error"]["code"] in {"FORBIDDEN_ACTION", "TENANT_ACCESS_FORBIDDEN"}
    serialized = res.text
    # No reason codes, role mappings or internals leak to the client.
    for leak in ("ROLE_", "POLICY_", "CONTEXT_", "TENANT_MISMATCH", "Traceback", "allowed_roles", JWT_SECRET):
        assert leak not in serialized
    assert body["error"]["details"] is None


# ---------------------------------------------------------------------------
# E. Authentication integration — permitted and unauthorized roles
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,user_id,expected_role",
    [
        ("/rbac/admin", "u-admin", "TENANT_ADMIN"),
        ("/rbac/analyst", "u-analyst", "SECURITY_ANALYST"),
        ("/rbac/developer", "u-dev", "DEVELOPER"),
        ("/rbac/any-day2-role", "u-admin", "TENANT_ADMIN"),
        ("/rbac/any-day2-role", "u-analyst", "SECURITY_ANALYST"),
        ("/rbac/any-day2-role", "u-dev", "DEVELOPER"),
    ],
)
async def test_permitted_role_is_allowed(client, path, user_id, expected_role):
    async with client:
        res = await client.get(path, headers=auth(user_id))
    assert res.status_code == 200
    assert res.json()["role"] == expected_role
    assert res.json()["tenant_id"] == TENANT_A


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,user_id",
    [
        ("/rbac/admin", "u-analyst"),
        ("/rbac/admin", "u-dev"),
        ("/rbac/analyst", "u-dev"),
        ("/rbac/analyst", "u-admin"),  # TENANT_ADMIN is not an implicit super-role
        ("/rbac/developer", "u-admin"),
        ("/rbac/developer", "u-analyst"),
    ],
)
async def test_unauthorized_recognized_role_returns_403(client, path, user_id):
    async with client:
        res = await client.get(path, headers=auth(user_id))
    assert_forbidden(res)


@pytest.mark.asyncio
@pytest.mark.parametrize("user_id", ["u-aidev", "u-auditor", "u-lower", "u-empty"])
async def test_unknown_unsupported_or_malformed_membership_role_returns_403(client, user_id):
    async with client:
        for path in ("/rbac/admin", "/rbac/analyst", "/rbac/developer", "/rbac/any-day2-role"):
            res = await client.get(path, headers=auth(user_id))
            assert_forbidden(res)


@pytest.mark.asyncio
async def test_jwt_role_claim_cannot_escalate_privilege(client):
    # Analyst forges/obtains a token whose role claim says TENANT_ADMIN.
    async with client:
        res = await client.get("/rbac/admin", headers=auth("u-analyst", role_claim="TENANT_ADMIN"))
    assert_forbidden(res)


@pytest.mark.asyncio
async def test_role_supplied_in_headers_query_or_body_is_ignored(client):
    async with client:
        res = await client.request(
            "GET",
            "/rbac/admin?role=TENANT_ADMIN&tenant_id=tenant-b-uuid-002",
            headers=auth("u-dev", **{"X-Role": "TENANT_ADMIN", "X-User-Role": "TENANT_ADMIN"}),
            json={"role": "TENANT_ADMIN", "tenant_id": TENANT_B},
        )
    assert_forbidden(res)


@pytest.mark.asyncio
async def test_missing_authentication_remains_401(client):
    async with client:
        res = await client.get("/rbac/any-day2-role")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header",
    ["Bearer not-a-jwt", "Basic dXNlcjpwYXNz", "Bearer ", "Token abc"],
)
async def test_invalid_authentication_remains_401(client, header):
    async with client:
        res = await client.get("/rbac/any-day2-role", headers={"Authorization": header})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_token_signed_with_wrong_secret_remains_401(client):
    forged = create_access_token(
        user_id="u-admin",
        tenant_id=TENANT_A,
        role="TENANT_ADMIN",
        settings=Settings(APP_ENV="test", JWT_SECRET="attacker-controlled-secret-that-is-long-enough-123"),
    )
    async with client:
        res = await client.get("/rbac/admin", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("user_id", ["u-revoked-admin", "u-inactive-admin"])
async def test_inactive_or_revoked_membership_remains_rejected(client, user_id):
    async with client:
        res = await client.get("/rbac/admin", headers=auth(user_id))
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


# ---------------------------------------------------------------------------
# D. Tenant isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_role_in_tenant_a_does_not_grant_role_in_tenant_b(client):
    async with client:
        # u-multi is TENANT_ADMIN in A but only SECURITY_ANALYST in B.
        res_a = await client.get("/rbac/admin", headers=auth("u-multi", tenant_id=TENANT_A))
        res_b = await client.get("/rbac/admin", headers=auth("u-multi", tenant_id=TENANT_B, role_claim="TENANT_ADMIN"))
    assert res_a.status_code == 200
    assert res_a.json()["tenant_id"] == TENANT_A
    assert_forbidden(res_b)


@pytest.mark.asyncio
async def test_user_without_membership_in_tenant_cannot_use_its_context(client):
    async with client:
        # u-admin has no membership in B; a token naming B must be rejected by M1.
        res = await client.get("/rbac/admin", headers=auth("u-admin", tenant_id=TENANT_B, role_claim="TENANT_ADMIN"))
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_client_supplied_tenant_header_cannot_override_authenticated_tenant(client):
    async with client:
        res = await client.get("/rbac/admin", headers=auth("u-admin", **{"X-Tenant-ID": TENANT_B}))
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


@pytest.mark.asyncio
async def test_matching_tenant_header_is_accepted(client):
    async with client:
        res = await client.get("/rbac/admin", headers=auth("u-admin", **{"X-Tenant-ID": TENANT_A}))
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_admin_cannot_access_another_tenants_resource(client):
    async with client:
        own = await client.get(f"/rbac/tenants/{TENANT_A}/settings", headers=auth("u-admin"))
        other = await client.get(f"/rbac/tenants/{TENANT_B}/settings", headers=auth("u-admin"))
        other_admin_b = await client.get(f"/rbac/tenants/{TENANT_A}/settings", headers=auth("u-admin-b", tenant_id=TENANT_B))
    assert own.status_code == 200
    assert_forbidden(other)
    assert_forbidden(other_admin_b)


@pytest.mark.asyncio
async def test_concurrent_requests_do_not_leak_context_across_tenants():
    app = build_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        calls = []
        for i in range(30):
            if i % 3 == 0:
                calls.append(c.get("/rbac/admin", headers=auth("u-admin", tenant_id=TENANT_A)))
            elif i % 3 == 1:
                calls.append(c.get("/rbac/admin", headers=auth("u-admin-b", tenant_id=TENANT_B)))
            else:
                calls.append(c.get("/rbac/admin", headers=auth("u-analyst", tenant_id=TENANT_A)))
        results = await asyncio.gather(*calls)
    for i, res in enumerate(results):
        if i % 3 == 0:
            assert res.status_code == 200 and res.json()["tenant_id"] == TENANT_A
        elif i % 3 == 1:
            assert res.status_code == 200 and res.json()["tenant_id"] == TENANT_B
        else:
            assert res.status_code == 403


# ---------------------------------------------------------------------------
# F. Fail-closed when dependencies fail
# ---------------------------------------------------------------------------

class _FailingMembershipRepo(InMemoryAuthRepository):
    async def get_membership(self, user_id: str, tenant_id: str):
        raise ConnectionError("simulated database outage")


class _FailingUserRepo(InMemoryAuthRepository):
    async def get_user_by_id(self, user_id: str):
        raise TimeoutError("simulated timeout")


@pytest.mark.asyncio
@pytest.mark.parametrize("repo_cls", [_FailingMembershipRepo, _FailingUserRepo])
async def test_auth_repository_failure_fails_closed(repo_cls):
    failing = repo_cls()
    seed = build_repo()
    failing.users, failing.tenants, failing.memberships = seed.users, seed.tenants, seed.memberships
    transport = httpx.ASGITransport(app=build_app(repo=failing))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/rbac/admin", headers=auth("u-admin"))
    assert res.status_code == 503
    assert res.json()["error"]["code"] == "SECURITY_DEPENDENCY_UNAVAILABLE"
    assert "simulated" not in res.text


@pytest.mark.asyncio
async def test_unexpected_evaluator_error_returns_403_not_success(monkeypatch):
    from backend.app.security import authorization as authz

    def boom(_role):
        raise RuntimeError("simulated evaluator fault")

    monkeypatch.setattr(authz, "_classify_role", boom)
    transport = httpx.ASGITransport(app=build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/rbac/admin", headers=auth("u-admin"))
    assert_forbidden(res)
    assert "simulated" not in res.text


def test_route_with_missing_authorization_configuration_cannot_be_defined():
    app = FastAPI()
    with pytest.raises(ValueError):

        @app.get("/misconfigured")
        async def misconfigured(ctx: TenantContext = Depends(require_role_access())):
            return {}
