"""Tenancy Subsystem Package.

Module: backend.app.tenancy
Owner: M1 (Request Handling & Context) + M6 (DB Constraints & Repositories)
"""

from backend.app.tenancy.context import (
    AuthRepositoryProtocol,
    InMemoryAuthRepository,
    MembershipRecord,
    TenantContext,
    TenantRecord,
    UserRecord,
    get_default_auth_repository,
    resolve_tenant_context_from_request,
    set_default_auth_repository,
)

__all__ = [
    "TenantContext",
    "UserRecord",
    "TenantRecord",
    "MembershipRecord",
    "AuthRepositoryProtocol",
    "InMemoryAuthRepository",
    "resolve_tenant_context_from_request",
    "get_default_auth_repository",
    "set_default_auth_repository",
]
