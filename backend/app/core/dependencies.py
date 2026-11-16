"""Shared FastAPI Dependencies and Context Providers.

Module: backend.app.core.dependencies
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 5: Security Architecture
- AMSC-DOC-005 Section 5: API Conventions
- Master Implementation Specification: M1 Day 2 Authentication & Tenant Context
"""

from typing import Annotated, Callable, List, Optional
from fastapi import Depends, Request

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import ForbiddenError
from backend.app.tenancy.context import (
    AuthRepositoryProtocol,
    TenantContext,
    UserRecord,
    get_default_auth_repository,
    resolve_tenant_context_from_request,
)


# --- 1. Settings Dependency ---

async def get_app_settings(request: Request) -> Settings:
    """Dependency that returns the current application settings consistently from app.state."""
    return getattr(request.app.state, "settings", None) or get_settings()


SettingsDep = Annotated[Settings, Depends(get_app_settings)]


# --- 2. Database / Auth Repository Boundary (Coordinated with M6) ---

async def get_auth_repo() -> AuthRepositoryProtocol:
    """Dependency providing the Auth repository interface.

    Allows clean swapping/overriding in tests or when M6 supplies SQLAlchemy models.
    """
    return get_default_auth_repository()


AuthRepoDep = Annotated[AuthRepositoryProtocol, Depends(get_auth_repo)]


# --- 3. Request-Scoped Tenant Context Dependency ---

async def get_tenant_context(
    request: Request,
    repo: AuthRepoDep,
) -> TenantContext:
    """FastAPI dependency to extract and assert verified TenantContext for protected endpoints.

    Caches the immutable context on request.state to ensure request-scoped execution
    and zero cross-request leakage.
    """
    cached_context: Optional[TenantContext] = getattr(request.state, "tenant_context", None)
    if cached_context is not None:
        return cached_context

    context = await resolve_tenant_context_from_request(request, repo=repo)
    request.state.tenant_context = context
    return context


TenantContextDep = Annotated[TenantContext, Depends(get_tenant_context)]


# --- 4. Authenticated User Dependency ---

async def get_current_user(
    context: TenantContextDep,
    repo: AuthRepoDep,
) -> UserRecord:
    """Dependency providing the trusted UserRecord for the authenticated caller."""
    user = await repo.get_user_by_id(context.user_id)
    if not user:
        raise ForbiddenError("Authenticated user record unavailable.")
    return user


CurrentUserDep = Annotated[UserRecord, Depends(get_current_user)]


# --- 5. Authorization Integration Boundary (For M4 RBAC Evaluator) ---

def require_roles(*allowed_roles: str) -> Callable[[TenantContext], TenantContext]:
    """Dependency factory enforcing membership role requirements.

    Provides a clean, documented handoff boundary for M4's Policy & RBAC engine.
    """
    async def role_checker(
        context: TenantContext = Depends(get_tenant_context),
    ) -> TenantContext:
        if allowed_roles and context.role not in allowed_roles:
            raise ForbiddenError(
                f"Role '{context.role}' lacks permission for this resource. Required: {list(allowed_roles)}"
            )
        return context

    return role_checker
