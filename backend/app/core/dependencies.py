"""Shared FastAPI Dependencies and Context Providers.

Module: backend.app.core.dependencies
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 Section 5: Security Architecture
- AMSC-DOC-005 Section 5: API Conventions
- Master Implementation Specification: M1 Day 2 Authentication & Tenant Context
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Annotated, Callable, Dict, List, Optional, Protocol
from fastapi import Depends, Request

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import ForbiddenError, SecurityDependencyError
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

async def get_auth_repo(
    request: Request,
    settings: SettingsDep,
) -> AuthRepositoryProtocol:
    """Dependency providing the Auth repository interface.

    Allows clean swapping/overriding in tests or when M6 supplies SQLAlchemy models.
    In production, strictly requires a real repository; in-memory demo authentication is forbidden.
    """
    repo = getattr(request.app.state, "auth_repo", None)
    if repo is not None:
        return repo

    if (
        settings.APP_ENV == "production"
        or not settings.ALLOW_IN_MEMORY_AUTH
        or settings.AUTH_BACKEND != "in_memory_demo"
    ):
        raise SecurityDependencyError("Authentication database repository is not configured.")

    return get_default_auth_repository(settings)


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


# --- 6. Rate Limiting Integration Boundary (For M7 Redis Rate Limiter) ---

@dataclass(frozen=True)
class RateLimitResult:
    """Standard rate limit check result."""
    allowed: bool
    retry_after: Optional[int] = None
    remaining: Optional[int] = None
    detail: Optional[str] = None


class RateLimiterProtocol(Protocol):
    """Protocol interface defining the rate limiter contract for AMSC endpoints.

    M7 provides the distributed Redis-backed sliding-window implementation.
    """
    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> RateLimitResult:
        ...


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter for unit testing and local development.

    Serves as the documented interface boundary until M7 provisions the Redis rate limiter.
    """
    def __init__(self) -> None:
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.is_available: bool = True

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> RateLimitResult:
        if not self.is_available:
            raise SecurityDependencyError("Rate limiting service unavailable.")

        now = time.time()
        cutoff = now - window_seconds
        # Evict timestamps outside the sliding window
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]

        if len(self.requests[key]) >= max_requests:
            earliest = self.requests[key][0]
            retry_after = max(1, int(window_seconds - (now - earliest)))
            return RateLimitResult(
                allowed=False,
                retry_after=retry_after,
                remaining=0,
                detail="Rate limit exceeded.",
            )

        self.requests[key].append(now)
        remaining = max_requests - len(self.requests[key])
        return RateLimitResult(
            allowed=True,
            retry_after=None,
            remaining=remaining,
            detail=None,
        )


_default_rate_limiter: Optional[RateLimiterProtocol] = None


def get_default_rate_limiter() -> RateLimiterProtocol:
    global _default_rate_limiter
    if _default_rate_limiter is None:
        _default_rate_limiter = InMemoryRateLimiter()
    return _default_rate_limiter


def set_default_rate_limiter(limiter: Optional[RateLimiterProtocol]) -> None:
    global _default_rate_limiter
    _default_rate_limiter = limiter


async def get_rate_limiter(request: Request) -> RateLimiterProtocol:
    """Dependency returning the configured rate limiter (M7 Redis rate limiter when available)."""
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is not None:
        return limiter
    return get_default_rate_limiter()


RateLimiterDep = Annotated[RateLimiterProtocol, Depends(get_rate_limiter)]
