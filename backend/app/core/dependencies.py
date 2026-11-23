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
from typing import Annotated, Any, Callable, Dict, List, Optional, Protocol
from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import ForbiddenError, SecurityDependencyError
from backend.app.tenancy.context import (
    AuthRepositoryProtocol,
    TenantContext,
    UserRecord,
    get_default_auth_repository,
    resolve_tenant_context_from_request,
)

# Canonical Bearer authentication security scheme for OpenAPI documentation.
# auto_error=False ensures FastAPI does not bypass custom exception handlers or envelopes.
bearer_security_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="Standard Bearer JWT authentication header: 'Authorization: Bearer <token>'",
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

    session_factory = getattr(request.app.state, "db_session_factory", None)
    if session_factory is not None and (
        settings.AUTH_BACKEND == "database"
        or settings.APP_ENV == "production"
        or not settings.ALLOW_IN_MEMORY_AUTH
    ):
        from backend.app.database.repositories.auth import DatabaseAuthRepository
        db_repo = DatabaseAuthRepository(session_factory)
        request.app.state.auth_repo = db_repo
        return db_repo

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
    _bearer_cred: Annotated[Optional[HTTPAuthorizationCredentials], Security(bearer_security_scheme)] = None,
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
    """Protocol interface defining the rate limiter contract for AMSC endpoints (GAP-006).

    M7 provides the distributed Redis-backed sliding-window implementation.
    """
    backend: str
    is_in_memory: bool
    is_persistent: bool

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> RateLimitResult:
        ...

    async def ping(self) -> bool:
        ...

    async def reset(self, key: str) -> None:
        ...


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter for unit testing and local development.

    Serves as the documented interface boundary until M7 provisions the Redis rate limiter.
    """
    backend: str = "in_memory"
    is_in_memory: bool = True
    is_persistent: bool = False

    def __init__(self) -> None:
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.is_available: bool = True

    async def ping(self) -> bool:
        return self.is_available

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

    async def reset(self, key: str) -> None:
        """Reset the rate limit counter for a specific key (GAP-009)."""
        if key in self.requests:
            del self.requests[key]


# Lua script for atomic distributed sliding-window rate limiting in Redis (GAP-006 / GAP-037)
REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_req = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local current_count = redis.call('ZCARD', key)
if current_count < max_req then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return {1, max_req - current_count - 1, 0}
else
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if oldest and #oldest >= 2 then
        retry_after = math.max(1, math.ceil(window - (now - tonumber(oldest[2]))))
    end
    return {0, 0, retry_after}
end
"""


class RedisRateLimiter:
    """Approved distributed Redis sliding-window rate limiter (M7 integration contract / GAP-006).

    Enforces backend identity 'redis', persistence contract, distributed sliding-window counters,
    and safe connectivity verification.
    """
    backend: str = "redis"
    is_in_memory: bool = False
    is_persistent: bool = True

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        failure_policy: str = "fail_closed",
    ) -> None:
        self.redis_client = redis_client
        self.failure_policy = failure_policy
        self.is_available: bool = True
        # Local state fallback for mock testing when no redis_client is supplied
        self._counters: Dict[str, List[float]] = defaultdict(list)

    async def ping(self) -> bool:
        """Verify Redis connectivity without exposing credentials or internal errors."""
        if not self.is_available:
            return False
        if self.redis_client is not None:
            try:
                ping_fn = getattr(self.redis_client, "ping", None)
                if ping_fn:
                    res = ping_fn()
                    import asyncio
                    if asyncio.iscoroutine(res):
                        return bool(await res)
                    return bool(res)
            except Exception:
                return False
        return self.is_available

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> RateLimitResult:
        """Atomic sliding-window rate limit evaluation."""
        if not self.is_available:
            raise SecurityDependencyError("Rate limiting service unavailable.")

        now = time.time()

        # If real Redis client is configured, execute atomic distributed sliding-window Lua script
        if self.redis_client is not None:
            try:
                import asyncio
                import inspect
                import uuid
                member = f"{now}:{uuid.uuid4().hex[:8]}"

                eval_fn = getattr(self.redis_client, "eval", None)
                if eval_fn is not None:
                    res = eval_fn(
                        REDIS_SLIDING_WINDOW_LUA,
                        1,
                        key,
                        str(now),
                        str(window_seconds),
                        str(max_requests),
                        member,
                    )
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        res = await res
                    allowed_val, remaining_val, retry_after_val = res
                    if int(allowed_val) == 1:
                        return RateLimitResult(
                            allowed=True,
                            remaining=max(0, int(remaining_val)),
                            retry_after=None,
                            detail=None,
                        )
                    else:
                        return RateLimitResult(
                            allowed=False,
                            remaining=0,
                            retry_after=max(1, int(retry_after_val)),
                            detail="Rate limit exceeded.",
                        )
            except SecurityDependencyError:
                raise
            except Exception as exc:
                if self.failure_policy == "fail_closed":
                    raise SecurityDependencyError("Rate limiting service unavailable.") from exc
                return RateLimitResult(allowed=True, remaining=max_requests, retry_after=None)

        # In-memory local fallback for tests where redis_client is None
        cutoff = now - window_seconds
        self._counters[key] = [t for t in self._counters[key] if t > cutoff]

        if len(self._counters[key]) >= max_requests:
            earliest = self._counters[key][0]
            retry_after = max(1, int(window_seconds - (now - earliest)))
            return RateLimitResult(
                allowed=False,
                retry_after=retry_after,
                remaining=0,
                detail="Rate limit exceeded.",
            )

        self._counters[key].append(now)
        remaining = max_requests - len(self._counters[key])
        return RateLimitResult(
            allowed=True,
            retry_after=None,
            remaining=remaining,
            detail=None,
        )

    async def reset(self, key: str) -> None:
        """Reset the rate limit counter for a specific key (GAP-009)."""
        if key in self._counters:
            del self._counters[key]
        if self.redis_client is not None:
            try:
                delete_fn = getattr(self.redis_client, "delete", None)
                if delete_fn:
                    res = delete_fn(key)
                    import asyncio
                    import inspect
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        await res
            except Exception:
                pass


_default_rate_limiter: Optional[RateLimiterProtocol] = None


def get_default_rate_limiter(settings: Optional[Settings] = None) -> RateLimiterProtocol:
    """Factory returning the default rate limiter for dev/test."""
    global _default_rate_limiter
    cfg = settings or get_settings()
    if cfg.APP_ENV == "production":
        raise RuntimeError(
            "Security violation: In-memory rate limiter cannot be accessed in production."
        )
    if not getattr(cfg, "ALLOW_IN_MEMORY_RATE_LIMITER", False):
        raise RuntimeError(
            "Security violation: In-memory rate limiter is disabled by configuration."
        )
    if _default_rate_limiter is None:
        _default_rate_limiter = InMemoryRateLimiter()
    return _default_rate_limiter


def set_default_rate_limiter(limiter: Optional[RateLimiterProtocol]) -> None:
    global _default_rate_limiter
    _default_rate_limiter = limiter


async def get_rate_limiter(
    request: Request,
    settings: SettingsDep,
) -> RateLimiterProtocol:
    """Dependency returning the configured rate limiter (M7 Redis rate limiter in production).

    Strictly fails closed if Redis rate limiter is missing in production.
    """
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is not None:
        if settings.APP_ENV == "production":
            if getattr(limiter, "is_in_memory", False) or getattr(limiter, "backend", "") != "redis":
                raise SecurityDependencyError("In-memory or unapproved rate limiters are strictly forbidden in production.")
            if not getattr(limiter, "is_persistent", False):
                raise SecurityDependencyError("Non-persistent rate limiters are strictly forbidden in production.")
        return limiter

    if (
        settings.APP_ENV == "production"
        or not getattr(settings, "ALLOW_IN_MEMORY_RATE_LIMITER", False)
        or getattr(settings, "RATE_LIMITER_BACKEND", "") != "in_memory"
    ):
        raise SecurityDependencyError("Redis-backed rate limiting service is not configured.")

    return get_default_rate_limiter(settings)


RateLimiterDep = Annotated[RateLimiterProtocol, Depends(get_rate_limiter)]
