"""AMSC API Application Entry Point.

Module: backend.app.main
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002: Combined TRD & SRS
- AMSC-DOC-005: Backend Database Schema & API Contract
- AMSC-DOC-006: Seven-Person Implementation Plan (Day 1 Deliverable)
"""

import re
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.app.api.auth import router as auth_router
from backend.app.api.memory import router as memory_router
from backend.app.api.tenants import router as tenants_router
from backend.app.core.config import Settings, get_settings
from backend.app.core.dependencies import InMemoryRateLimiter
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.logging import setup_logging


# --- Response Schemas ---

class HealthResponse(BaseModel):
    """Canonical health check response model."""

    status: str = Field(default="healthy", description="Application service status")
    service: str = Field(default="amsc-api", description="Service identifier")


# Safe correlation ID pattern: alphanumeric, hyphen, underscore, period (max 128 chars)
SAFE_CORRELATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")


def sanitize_correlation_id(value: str | None) -> str | None:
    """Validate incoming correlation IDs to prevent log/header injection."""
    if not value:
        return None
    val = value.strip()
    if not val or len(val) > 128:
        return None
    if not SAFE_CORRELATION_ID_REGEX.match(val):
        return None
    return val


# --- Custom Middlewares ---

class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware to populate request_id and propagate tracing headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        raw_req_id = request.headers.get("x-request-id")
        raw_trace_id = request.headers.get("x-trace-id")
        raw_corr_id = request.headers.get("x-correlation-id")

        safe_req_id = sanitize_correlation_id(raw_req_id)
        safe_trace_id = sanitize_correlation_id(raw_trace_id)
        safe_corr_id = sanitize_correlation_id(raw_corr_id)

        request_id = safe_req_id or safe_trace_id or safe_corr_id or f"req-{uuid.uuid4().hex[:12]}"
        trace_id = safe_trace_id or safe_corr_id

        # Bind to request state for downstream handlers and error formatting
        request.state.request_id = request_id
        request.state.trace_id = trace_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        if trace_id:
            response.headers["X-Trace-ID"] = trace_id
        if safe_corr_id:
            response.headers["X-Correlation-ID"] = safe_corr_id
        return response


# --- Application Lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    settings = getattr(app.state, "settings", None) or get_settings()
    logger = setup_logging(settings.LOG_LEVEL)
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}]"
    )

    # Production startup validation: Enforce real database repository and Redis rate limiter configuration
    if settings.APP_ENV == "production":
        auth_repo = getattr(app.state, "auth_repo", None)
        if auth_repo is None or getattr(auth_repo, "is_demo", False):
            raise RuntimeError(
                "Production startup failure: Real database authentication repository is not configured. "
                "In-memory demo authentication is strictly forbidden in production."
            )

        rate_limiter = getattr(app.state, "rate_limiter", None)
        if rate_limiter is None or getattr(rate_limiter, "is_in_memory", False):
            raise RuntimeError(
                "Production startup failure: Redis-backed rate limiter is not configured. "
                "In-memory rate limiting is strictly forbidden in production."
            )

    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


# --- Application Factory ---

def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        openapi_url=settings.OPENAPI_URL,
        docs_url=settings.DOCS_URL,
        redoc_url=settings.REDOC_URL,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # In development and test, initialize safe in-memory rate limiter if permitted
    if settings.APP_ENV != "production" and getattr(settings, "ALLOW_IN_MEMORY_RATE_LIMITER", False):
        app.state.rate_limiter = InMemoryRateLimiter()
    else:
        app.state.rate_limiter = None

    # 1. Register Context & Tracing Middleware
    app.add_middleware(RequestContextMiddleware)

    # 2. Configure CORS Middleware with explicit settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOWED_METHODS,
        allow_headers=settings.CORS_ALLOWED_HEADERS,
        expose_headers=settings.CORS_EXPOSE_HEADERS,
    )

    # 3. Register Standard Exception Handlers
    register_exception_handlers(app)

    # 4. Core System Endpoints: Health Check
    @app.get(
        "/health",
        response_model=HealthResponse,
        summary="Service Liveness Health Check",
        description="Verify service process vitality. Returns HTTP 200 when backend is responsive.",
        tags=["Health"],
    )
    async def health_check() -> HealthResponse:
        """Process liveness probe."""
        return HealthResponse(status="healthy", service="amsc-api")

    # 5. Versioned API Router Base
    api_router = APIRouter(prefix=settings.API_PREFIX)

    @api_router.get(
        "/health",
        response_model=HealthResponse,
        summary="Versioned Liveness Health Check",
        tags=["Health"],
    )
    async def versioned_health_check() -> HealthResponse:
        """Versioned route for health inspection."""
        return HealthResponse(status="healthy", service="amsc-api")

    api_router.include_router(auth_router)
    api_router.include_router(tenants_router)
    api_router.include_router(memory_router)

    app.include_router(api_router)

    return app


# Root application instance for ASGI servers (uvicorn backend.app.main:app)
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
