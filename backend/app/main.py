"""AMSC API Application Entry Point.

Module: backend.app.main
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002: Combined TRD & SRS
- AMSC-DOC-005: Backend Database Schema & API Contract
- AMSC-DOC-006: Seven-Person Implementation Plan (Day 1 Deliverable)
"""

import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.logging import setup_logging


# --- Response Schemas ---

class HealthResponse(BaseModel):
    """Canonical health check response model."""

    status: str = Field(default="healthy", description="Application service status")
    service: str = Field(default="amsc-api", description="Service identifier")


# --- Custom Middlewares ---

class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware to populate request_id and propagate tracing headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get("x-request-id") or request.headers.get("x-trace-id")
        request_id = incoming_id or f"req-{uuid.uuid4().hex[:12]}"

        # Bind to request state for downstream handlers and error formatting
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# --- Application Lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    settings = get_settings()
    logger = setup_logging(settings.LOG_LEVEL)
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}]"
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

    # 1. Register Context & Tracing Middleware
    app.add_middleware(RequestContextMiddleware)

    # 2. Configure CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
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

    app.include_router(api_router)

    return app


# Root application instance for ASGI servers (uvicorn backend.app.main:app)
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
