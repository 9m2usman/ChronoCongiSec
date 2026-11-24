"""AMSC API Application Entry Point.

Module: backend.app.main
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002: Combined TRD & SRS
- AMSC-DOC-005: Backend Database Schema & API Contract
- AMSC-DOC-006: Seven-Person Implementation Plan (Day 1 Deliverable)
"""

import hashlib
import re
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Tuple
from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.app.api.admin import router as admin_router
from backend.app.api.agents import router as agents_router
from backend.app.api.audit import router as audit_router
from backend.app.api.auth import router as auth_router
from backend.app.api.baseline import router as baseline_router
from backend.app.api.branches import router as branches_router
from backend.app.api.chronimem import router as chronimem_router
from backend.app.api.detection import router as detection_router
from backend.app.api.drift import router as drift_router
from backend.app.api.gateway import router as gateway_router
from backend.app.api.incident_management import (
    memory_quarantine_router,
    router as incident_router,
)
from backend.app.api.knowledge import router as knowledge_router
from backend.app.api.memory import router as memory_router
from backend.app.api.observation import router as observation_router
from backend.app.api.recovery import router as recovery_router
from backend.app.api.tenants import router as tenants_router
from backend.app.api.traces import router as traces_router
from backend.app.core.config import Settings, get_settings
from backend.app.core.dependencies import InMemoryRateLimiter
from backend.app.core.exceptions import API_ERROR_RESPONSES, register_exception_handlers
from backend.app.core.logging import setup_logging


# --- Response Schemas ---

class HealthResponse(BaseModel):
    """Canonical health check response model."""

    status: str = Field(default="healthy", description="Application service status")
    service: str = Field(default="amsc-api", description="Service identifier")


class ReadinessResponse(BaseModel):
    """Canonical service readiness probe response model (GAP-006 / Finding N)."""

    status: str = Field(default="ready", description="Application readiness status")
    service: str = Field(default="amsc-api", description="Service identifier")
    dependencies: dict[str, str] = Field(default_factory=dict, description="Component dependency status")


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
        raw_traceparent = request.headers.get("traceparent")

        w3c_trace_id = None
        if raw_traceparent:
            tp_match = re.match(
                r"^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$",
                raw_traceparent.strip(),
            )
            if tp_match:
                extracted_tid = tp_match.group(1).lower()
                extracted_pid = tp_match.group(2).lower()
                # W3C Trace Context spec: all-zeros trace_id or parent_id are invalid
                if extracted_tid != "0" * 32 and extracted_pid != "0" * 16:
                    w3c_trace_id = extracted_tid

        if not raw_trace_id and w3c_trace_id:
            raw_trace_id = w3c_trace_id

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
            if w3c_trace_id and trace_id == w3c_trace_id and raw_traceparent:
                response.headers["traceparent"] = raw_traceparent.strip()
            else:
                if re.fullmatch(r"[0-9a-fA-F]{32}", trace_id):
                    canonical_tid = trace_id.lower()
                else:
                    canonical_tid = hashlib.sha256(trace_id.encode("utf-8")).hexdigest()[:32]
                span_id = uuid.uuid4().hex[:16]
                response.headers["traceparent"] = f"00-{canonical_tid}-{span_id}-01"
        if safe_corr_id:
            response.headers["X-Correlation-ID"] = safe_corr_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Standard baseline HTTP security headers for all API responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"

        path = request.url.path
        if path.startswith("/api/") or path.startswith("/auth"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
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

    # Database engine and session factory initialization
    db_url = getattr(settings, "DATABASE_URL", None)
    if not hasattr(app.state, "db_session_factory") or app.state.db_session_factory is None:
        if db_url and db_url.startswith("postgresql+asyncpg://"):
            try:
                from backend.app.database.session import create_engine, create_session_factory
                engine = create_engine(db_url)
                # In development mode, verify connectivity to avoid background connection stalls if DB is offline
                if settings.APP_ENV != "production":
                    import asyncio
                    from sqlalchemy import text
                    async def _test_conn() -> None:
                        async with engine.connect() as conn:
                            await conn.execute(text("SELECT 1"))
                    await asyncio.wait_for(_test_conn(), timeout=1.0)
                app.state.db_engine = engine
                app.state.db_session_factory = create_session_factory(engine)
                logger.info("Initialized PostgreSQL async engine and session factory.")
            except Exception as exc:
                if settings.APP_ENV == "production":
                    raise RuntimeError(f"Production database initialization failed: {exc}")
                logger.info(
                    f"PostgreSQL at {db_url} is not running or unreachable ({exc}). "
                    "Operating in in-memory development mode without background connection delays."
                )
                app.state.db_engine = None
                app.state.db_session_factory = None

    # Wire persistent repositories when session factory is configured
    session_factory = getattr(app.state, "db_session_factory", None)
    if session_factory is not None:
        auth_repo = getattr(app.state, "auth_repo", None)
        if auth_repo is None or getattr(auth_repo, "is_demo", False):
            from backend.app.database.repositories.auth import DatabaseAuthRepository
            app.state.auth_repo = DatabaseAuthRepository(session_factory)

        if getattr(app.state, "agent_repo", None) is None:
            from backend.app.database.repositories.agents import SqlAlchemyAgentRepository
            app.state.agent_repo = SqlAlchemyAgentRepository(session_factory)

        if getattr(app.state, "memory_repo", None) is None:
            from backend.app.memory.adapters import DatabaseMemoryRepository
            app.state.memory_repo = DatabaseMemoryRepository(session_factory)

        if getattr(app.state, "gateway_repo", None) is None:
            from backend.app.api.gateway import SqlAlchemyGatewayRepository
            app.state.gateway_repo = SqlAlchemyGatewayRepository(session_factory)

        if getattr(app.state, "incident_repo", None) is None:
            from backend.app.api.incident_management import SqlAlchemyIncidentRepository
            app.state.incident_repo = SqlAlchemyIncidentRepository(session_factory)

        if getattr(app.state, "trace_repo", None) is None:
            from backend.app.api.traces import SqlAlchemyTraceRepository
            app.state.trace_repo = SqlAlchemyTraceRepository(session_factory)

        if getattr(app.state, "baseline_repo", None) is None:
            from backend.app.database.repositories.baseline import SqlAlchemyBaselineRepository
            app.state.baseline_repo = SqlAlchemyBaselineRepository(session_factory)

        if getattr(app.state, "observation_repo", None) is None:
            from backend.app.database.repositories.observation import SqlAlchemyObservationRepository
            app.state.observation_repo = SqlAlchemyObservationRepository(session_factory)

        if getattr(app.state, "drift_service", None) is None:
            from backend.app.security.drift import DriftReviewService, SqlDriftReviewStore
            app.state.drift_service = DriftReviewService(SqlDriftReviewStore(session_factory))

        if getattr(app.state, "outbox_processor", None) is None:
            from backend.app.workers.outbox import OutboxProcessor
            app.state.outbox_processor = OutboxProcessor(session_factory)

    # Production startup validation: Enforce real database repositories and Redis rate limiter configuration
    if settings.APP_ENV == "production":
        auth_repo = getattr(app.state, "auth_repo", None)
        if auth_repo is None or getattr(auth_repo, "is_demo", False):
            raise RuntimeError(
                "Production startup failure: Real database authentication repository is not configured. "
                "In-memory demo authentication is strictly forbidden in production."
            )

        rate_limiter = getattr(app.state, "rate_limiter", None)
        if (
            rate_limiter is None
            or getattr(rate_limiter, "is_in_memory", False)
            or (hasattr(rate_limiter, "backend") and rate_limiter.backend != "redis")
            or not getattr(rate_limiter, "is_persistent", True)
        ):
            raise RuntimeError(
                "Production startup failure: Redis-backed rate limiter is not configured. "
                "In-memory rate limiting and unapproved rate limiters are strictly forbidden in production."
            )

        if hasattr(rate_limiter, "ping"):
            try:
                ping_res = rate_limiter.ping()
                import inspect
                if inspect.isawaitable(ping_res):
                    is_ready = await ping_res
                else:
                    is_ready = bool(ping_res)
                if not is_ready:
                    raise RuntimeError("Redis rate limiter readiness ping returned false.")
            except Exception:
                raise RuntimeError(
                    "Production startup failure: Redis-backed rate limiter is unreachable or not ready."
                )

        memory_repo = getattr(app.state, "memory_repo", None)
        if (
            memory_repo is None
            or getattr(memory_repo, "is_in_memory", True)
            or not getattr(memory_repo, "is_persistent", False)
        ):
            raise RuntimeError(
                "Production startup failure: Persistent database memory repository from M6 is not configured. "
                "In-memory memory repository is strictly forbidden in production."
            )

        agent_repo = getattr(app.state, "agent_repo", None)
        if agent_repo is not None and (
            getattr(agent_repo, "is_in_memory", True)
            or not getattr(agent_repo, "is_persistent", False)
        ):
            raise RuntimeError(
                "Production startup failure: Persistent database agent repository from M6 is not configured. "
                "In-memory agent repository is strictly forbidden in production."
            )

        gateway_repo = getattr(app.state, "gateway_repo", None)
        if gateway_repo is not None and (
            getattr(gateway_repo, "is_in_memory", True)
            or not getattr(gateway_repo, "is_persistent", False)
        ):
            raise RuntimeError(
                "Production startup failure: Persistent database gateway repository from M6 is not configured. "
                "In-memory gateway repository is strictly forbidden in production."
            )

        incident_repo = getattr(app.state, "incident_repo", None)
        if incident_repo is not None and (
            getattr(incident_repo, "is_in_memory", True)
            or not getattr(incident_repo, "is_persistent", False)
        ):
            raise RuntimeError(
                "Production startup failure: Persistent database incident repository from M6 is not configured. "
                "In-memory incident repository is strictly forbidden in production."
            )

        trace_repo = getattr(app.state, "trace_repo", None)
        if trace_repo is not None and (
            getattr(trace_repo, "is_in_memory", True)
            or not getattr(trace_repo, "is_persistent", False)
        ):
            raise RuntimeError(
                "Production startup failure: Persistent database trace repository from M6 is not configured. "
                "In-memory trace repository is strictly forbidden in production."
            )

    # Construct services that depend on validated production repositories only after
    # the production guards have rejected any in-memory or missing persistence layer.
    if getattr(app.state, "recovery_service", None) is None:
        if session_factory is not None:
            from backend.app.recovery.store import create_recovery_service
            app.state.recovery_service = create_recovery_service(
                session_factory,
                memory_repo=getattr(app.state, "memory_repo", None),
                trust_evaluator=getattr(app.state, "trust_evaluator", None),
            )
        elif settings.APP_ENV != "production":
            from backend.app.recovery.store import create_in_memory_recovery_service
            app.state.recovery_service = create_in_memory_recovery_service(
                memory_repo=getattr(app.state, "memory_repo", None),
                trust_evaluator=getattr(app.state, "trust_evaluator", None),
            )

    yield
    from backend.app.core.security import shutdown_auth_executor
    shutdown_auth_executor()
    logger.info(f"Shutting down {settings.APP_NAME}")


# --- Application Factory ---

def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    if settings is None:
        settings = get_settings()

    # Production Documentation Policy:
    # Disable interactive Swagger UI and ReDoc in production by default unless explicitly enabled
    protect_docs = (
        settings.APP_ENV == "production"
        and getattr(settings, "ENABLE_DOCS_IN_PRODUCTION", False)
        and getattr(settings, "PROTECT_DOCS_IN_PRODUCTION", False)
    )
    docs_url = settings.DOCS_URL if (settings.APP_ENV != "production" or (getattr(settings, "ENABLE_DOCS_IN_PRODUCTION", False) and not protect_docs)) else None
    redoc_url = settings.REDOC_URL if (settings.APP_ENV != "production" or (getattr(settings, "ENABLE_DOCS_IN_PRODUCTION", False) and not protect_docs)) else None

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        openapi_url=settings.OPENAPI_URL,
        docs_url=docs_url,
        redoc_url=redoc_url,
        responses=API_ERROR_RESPONSES,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Revocation store initialization (GAP-007)
    if settings.APP_ENV != "production":
        from backend.app.core.security import get_default_revocation_store
        app.state.revocation_store = get_default_revocation_store()
    else:
        app.state.revocation_store = getattr(app.state, "revocation_store", None)

    # In development and test, initialize safe in-memory rate limiter if permitted
    if settings.APP_ENV != "production" and getattr(settings, "ALLOW_IN_MEMORY_RATE_LIMITER", False):
        app.state.rate_limiter = InMemoryRateLimiter()
    else:
        app.state.rate_limiter = None

    # Memory repository initialization: auto-attach in-memory repository for dev/test only
    if settings.APP_ENV != "production":
        from backend.app.memory.repository import get_default_repository, seed_enterprise_demo_memories
        app.state.memory_repo = get_default_repository()
        seed_enterprise_demo_memories(app.state.memory_repo)
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.memory.adapters import DatabaseMemoryRepository
            app.state.memory_repo = DatabaseMemoryRepository(session_factory)
        else:
            app.state.memory_repo = None

    # Agent repository initialization: auto-attach in-memory repository for dev/test only
    if settings.APP_ENV != "production":
        from backend.app.api.agents import get_default_agent_repository
        app.state.agent_repo = get_default_agent_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.database.repositories.agents import SqlAlchemyAgentRepository
            app.state.agent_repo = SqlAlchemyAgentRepository(session_factory)
        else:
            app.state.agent_repo = None

    # Gateway repository initialization: auto-attach in-memory repository for dev/test only
    if settings.APP_ENV != "production":
        from backend.app.api.gateway import get_default_gateway_repository
        app.state.gateway_repo = get_default_gateway_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.api.gateway import SqlAlchemyGatewayRepository
            app.state.gateway_repo = SqlAlchemyGatewayRepository(session_factory)
        else:
            app.state.gateway_repo = None

    # Incident repository initialization: auto-attach in-memory repository for dev/test only
    if settings.APP_ENV != "production":
        from backend.app.api.incident_management import get_default_incident_repository
        app.state.incident_repo = get_default_incident_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.api.incident_management import SqlAlchemyIncidentRepository
            app.state.incident_repo = SqlAlchemyIncidentRepository(session_factory)
        else:
            app.state.incident_repo = None

    # Traces repository initialization: auto-attach in-memory repository for dev/test only
    if settings.APP_ENV != "production":
        from backend.app.api.traces import get_default_trace_repository
        app.state.trace_repo = get_default_trace_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.api.traces import SqlAlchemyTraceRepository
            app.state.trace_repo = SqlAlchemyTraceRepository(session_factory)
        else:
            app.state.trace_repo = None

    # Baseline repository initialization (Phase 1 §2)
    if settings.APP_ENV != "production":
        from backend.app.api.baseline import get_default_baseline_repository
        app.state.baseline_repo = get_default_baseline_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.database.repositories.baseline import SqlAlchemyBaselineRepository
            app.state.baseline_repo = SqlAlchemyBaselineRepository(session_factory)
        else:
            app.state.baseline_repo = None

    # Observation repository initialization (Phase 1 §3 & §4)
    if settings.APP_ENV != "production":
        from backend.app.api.observation import get_default_observation_repository
        app.state.observation_repo = get_default_observation_repository()
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.database.repositories.observation import SqlAlchemyObservationRepository
            app.state.observation_repo = SqlAlchemyObservationRepository(session_factory)
        else:
            app.state.observation_repo = None

    # Detection repository and engine initialization (Phase 2)
    if settings.APP_ENV != "production":
        from backend.app.database.repositories.detection import get_default_detection_repository
        from backend.app.security.detection import DetectionEngine
        app.state.detection_repo = get_default_detection_repository()
        app.state.detection_engine = DetectionEngine(
            detection_repo=app.state.detection_repo,
            baseline_repo=app.state.baseline_repo,
            agent_repo=app.state.agent_repo,
        )
    else:
        session_factory = getattr(app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.database.repositories.detection import SqlAlchemyDetectionRepository
            from backend.app.security.detection import DetectionEngine
            app.state.detection_repo = SqlAlchemyDetectionRepository(session_factory)
            app.state.detection_engine = DetectionEngine(
                detection_repo=app.state.detection_repo,
                baseline_repo=app.state.baseline_repo,
                agent_repo=app.state.agent_repo,
            )
        else:
            app.state.detection_repo = None
            app.state.detection_engine = None

    # Quarantine service initialization
    from backend.app.security.quarantine import get_default_quarantine_service
    app.state.quarantine_service = get_default_quarantine_service()

    # Recovery service initialization
    if getattr(app.state, "recovery_service", None) is None:
        if settings.APP_ENV != "production":
            from backend.app.recovery.store import create_in_memory_recovery_service
            app.state.recovery_service = create_in_memory_recovery_service(
                memory_repo=app.state.memory_repo,
                trust_evaluator=getattr(app.state, "trust_evaluator", None),
            )

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

    # 3. Register Baseline HTTP Security Headers Middleware (outermost to protect all responses including CORS preflight)
    app.add_middleware(SecurityHeadersMiddleware)

    # 4. Register Standard Exception Handlers
    register_exception_handlers(app)

    # 5. Core System Endpoints: Health & Readiness Probes
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

    async def evaluate_readiness(app_instance: FastAPI) -> Tuple[bool, Dict[str, str]]:
        cfg = getattr(app_instance.state, "settings", None) or get_settings()
        deps: Dict[str, str] = {}
        all_ready = True

        # Auth Repo Check
        auth_repo = getattr(app_instance.state, "auth_repo", None)
        if auth_repo is None:
            if cfg.APP_ENV == "production" or not cfg.ALLOW_IN_MEMORY_AUTH:
                deps["auth_repo"] = "unavailable"
                all_ready = False
            else:
                deps["auth_repo"] = "ready (dev/test)"
        else:
            deps["auth_repo"] = "ready"

        # Rate Limiter Check (GAP-006)
        limiter = getattr(app_instance.state, "rate_limiter", None)
        if limiter is None:
            if cfg.APP_ENV == "production":
                deps["rate_limiter"] = "unavailable"
                all_ready = False
            else:
                deps["rate_limiter"] = "ready (dev/test in-memory)"
        else:
            if hasattr(limiter, "ping"):
                try:
                    res = limiter.ping()
                    import asyncio
                    is_ready = await res if asyncio.iscoroutine(res) else bool(res)
                    if not is_ready:
                        deps["rate_limiter"] = "unreachable"
                        all_ready = False
                    else:
                        deps["rate_limiter"] = "ready"
                except Exception:
                    deps["rate_limiter"] = "unreachable"
                    all_ready = False
            else:
                deps["rate_limiter"] = "ready"

        # Memory Repo Check
        mem_repo = getattr(app_instance.state, "memory_repo", None)
        if mem_repo is None:
            if cfg.APP_ENV == "production":
                deps["memory_repo"] = "unavailable"
                all_ready = False
            else:
                deps["memory_repo"] = "ready (dev/test)"
        else:
            if cfg.APP_ENV == "production" and (
                getattr(mem_repo, "is_in_memory", True) or not getattr(mem_repo, "is_persistent", False)
            ):
                deps["memory_repo"] = "rejected (in-memory in production)"
                all_ready = False
            else:
                deps["memory_repo"] = "ready"

        # Agent Repo Check (Finding F & N)
        agent_repo = getattr(app_instance.state, "agent_repo", None)
        if agent_repo is None:
            if cfg.APP_ENV == "production":
                deps["agent_repo"] = "unavailable"
                all_ready = False
            else:
                deps["agent_repo"] = "ready (dev/test)"
        else:
            if cfg.APP_ENV == "production" and (
                getattr(agent_repo, "is_in_memory", True) or not getattr(agent_repo, "is_persistent", False)
            ):
                deps["agent_repo"] = "rejected (in-memory in production)"
                all_ready = False
            else:
                deps["agent_repo"] = "ready"

        # Trace Repo Check (Finding H & N)
        trace_repo = getattr(app_instance.state, "trace_repo", None)
        if trace_repo is None:
            if cfg.APP_ENV == "production":
                deps["trace_repo"] = "unavailable"
                all_ready = False
            else:
                deps["trace_repo"] = "ready (dev/test)"
        else:
            if cfg.APP_ENV == "production" and (
                getattr(trace_repo, "is_in_memory", True) or not getattr(trace_repo, "is_persistent", False)
            ):
                deps["trace_repo"] = "rejected (in-memory in production)"
                all_ready = False
            else:
                deps["trace_repo"] = "ready"

        # Incident Repo Check (Finding I & N)
        incident_repo = getattr(app_instance.state, "incident_repo", None)
        if incident_repo is None:
            if cfg.APP_ENV == "production":
                deps["incident_repo"] = "unavailable"
                all_ready = False
            else:
                deps["incident_repo"] = "ready (dev/test)"
        else:
            if cfg.APP_ENV == "production" and (
                getattr(incident_repo, "is_in_memory", True) or not getattr(incident_repo, "is_persistent", False)
            ):
                deps["incident_repo"] = "rejected (in-memory in production)"
                all_ready = False
            else:
                deps["incident_repo"] = "ready"

        # Revocation Store Check (GAP-007 / Finding B & N)
        rev_store = getattr(app_instance.state, "revocation_store", None)
        if rev_store is None:
            if cfg.APP_ENV == "production":
                deps["revocation_store"] = "unavailable"
                all_ready = False
            else:
                deps["revocation_store"] = "ready (dev/test in-memory)"
        else:
            deps["revocation_store"] = "ready"

        # Baseline Repo Check (Phase 1 §2)
        base_repo = getattr(app_instance.state, "baseline_repo", None)
        if base_repo is None:
            if cfg.APP_ENV == "production":
                deps["baseline_repo"] = "unavailable"
                all_ready = False
            else:
                deps["baseline_repo"] = "ready (dev/test in-memory)"
        else:
            deps["baseline_repo"] = "ready"

        # Observation Repo Check (Phase 1 §3 & §4)
        obs_repo = getattr(app_instance.state, "observation_repo", None)
        if obs_repo is None:
            if cfg.APP_ENV == "production":
                deps["observation_repo"] = "unavailable"
                all_ready = False
            else:
                deps["observation_repo"] = "ready (dev/test in-memory)"
        else:
            deps["observation_repo"] = "ready"

        # Detection Repo Check (Phase 2)
        det_repo = getattr(app_instance.state, "detection_repo", None)
        if det_repo is None:
            if cfg.APP_ENV == "production":
                deps["detection_repo"] = "unavailable"
                all_ready = False
            else:
                deps["detection_repo"] = "ready (dev/test in-memory)"
        else:
            deps["detection_repo"] = "ready"

        return all_ready, deps

    @app.get(
        "/ready",
        response_model=ReadinessResponse,
        summary="Service Readiness Probe",
        description="Verify service readiness and dependency health (database, Redis, memory).",
        tags=["Health"],
    )
    async def readiness_probe(request: Request) -> ReadinessResponse:
        """Process readiness probe asserting dependencies are available."""
        is_ready, deps = await evaluate_readiness(request.app)
        if not is_ready:
            from backend.app.core.exceptions import SecurityDependencyError
            raise SecurityDependencyError("Service dependencies are not ready.")
        return ReadinessResponse(status="ready", service="amsc-api", dependencies=deps)

    # Protected interactive documentation (Finding K / GAP-040)
    if protect_docs:
        from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
        from backend.app.core.dependencies import get_tenant_context
        from backend.app.tenancy.context import TenantContext

        @app.get("/docs", include_in_schema=False)
        async def protected_swagger_ui(
            context: TenantContext = Depends(get_tenant_context),
        ):
            return get_swagger_ui_html(
                openapi_url=settings.OPENAPI_URL,
                title=f"{settings.APP_NAME} - Swagger UI (Protected)",
            )

        @app.get("/redoc", include_in_schema=False)
        async def protected_redoc_ui(
            context: TenantContext = Depends(get_tenant_context),
        ):
            return get_redoc_html(
                openapi_url=settings.OPENAPI_URL,
                title=f"{settings.APP_NAME} - ReDoc (Protected)",
            )

    # 6. Versioned API Router Base with Standard Error Responses
    api_router = APIRouter(prefix=settings.API_PREFIX, responses=API_ERROR_RESPONSES)

    @api_router.get(
        "/health",
        response_model=HealthResponse,
        summary="Versioned Liveness Health Check",
        tags=["Health"],
    )
    async def versioned_health_check() -> HealthResponse:
        """Versioned route for health inspection."""
        return HealthResponse(status="healthy", service="amsc-api")

    @api_router.get(
        "/ready",
        response_model=ReadinessResponse,
        summary="Versioned Readiness Health Check",
        tags=["Health"],
    )
    async def versioned_readiness_check(request: Request) -> ReadinessResponse:
        """Versioned route for readiness inspection."""
        is_ready, deps = await evaluate_readiness(request.app)
        if not is_ready:
            from backend.app.core.exceptions import SecurityDependencyError
            raise SecurityDependencyError("Service dependencies are not ready.")
        return ReadinessResponse(status="ready", service="amsc-api", dependencies=deps)

    api_router.include_router(auth_router)
    api_router.include_router(branches_router)
    api_router.include_router(admin_router)
    api_router.include_router(tenants_router)
    api_router.include_router(agents_router)
    api_router.include_router(baseline_router)
    api_router.include_router(observation_router)
    api_router.include_router(detection_router)
    api_router.include_router(gateway_router)
    api_router.include_router(memory_router)
    api_router.include_router(incident_router)
    api_router.include_router(memory_quarantine_router)
    api_router.include_router(traces_router)
    api_router.include_router(drift_router)
    api_router.include_router(recovery_router)
    api_router.include_router(audit_router)
    api_router.include_router(chronimem_router)
    api_router.include_router(knowledge_router)

    app.include_router(api_router)

    return app


# Root application instance for ASGI servers (uvicorn backend.app.main:app)
app = create_app()

if __name__ == "__main__":
    import uvicorn
    from backend.app.core.config import get_settings

    settings = get_settings()
    # Reload behavior is explicitly development-only; production never runs with reload=True
    is_dev = settings.APP_ENV == "development"
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=is_dev)
