"""Centralized Application Configuration.

Module: backend.app.core.config
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Backend Technology Stack
- AMSC-DOC-005 (Database & API Schema) Section 5: API Conventions
- Master Implementation Specification: M1 Day 1
"""

import json
import secrets
from functools import lru_cache
from typing import Any, List, Optional, Union
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ALLOWED_ENVIRONMENTS = {"development", "staging", "production", "test"}


class Settings(BaseSettings):
    """AMSC Application Settings.

    Centralized, type-safe configuration using Pydantic Settings.
    Reads values from environment variables or a local .env file.
    """

    # --- 1. Application Identity ---
    APP_NAME: str = Field(
        default="Agent Memory Security Center",
        description="Application title for display and OpenAPI documentation",
    )
    APP_VERSION: str = Field(
        default="1.0.0",
        description="Semantic application version",
    )
    APP_DESCRIPTION: str = Field(
        default="Enterprise AI-Agent Memory Security, Governance, Observability & Recovery Platform",
        description="Detailed application summary",
    )
    APP_ENV: str = Field(
        default="development",
        description="Runtime environment: 'development', 'staging', 'production', 'test'",
    )
    DEBUG: bool = Field(
        default=False,
        description="Debug mode toggle (must remain False in production)",
    )

    # --- 2. API Routing & Documentation ---
    API_PREFIX: str = Field(
        default="/api/v1",
        description="Canonical API path prefix for versioned endpoints",
    )
    DOCS_URL: str | None = Field(
        default="/docs",
        description="Swagger UI URL path (can be disabled in production)",
    )
    REDOC_URL: str | None = Field(
        default="/redoc",
        description="ReDoc UI URL path (can be disabled in production)",
    )
    OPENAPI_URL: str | None = Field(
        default="/openapi.json",
        description="OpenAPI specification endpoint",
    )
    ENABLE_DOCS_IN_PRODUCTION: bool = Field(
        default=False,
        description="Explicit flag permitting Swagger UI and ReDoc in production (disabled by default)",
    )
    PROTECT_DOCS_IN_PRODUCTION: bool = Field(
        default=False,
        description="When ENABLE_DOCS_IN_PRODUCTION is True, require Bearer authentication to access /docs and /redoc",
    )
    ALLOW_LOCALHOST_CORS_IN_PRODUCTION: bool = Field(
        default=False,
        description="Explicit override permitting localhost origins in production (strictly disabled by default)",
    )

    # --- 3. CORS Configuration ---
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ],
        description="List of allowed CORS origins for browser security enforcement",
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Whether cross-origin requests are permitted to include credentials",
    )
    CORS_ALLOWED_METHODS: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        description="Explicit allowed HTTP methods for CORS requests",
    )
    CORS_ALLOWED_HEADERS: List[str] = Field(
        default_factory=lambda: [
            "Authorization",
            "Content-Type",
            "Accept",
            "Origin",
            "X-Requested-With",
            "X-Tenant-ID",
            "X-Trace-ID",
            "X-Request-ID",
            "X-Correlation-ID",
            "Idempotency-Key",
            "X-Idempotency-Key",
        ],
        description="Explicit allowed HTTP request headers for CORS",
    )
    CORS_EXPOSE_HEADERS: List[str] = Field(
        default_factory=lambda: ["X-Request-ID", "X-Trace-ID", "X-Correlation-ID"],
        description="Response headers exposed to frontend browser clients",
    )

    # --- 4. Logging ---
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Application log level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )

    # --- 5. Security & Authentication Foundations (Day 2 Readiness) ---
    JWT_SECRET: str = Field(
        default="",
        description="Secret key for HMAC-SHA256 JWT signing (never commit real production secrets)",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="JWT cryptographic signing algorithm",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60,
        description="Access token lifespan in minutes",
    )
    AUTH_BACKEND: str = Field(
        default="in_memory_demo",
        description="Authentication repository backend: 'in_memory_demo' or 'database'",
    )
    ALLOW_IN_MEMORY_AUTH: bool = Field(
        default=True,
        description="Explicit flag permitting in-memory demo authentication (strictly forbidden in production)",
    )
    RATE_LIMIT_REDIS_FAILURE_POLICY: str = Field(
        default="fail_closed",
        description="Behavior when Redis is unavailable during login rate limiting: 'fail_closed' or 'fail_open'",
    )
    ALLOW_IN_MEMORY_RATE_LIMITER: bool = Field(
        default=True,
        description="Explicit flag permitting in-memory rate limiting (strictly forbidden in production)",
    )
    RATE_LIMITER_BACKEND: str = Field(
        default="in_memory",
        description="Rate limiter implementation backend: 'in_memory' or 'redis'",
    )
    LOGIN_RATE_LIMIT_IP_MAX_REQUESTS: int = Field(
        default=10,
        description="Max login attempts allowed per IP per window in production/dev",
    )
    LOGIN_RATE_LIMIT_ACCOUNT_MAX_REQUESTS: int = Field(
        default=5,
        description="Max login attempts allowed per target account per window in production/dev",
    )
    LOGIN_RATE_LIMIT_GLOBAL_ACCOUNT_MAX_REQUESTS: Optional[int] = Field(
        default=None,
        description="Global rate limit for an account across all source IPs (DoS mitigation tier).",
    )
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        description="Sliding window duration for login rate limiting in seconds",
    )
    TRUSTED_PROXIES: List[str] = Field(
        default_factory=list,
        description="Explicitly trusted reverse proxy IP addresses; only these proxies may supply forwarded client IPs",
    )
    AUTH_MAX_CONCURRENT_VERIFICATIONS: int = Field(
        default=8,
        description="Maximum concurrent Argon2 password verification operations to bound CPU and memory usage",
    )
    RATE_LIMIT_HMAC_SECRET: str = Field(
        default="",
        description="Keyed HMAC secret for privacy-preserving rate limit keys (GAP-009 / Finding C)",
    )
    JWT_ACTIVE_KID: str = Field(
        default="k-current",
        description="Active cryptographic key identifier for JWT signing (GAP-014 / Finding D)",
    )
    JWT_KEYRING_CONFIG: Optional[str] = Field(
        default=None,
        description="Optional JSON configuration string for keyring rotation and retirement (GAP-014 / Finding D)",
    )

    # --- 6. Persistence & Cache Connection Placeholders (M6/M7 Alignment) ---
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://amsc:amsc_dev_password@localhost:5432/amsc",
        description="Asynchronous SQLAlchemy connection string for PostgreSQL",
    )
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for distributed locking, rate-limiting, and ephemeral state",
    )

    # --- Pydantic Settings Configuration ---
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Field Validators ---
    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        """Validate and normalize environment name."""
        normalized = v.strip().lower()
        if normalized not in ALLOWED_ENVIRONMENTS:
            raise ValueError(
                f"APP_ENV must be one of {sorted(ALLOWED_ENVIRONMENTS)}, got '{v}'"
            )
        return normalized

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse and normalize CORS origins (strip whitespace and trailing slashes)."""
        def _normalize(origin: str) -> str:
            cleaned = origin.strip()
            # RFC 6454: Origins must not contain trailing slashes
            if cleaned != "*" and cleaned.endswith("/"):
                cleaned = cleaned.rstrip("/")
            return cleaned

        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    parsed = json.loads(v_stripped)
                    if isinstance(parsed, list):
                        return [_normalize(str(item)) for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [_normalize(origin) for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [_normalize(str(item)) for item in v if str(item).strip()]
        return []

    @field_validator("TRUSTED_PROXIES", mode="before")
    @classmethod
    def assemble_trusted_proxies(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse and normalize trusted proxy addresses."""
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    parsed = json.loads(v_stripped)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [p.strip() for p in v.split(",") if p.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return []

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate standard logging levels."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper().strip()
        if upper_v not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got {v}")
        return upper_v

    @model_validator(mode="after")
    def validate_security_invariants(self) -> "Settings":
        """Enforce strict fail-closed security invariants across environments."""
        # Universal Invariant: Never combine wildcard origins with credentialed requests
        if self.CORS_ALLOW_CREDENTIALS and "*" in self.CORS_ORIGINS:
            raise ValueError(
                "Security violation: Wildcard ('*') CORS origins cannot be combined with credentialed requests."
            )

        # JWT Secret Handling:
        # In dev/test/staging, generate a cryptographically secure random 32-byte secret if not provided.
        # In production, require an explicit, strong secret from the runtime environment.
        if not self.JWT_SECRET:
            if self.APP_ENV == "production":
                raise ValueError(
                    "Security violation: JWT_SECRET must be explicitly configured in the runtime environment for production."
                )
            self.JWT_SECRET = secrets.token_urlsafe(32)
        elif len(self.JWT_SECRET) < 32:
            if self.APP_ENV == "production":
                raise ValueError(
                    "Security violation: JWT_SECRET must be at least 32 characters in production."
                )
            raise ValueError(
                "Security violation: JWT_SECRET must be at least 32 characters (256 bits)."
            )

        # Rate Limit HMAC Secret Handling in non-production:
        if not self.RATE_LIMIT_HMAC_SECRET:
            self.RATE_LIMIT_HMAC_SECRET = self.JWT_SECRET
        elif len(self.RATE_LIMIT_HMAC_SECRET) < 32 and self.APP_ENV != "production":
            self.RATE_LIMIT_HMAC_SECRET = self.JWT_SECRET

        # Strict Production Guardrails
        if self.APP_ENV == "production":
            # 1. Debug mode must not be active in production
            if self.DEBUG:
                raise ValueError("Security violation: DEBUG mode must be False in production.")

            # 2. Insecure default secret check
            insecure_markers = {
                "insecure", "dev", "change", "replace", "default",
                "example", "placeholder",
            }
            if any(marker in self.JWT_SECRET.lower() for marker in insecure_markers):
                raise ValueError(
                    "Security violation: Default, placeholder, or development JWT_SECRET cannot be used in production."
                )
            if len(self.JWT_SECRET) < 32:
                raise ValueError(
                    "Security violation: JWT_SECRET must be at least 32 characters in production."
                )

            # 3. CORS wildcard and localhost restriction
            if "*" in self.CORS_ORIGINS:
                raise ValueError(
                    "Security violation: Wildcard ('*') CORS origins are prohibited in production."
                )
            default_dev_origins = {
                "http://localhost:5173",
                "http://localhost:3000",
                "http://127.0.0.1:5173",
                "http://127.0.0.1:3000",
            }
            if set(self.CORS_ORIGINS).issubset(default_dev_origins) and not self.ALLOW_LOCALHOST_CORS_IN_PRODUCTION:
                self.CORS_ORIGINS = ["https://amsc.prod.internal"]
            elif not self.CORS_ORIGINS:
                raise ValueError(
                    "Security configuration error: At least one explicit origin must be defined in production."
                )
            elif not self.ALLOW_LOCALHOST_CORS_IN_PRODUCTION:
                localhost_markers = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
                for origin in self.CORS_ORIGINS:
                    lower_orig = origin.lower()
                    if any(marker in lower_orig for marker in localhost_markers):
                        raise ValueError(
                            f"Security violation: Development localhost origin '{origin}' is prohibited in production."
                        )

            # 3b. Keyed HMAC secret for login rate limiting in production
            if not self.RATE_LIMIT_HMAC_SECRET:
                raise ValueError(
                    "Security violation: RATE_LIMIT_HMAC_SECRET must be explicitly configured in the runtime environment for production."
                )
            if len(self.RATE_LIMIT_HMAC_SECRET) < 32:
                raise ValueError(
                    "Security violation: RATE_LIMIT_HMAC_SECRET must be at least 32 characters in production."
                )
            if any(marker in self.RATE_LIMIT_HMAC_SECRET.lower() for marker in insecure_markers):
                raise ValueError(
                    "Security violation: Default, placeholder, or development RATE_LIMIT_HMAC_SECRET cannot be used in production."
                )

            # 4. In-memory demo authentication strictly forbidden in production
            if self.ALLOW_IN_MEMORY_AUTH:
                raise ValueError(
                    "Security violation: ALLOW_IN_MEMORY_AUTH must be False in production."
                )
            if self.AUTH_BACKEND != "database":
                raise ValueError(
                    f"Security violation: AUTH_BACKEND '{self.AUTH_BACKEND}' is prohibited in production. Real 'database' backend required."
                )

            # 5. Database connection configuration in production
            if not self.DATABASE_URL:
                raise ValueError(
                    "Security configuration error: Production DATABASE_URL must be explicitly configured."
                )
            insecure_db_markers = ["amsc_dev_password", "localhost", "127.0.0.1"]
            if any(marker in self.DATABASE_URL.lower() for marker in insecure_db_markers):
                raise ValueError(
                    "Security violation: Production DATABASE_URL must use production credentials and a non-localhost host."
                )

            # 6. Redis connection configuration in production
            if not self.REDIS_URL:
                raise ValueError(
                    "Security configuration error: Production REDIS_URL must be explicitly configured."
                )
            insecure_redis_markers = ["localhost", "127.0.0.1"]
            if any(marker in self.REDIS_URL.lower() for marker in insecure_redis_markers):
                raise ValueError(
                    "Security violation: Production REDIS_URL must use a non-localhost host."
                )

            # 7. In-memory rate limiting strictly forbidden in production
            if self.ALLOW_IN_MEMORY_RATE_LIMITER:
                raise ValueError(
                    "Security violation: ALLOW_IN_MEMORY_RATE_LIMITER must be False in production."
                )
            if self.RATE_LIMITER_BACKEND != "redis":
                raise ValueError(
                    f"Security violation: RATE_LIMITER_BACKEND '{self.RATE_LIMITER_BACKEND}' is prohibited in production. Real 'redis' backend required."
                )
            if self.RATE_LIMIT_REDIS_FAILURE_POLICY != "fail_closed":
                raise ValueError(
                    "Security violation: Production RATE_LIMIT_REDIS_FAILURE_POLICY must be 'fail_closed'."
                )

        return self


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
