"""Centralized Application Configuration.

Module: backend.app.core.config
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Backend Technology Stack
- AMSC-DOC-005 (Database & API Schema) Section 5: API Conventions
- Master Implementation Specification: M1 Day 1
"""

import json
from functools import lru_cache
from typing import Any, List, Union
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # --- 4. Logging ---
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Application log level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )

    # --- 5. Security & Authentication Foundations (Day 2 Readiness) ---
    JWT_SECRET: str = Field(
        default="insecure-dev-secret-key-change-in-production-min-32-chars",
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
    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse CORS origins from comma-separated string, JSON string, or list."""
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    parsed = json.loads(v_stripped)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
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
    def validate_production_security(self) -> "Settings":
        """Enforce strict fail-closed security validations in production."""
        if self.APP_ENV.lower() == "production":
            # 1. Debug mode must not be active in production
            if self.DEBUG:
                raise ValueError("Security violation: DEBUG mode must be False in production.")

            # 2. Insecure default secret check
            if "insecure" in self.JWT_SECRET.lower() or "dev" in self.JWT_SECRET.lower():
                raise ValueError(
                    "Security violation: Default or development JWT_SECRET cannot be used in production."
                )
            if len(self.JWT_SECRET) < 32:
                raise ValueError(
                    "Security violation: JWT_SECRET must be at least 32 characters in production."
                )

            # 3. CORS wildcard restriction
            if "*" in self.CORS_ORIGINS:
                raise ValueError(
                    "Security violation: Wildcard ('*') CORS origins are prohibited in production."
                )
            if not self.CORS_ORIGINS:
                raise ValueError(
                    "Security configuration error: At least one explicit origin must be defined in production."
                )

        return self


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
