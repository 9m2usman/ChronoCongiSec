"""Shared FastAPI Dependencies and Context Providers.

Module: backend.app.core.dependencies
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- Master Implementation Specification: M1 Day 1 Baseline
- Day 2 Architecture Extension Points (Auth, Tenancy Context, DB Session)
"""

from typing import Annotated
from fastapi import Depends
from backend.app.core.config import Settings, get_settings


def get_app_settings() -> Settings:
    """Dependency that returns the current application settings."""
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_app_settings)]

# --- Day 2 Architectural Placeholders ---
# Note: Full Day 2 implementation will provide:
# - get_db: Async database session dependency (coordinated with M6)
# - get_current_user: Authenticated user context from JWT token (M1 Day 2)
# - get_tenant_context: Validated tenant scope dependency (M1 Day 2)
