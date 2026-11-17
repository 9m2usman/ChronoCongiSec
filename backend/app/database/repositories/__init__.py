"""Tenant-scoped repositories (M6)."""

from backend.app.database.repositories.base import (
    MAX_PAGE_SIZE,
    TenantScopedRepository,
    TenantScopeError,
)

__all__ = ["MAX_PAGE_SIZE", "TenantScopeError", "TenantScopedRepository"]
