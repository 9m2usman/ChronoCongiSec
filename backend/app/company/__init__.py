"""Authoritative Phase 2 Company Application Service & Resource Isolation."""

from backend.app.company.service import (
    CompanyResourceService,
    SqlCompanyResourceIsolationAdapter,
)

__all__ = [
    "CompanyResourceService",
    "SqlCompanyResourceIsolationAdapter",
]
