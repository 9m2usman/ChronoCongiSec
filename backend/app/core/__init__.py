"""Core Platform Components (Configuration, Security, Exceptions, Logging, Dependencies).

Module: backend.app.core
Owner: M1 — Platform Backend & API Integration Lead
"""

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import (
    AMSCException,
    AuthenticationError,
    ForbiddenError,
    NotFoundError,
    PolicyDeniedError,
    SecurityDependencyError,
    TenantAccessForbiddenError,
    ValidationError,
)
from backend.app.core.logging import setup_logging

__all__ = [
    "Settings",
    "get_settings",
    "AMSCException",
    "NotFoundError",
    "ValidationError",
    "AuthenticationError",
    "ForbiddenError",
    "TenantAccessForbiddenError",
    "PolicyDeniedError",
    "SecurityDependencyError",
    "setup_logging",
]
