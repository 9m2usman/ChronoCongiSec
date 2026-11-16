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
from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    needs_rehash,
    verify_password,
)

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
    "create_access_token",
    "decode_access_token",
    "hash_password",
    "verify_password",
    "needs_rehash",
]
