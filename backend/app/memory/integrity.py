"""Cryptographic content hashing and integrity verification for Memory & Provenance.

Module: backend.app.memory.integrity
Owner: M3 — Knowledge & Memory Systems Lead
"""

import hashlib
from typing import Any
from backend.app.core.exceptions import AMSCException


class MemoryIntegrityError(AMSCException):
    """Raised when cryptographic checksum verification fails for a memory record."""

    def __init__(
        self,
        message: str = "Cryptographic checksum verification failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            code="MEMORY_INTEGRITY_VIOLATION",
            status_code=500,
            details=details,
        )


def sha256_hex(content: str) -> str:
    """Normalize line endings, strip leading/trailing whitespace, and return SHA-256 hex digest.

    Conforms to Document 02 §15.1: Checksum = SHA256(UTF8(Strip(Content))).
    Handles empty input and None safely.
    """
    if content is None:
        content = ""
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    stripped = normalized.strip()
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()


def verify_checksum(content: str, checksum: str) -> bool:
    """Verify that content's canonical SHA-256 matches the expected checksum."""
    if checksum is None or content is None:
        return False
    return sha256_hex(content).lower() == checksum.strip().lower()


__all__ = [
    "sha256_hex",
    "verify_checksum",
    "MemoryIntegrityError",
]
