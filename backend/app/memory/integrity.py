"""Cryptographic content hashing and integrity verification for Memory & Provenance.

Important:
SHA-256 content checksums provide integrity comparison and tamper detection,
not proof of authenticity or non-repudiation. They are not digital signatures
or authentication mechanisms.

Module: backend.app.memory.integrity
Owner: M3 — Knowledge & Memory Systems Lead
"""

import hashlib
from typing import Any, Optional
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


def sha256_hex(content: Optional[str] = None) -> str:
    """Normalize line endings, strip leading/trailing whitespace, and return SHA-256 hex digest.

    Conforms to Document 02 §15.1: Checksum = SHA256(UTF8(Strip(Content))).
    Explicitly handles empty input and None safely by hashing an empty string.

    Note: SHA-256 checksums provide content integrity comparison, not digital signatures
    or authentication.

    Args:
        content: The text content to hash, or None (treated as empty string).

    Returns:
        A 64-character lowercase hexadecimal SHA-256 digest string.
    """
    if content is None:
        content = ""
    elif not isinstance(content, str):
        raise TypeError(f"content must be a string or None, got {type(content).__name__}")
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    stripped = normalized.strip()
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()


def verify_checksum(content: Optional[str], checksum: Optional[str]) -> bool:
    """Verify that content's canonical SHA-256 matches the expected checksum."""
    if checksum is None or content is None:
        return False
    return sha256_hex(content).lower() == checksum.strip().lower()


__all__ = [
    "sha256_hex",
    "verify_checksum",
    "MemoryIntegrityError",
]
