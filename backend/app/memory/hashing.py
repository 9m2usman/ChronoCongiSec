"""Cryptographic content hashing utilities for Memory & Provenance.

Important:
SHA-256 content checksums provide integrity comparison and tamper detection,
not proof of authenticity or non-repudiation. They are not digital signatures
or authentication mechanisms.
"""

import hashlib
from typing import Optional


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
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    stripped = normalized.strip()
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()
