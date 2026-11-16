"""Cryptographic content hashing utilities for Memory & Provenance."""

import hashlib


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
