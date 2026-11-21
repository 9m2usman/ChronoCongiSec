"""Compatibility shim for backend.app.memory.hashing.

Module: backend.app.memory.hashing
Re-exports sha256_hex and verify_checksum from backend.app.memory.integrity
to support legacy and cross-member callers without breaking the PR #7 package structure.
"""

from backend.app.memory.integrity import sha256_hex, verify_checksum

__all__ = ["sha256_hex", "verify_checksum"]
