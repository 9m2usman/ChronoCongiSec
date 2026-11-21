"""Cryptographic content hashing and integrity verification for Memory & Provenance.

Important:
SHA-256 content checksums provide integrity comparison and tamper detection,
not proof of authenticity or non-repudiation. They are not digital signatures
or authentication mechanisms.

Module: backend.app.memory.integrity
Owner: M3 — Knowledge & Memory Systems Lead
"""

import hashlib
import inspect
from datetime import datetime, timezone
from typing import Any, List, Optional
from backend.app.core.exceptions import AMSCException
from .models import MemoryIntegrityReport, MismatchedVersionItem


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


async def audit_memory_integrity(
    tenant_id: str,
    repository: Optional[Any] = None,
    batch_size: int = 100,
) -> MemoryIntegrityReport:
    """Audit cryptographic integrity across every version of every memory record in a tenant.

    Rules & Invariants:
    1. Read-only: never modifies records, versions, or trust states.
    2. Paging: iterates through repository in bounded batches of `batch_size` (default 100),
       never loading entire datasets into memory at once.
    3. Resilience: an individual corrupted record or repository error does not halt the audit;
       the failure is recorded and verification continues.
    4. Completeness: detects both content-checksum mismatches and missing current versions.
    """
    from .repository import get_default_repository

    repo = repository or get_default_repository()
    started_at = datetime.now(timezone.utc)
    safe_batch_size = max(1, min(batch_size, 500))

    offset = 0
    total_records = 0
    total_versions = 0
    matched = 0
    mismatched: List[MismatchedVersionItem] = []
    missing_versions: List[str] = []

    while True:
        res = repo.list_records(
            tenant_id=tenant_id,
            only_trusted=False,
            limit=safe_batch_size,
            offset=offset,
        )
        batch = await res if inspect.isawaitable(res) else res
        if not batch:
            break

        for record in batch:
            total_records += 1
            try:
                v_res = repo.get_versions(record.id, tenant_id)
                versions = await v_res if inspect.isawaitable(v_res) else v_res
                version_nums = {v.version for v in versions}

                # Verify current_version has an existing version row
                if record.current_version not in version_nums:
                    missing_versions.append(record.id)

                for ver in versions:
                    total_versions += 1
                    try:
                        computed = sha256_hex(ver.content)
                        if computed.lower() == ver.checksum.strip().lower():
                            matched += 1
                        else:
                            mismatched.append(
                                MismatchedVersionItem(
                                    record_id=record.id,
                                    version=ver.version,
                                )
                            )
                    except Exception:
                        mismatched.append(
                            MismatchedVersionItem(
                                record_id=record.id,
                                version=ver.version,
                            )
                        )
            except Exception:
                # Broken record lookup does not abort audit
                missing_versions.append(record.id)

        offset += len(batch)
        if len(batch) < safe_batch_size:
            break

    finished_at = datetime.now(timezone.utc)
    match_percentage = 100.0 if total_versions == 0 else round((matched / total_versions) * 100.0, 2)

    return MemoryIntegrityReport(
        total_records=total_records,
        total_versions=total_versions,
        matched=matched,
        mismatched=mismatched,
        missing_versions=missing_versions,
        match_percentage=match_percentage,
        started_at=started_at,
        finished_at=finished_at,
    )


__all__ = [
    "sha256_hex",
    "verify_checksum",
    "MemoryIntegrityError",
    "audit_memory_integrity",
]
