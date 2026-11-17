"""Memory versioning and append-only version evolution.

Module: backend.app.memory.versioning
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 and Document 05 §3.3 specifications.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from backend.app.core.exceptions import ValidationError
from .integrity import sha256_hex
from .models import MemoryRecord, MemoryVersion, TrustState
from .repository import MemoryRepository, get_default_repository
from .retrieval import MemoryNotFoundError


def update_memory(
    tenant_id: str,
    record_id: str,
    content: str,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Update a memory record with new content.

    Appends a new immutable version (current_version + 1) with an independent SHA-256
    checksum. Never edits or mutates historical versions.
    Enforces GAP-002: Invalidation of prior trust assessment. New unvalidated content
    resets record.trust_state to UNVERIFIED until evaluated by M4.
    """
    if content is None or not content.strip():
        raise ValidationError("Updated memory content must not be empty.")

    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    now = datetime.now(timezone.utc)
    new_version_num = record.current_version + 1
    checksum = sha256_hex(content)

    # 1. Create new immutable version
    new_version = MemoryVersion(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        record_id=record_id,
        version=new_version_num,
        content=content,
        checksum=checksum,
        created_at=now,
    )
    repo.create_version(new_version)

    # 2. Update record metadata and invalidate trust state (GAP-002)
    # The new content has not been vetted by M4; it must become UNVERIFIED immediately
    record.current_version = new_version_num
    record.trust_state = TrustState.UNVERIFIED.value
    record.updated_at = now
    repo.update_record(record)

    return record, new_version


__all__ = [
    "update_memory",
]
