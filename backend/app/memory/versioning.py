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

# Terminal/restricted trust states that prohibit any updates
TERMINAL_TRUST_STATES = {
    TrustState.QUARANTINED.value,
    TrustState.REJECTED.value,
    TrustState.SUPERSEDED.value,
}


def update_memory(
    tenant_id: str,
    record_id: str,
    content: str,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Update a memory record with new content.

    Appends a new immutable version (current_version + 1) with an independent SHA-256
    checksum. Never edits or mutates historical versions.

    Trust state transition rules:
    1. If QUARANTINED, REJECTED, or SUPERSEDED: refuse update by raising ValidationError.
       No new version row, no change to trust_state, no change to updated_at.
    2. If TRUSTED: write new version, set trust_state to UNVERIFIED (needs re-validation).
    3. If UNVERIFIED: write new version, stay UNVERIFIED.
    4. If SUSPICIOUS: write new version, stay SUSPICIOUS (an edit must never clear a flag).
    5. An update must never move a record to a less restrictive state.
    """
    if content is None or not content.strip():
        raise ValidationError("Updated memory content must not be empty.")

    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    # 1. Refuse updates on QUARANTINED, REJECTED, or SUPERSEDED records
    record_state = record.trust_state.value if hasattr(record.trust_state, "value") else str(record.trust_state)
    if record_state in TERMINAL_TRUST_STATES:
        raise ValidationError(
            f"Cannot update memory record '{record_id}' in terminal/restricted state '{record_state}'. "
            "Updates are prohibited on QUARANTINED, REJECTED, or SUPERSEDED records."
        )

    # Determine target trust state
    if record_state == TrustState.TRUSTED.value:
        next_trust_state = TrustState.UNVERIFIED.value
    elif record_state == TrustState.UNVERIFIED.value:
        next_trust_state = TrustState.UNVERIFIED.value
    elif record_state == TrustState.SUSPICIOUS.value:
        next_trust_state = TrustState.SUSPICIOUS.value
    else:
        # F-1a: Refuse updates if stored trust state is unrecognized/unknown (fail closed)
        raise ValidationError(
            f"Cannot update memory record '{record_id}' with invalid or unknown trust state '{record_state}'."
        )

    now = datetime.now(timezone.utc)
    new_version_num = record.current_version + 1
    checksum = sha256_hex(content)

    # Write new immutable version
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

    # Update record metadata and trust state
    record.current_version = new_version_num
    record.trust_state = next_trust_state
    record.updated_at = now
    repo.update_record(record)

    return record, new_version


__all__ = [
    "update_memory",
]
