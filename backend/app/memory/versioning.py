"""Memory versioning and append-only version evolution.

Module: backend.app.memory.versioning
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 and Document 05 §3.3 specifications.
"""

import difflib
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from backend.app.core.exceptions import ValidationError
from .integrity import MemoryIntegrityError, sha256_hex
from .models import (
    LineDiffItem,
    MemoryRecord,
    MemoryVersion,
    TimelineEvent,
    TrustState,
    VersionCompareResponse,
)
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
        # Fallback safeguard: default to UNVERIFIED
        next_trust_state = TrustState.UNVERIFIED.value

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


# ASSUMPTION (M3): at most 2000 diff lines; above that return truncated=True with the first 2000, never an unbounded response.
MAX_DIFF_LINES = 2000


def compare_versions(
    tenant_id: str,
    record_id: str,
    v_from: int,
    v_to: int,
    repository: Optional[MemoryRepository] = None,
) -> VersionCompareResponse:
    """Compute unified diff and added/removed line annotations between two memory versions.

    Enforces strict tenant isolation: both versions must belong to the specified record
    within the tenant. If not found or cross-tenant, raises MemoryNotFoundError without revealing
    external existence. Re-verifies cryptographic checksums of both versions before diffing.
    """
    if v_from < 1 or v_to < 1:
        raise ValidationError("Version numbers v_from and v_to must be >= 1.")

    repo = repository or get_default_repository()
    record = repo.get_record(record_id, tenant_id)
    if not record or record.tenant_id != tenant_id:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    ver_from = repo.get_version(record_id, v_from, tenant_id)
    if not ver_from or ver_from.tenant_id != tenant_id or ver_from.record_id != record_id:
        raise MemoryNotFoundError(
            f"Version {v_from} not found for record '{record_id}' in tenant '{tenant_id}'."
        )

    ver_to = repo.get_version(record_id, v_to, tenant_id)
    if not ver_to or ver_to.tenant_id != tenant_id or ver_to.record_id != record_id:
        raise MemoryNotFoundError(
            f"Version {v_to} not found for record '{record_id}' in tenant '{tenant_id}'."
        )

    # Recompute and verify both cryptographic checksums first (tamper detection)
    computed_from = sha256_hex(ver_from.content)
    if computed_from != ver_from.checksum:
        raise MemoryIntegrityError(
            f"Cryptographic integrity violation: MemoryRecord '{record_id}' Version {v_from} "
            f"checksum mismatch! Stored='{ver_from.checksum}', Computed='{computed_from}'."
        )

    computed_to = sha256_hex(ver_to.content)
    if computed_to != ver_to.checksum:
        raise MemoryIntegrityError(
            f"Cryptographic integrity violation: MemoryRecord '{record_id}' Version {v_to} "
            f"checksum mismatch! Stored='{ver_to.checksum}', Computed='{computed_to}'."
        )

    # v_from == v_to gives an empty diff
    if v_from == v_to:
        return VersionCompareResponse(
            record_id=record.id,
            v_from=v_from,
            v_to=v_to,
            trust_state=record.trust_state,
            checksum_from=ver_from.checksum,
            checksum_to=ver_to.checksum,
            unified_diff="",
            added_lines=[],
            removed_lines=[],
            truncated=False,
        )

    lines_from = ver_from.content.splitlines()
    lines_to = ver_to.content.splitlines()

    raw_diff = list(
        difflib.unified_diff(
            lines_from,
            lines_to,
            fromfile=f"v{v_from}",
            tofile=f"v{v_to}",
            lineterm="",
            n=3,
        )
    )

    truncated = False
    if len(raw_diff) > MAX_DIFF_LINES:
        unified_diff_str = "\n".join(raw_diff[:MAX_DIFF_LINES])
        truncated = True
    else:
        unified_diff_str = "\n".join(raw_diff)

    matcher = difflib.SequenceMatcher(None, lines_from, lines_to)
    added_lines: List[LineDiffItem] = []
    removed_lines: List[LineDiffItem] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            for idx in range(i1, i2):
                removed_lines.append(
                    LineDiffItem(line_number=idx + 1, text=lines_from[idx])
                )
        if tag in ("replace", "insert"):
            for idx in range(j1, j2):
                added_lines.append(
                    LineDiffItem(line_number=idx + 1, text=lines_to[idx])
                )

    if truncated:
        added_lines = added_lines[:MAX_DIFF_LINES]
        removed_lines = removed_lines[:MAX_DIFF_LINES]

    return VersionCompareResponse(
        record_id=record.id,
        v_from=v_from,
        v_to=v_to,
        trust_state=record.trust_state,
        checksum_from=ver_from.checksum,
        checksum_to=ver_to.checksum,
        unified_diff=unified_diff_str,
        added_lines=added_lines,
        removed_lines=removed_lines,
        truncated=truncated,
    )


def get_timeline(
    tenant_id: str,
    agent_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    repository: Optional[MemoryRepository] = None,
) -> List[TimelineEvent]:
    """Retrieve temporal version timeline of memory evolution for a tenant/agent.

    Version events are ordered by created_at then version.
    Enforces tenant scoping and bounded pagination (limit default 50, max 100, offset >= 0).

    ASSUMPTION (M3): these are human-facing history views; they return records in any trust state,
    with trust_state shown in the response, because docs/05 assigns them to Member and the demo
    must show injected text. They must NEVER feed agent retrieval.
    """
    safe_limit = max(1, min(limit, 100))
    safe_offset = max(0, offset)

    repo = repository or get_default_repository()
    records = repo.list_records(
        tenant_id=tenant_id,
        agent_id=agent_id,
        only_trusted=False,
        limit=10000,
        offset=0,
    )

    events: List[TimelineEvent] = []
    for record in records:
        versions = repo.get_versions(record.id, tenant_id)
        for ver in versions:
            events.append(
                TimelineEvent(
                    record_id=record.id,
                    version=ver.version,
                    checksum=ver.checksum,
                    created_at=ver.created_at,
                    trust_state=record.trust_state,
                    record_type=record.record_type,
                )
            )

    def _sort_key(ev: TimelineEvent):
        dt = ev.created_at
        if isinstance(dt, datetime):
            ts = dt.timestamp()
        elif isinstance(dt, (int, float)):
            ts = float(dt)
        else:
            ts = 0.0
        return (ts, ev.version)

    events.sort(key=_sort_key)
    return events[safe_offset : safe_offset + safe_limit]


__all__ = [
    "update_memory",
    "compare_versions",
    "get_timeline",
    "MAX_DIFF_LINES",
]
