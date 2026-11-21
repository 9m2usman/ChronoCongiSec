"""Memory versioning and append-only version evolution.

Module: backend.app.memory.versioning
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §15.2 and Document 05 §3.3 specifications.
"""

import difflib
import inspect
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

MAX_DIFF_LINES = 1000


class AwaitableTuple(tuple):
    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


def update_memory(
    tenant_id: str,
    record_id: str,
    content: str,
    expected_current_version: Optional[int] = None,
    repository: Optional[MemoryRepository] = None,
) -> Tuple[MemoryRecord, MemoryVersion]:
    """Update a memory record with new content.

    Appends a new immutable version (current_version + 1) with an independent SHA-256
    checksum. Never edits or mutates historical versions.
    Enforces optimistic concurrency control if expected_current_version is provided.

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

    def _validate_and_prep(record):
        if not record:
            raise MemoryNotFoundError(
                f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
            )

        if expected_current_version is not None and record.current_version != expected_current_version:
            raise ValidationError(
                f"Optimistic concurrency conflict on memory record '{record_id}': "
                f"expected version {expected_current_version}, but current version is {record.current_version}."
            )

        record_state = record.trust_state.value if hasattr(record.trust_state, "value") else str(record.trust_state)
        if record_state in TERMINAL_TRUST_STATES:
            raise ValidationError(
                f"Cannot update memory record '{record_id}' in terminal/restricted state '{record_state}'. "
                "Updates are prohibited on QUARANTINED, REJECTED, or SUPERSEDED records."
            )

        if record_state == TrustState.TRUSTED.value:
            next_trust_state = TrustState.UNVERIFIED.value
        elif record_state == TrustState.UNVERIFIED.value:
            next_trust_state = TrustState.UNVERIFIED.value
        elif record_state == TrustState.SUSPICIOUS.value:
            next_trust_state = TrustState.SUSPICIOUS.value
        else:
            raise ValidationError(
                f"Cannot update memory record '{record_id}' with invalid or unknown trust state '{record_state}'."
            )

        now = datetime.now(timezone.utc)
        new_version_num = record.current_version + 1
        checksum = sha256_hex(content)

        new_version = MemoryVersion(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            record_id=record_id,
            version=new_version_num,
            content=content,
            checksum=checksum,
            created_at=now,
        )

        record.current_version = new_version_num
        record.trust_state = next_trust_state
        record.updated_at = now
        return record, new_version

    def sync_impl():
        record = repo.get_record(record_id, tenant_id)
        record, new_version = _validate_and_prep(record)
        with repo.transaction():
            repo.create_version(new_version)
            repo.update_record(record)
        return (record, new_version)

    async def async_impl():
        record = repo.get_record(record_id, tenant_id)
        if inspect.isawaitable(record):
            record = await record
        record, new_version = _validate_and_prep(record)
        async with repo.transaction():
            res = repo.create_version(new_version)
            if inspect.isawaitable(res):
                await res
            res = repo.update_record(record)
            if inspect.isawaitable(res):
                await res
        return (record, new_version)

    is_async = (
        inspect.iscoroutinefunction(getattr(repo, "update_record", None))
        or inspect.iscoroutinefunction(getattr(repo, "create_version", None))
        or inspect.iscoroutinefunction(getattr(repo, "get_record", None))
        or getattr(repo, "is_persistent", False)
    )

    if not is_async:
        return AwaitableTuple(sync_impl())

    return async_impl()


async def compare_versions(
    tenant_id: str,
    record_id: str,
    v_from: int,
    v_to: int,
    repository: Optional[MemoryRepository] = None,
) -> VersionCompareResponse:
    """Compute unified diff and added/removed line annotations between two memory versions.

    Rules & Invariants:
    1. Read-only: never modifies records, versions, or trust states.
    2. Tamper detection: computes and verifies SHA-256 checksum of both versions against their
       stored checksums; raises MemoryIntegrityError if either does not match.
    3. Monotonic ordering: v_from must be <= v_to; raises ValidationError if v_from > v_to.
    4. Truncation: limits diff output to MAX_DIFF_LINES (1000) to protect downstream consumers.
    """
    if v_from > v_to:
        raise ValidationError(
            f"Invalid version comparison range: v_from ({v_from}) must be less than or equal to v_to ({v_to})."
        )

    repo = repository or get_default_repository()
    rec_res = repo.get_record(record_id, tenant_id)
    record = await rec_res if inspect.isawaitable(rec_res) else rec_res
    if not record:
        raise MemoryNotFoundError(
            f"Memory record '{record_id}' not found for tenant '{tenant_id}'."
        )

    vf_res = repo.get_version(record_id, v_from, tenant_id)
    ver_from = await vf_res if inspect.isawaitable(vf_res) else vf_res
    if not ver_from:
        raise MemoryNotFoundError(
            f"Version {v_from} of MemoryRecord '{record_id}' not found for tenant '{tenant_id}'."
        )

    vt_res = repo.get_version(record_id, v_to, tenant_id)
    ver_to = await vt_res if inspect.isawaitable(vt_res) else vt_res
    if not ver_to:
        raise MemoryNotFoundError(
            f"Version {v_to} of MemoryRecord '{record_id}' not found for tenant '{tenant_id}'."
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


async def get_timeline(
    tenant_id: str,
    agent_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    repository: Optional[MemoryRepository] = None,
) -> List[TimelineEvent]:
    """Retrieve temporal version timeline of memory evolution for a tenant/agent.

    Version events are ordered by created_at then version.
    Enforces tenant scoping and bounded pagination (limit default 50, max 100, offset >= 0).
    """
    safe_limit = max(1, min(limit, 100))
    safe_offset = max(0, offset)

    repo = repository or get_default_repository()
    rec_res = repo.list_records(
        tenant_id=tenant_id,
        agent_id=agent_id,
        only_trusted=False,
        limit=10000,
        offset=0,
    )
    records = await rec_res if inspect.isawaitable(rec_res) else rec_res

    events: List[TimelineEvent] = []
    for record in records:
        v_res = repo.get_versions(record.id, tenant_id)
        versions = await v_res if inspect.isawaitable(v_res) else v_res
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
