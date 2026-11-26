"""Pre-action checkpoint contracts for protected gateway mutations.

Production adapters must snapshot every affected company resource and memory
reference into durable storage before the gateway dispatches an adapter. The
in-memory implementation is for tests/development only and records proposal
metadata; it is never accepted by production startup or execution.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Mapping, Optional, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.database.models.company import (
    CompanyFile,
    CompanyFileTransfer,
    CompanyFileVersion,
    CompanyMessage,
    CompanyNotification,
    CompanyTask,
    CompanyWorkspace,
)
from backend.app.database.models.memory import MemoryRecord, MemoryVersion
from backend.app.database.models.recovery import Checkpoint, CheckpointItem


class PreActionCheckpointService(Protocol):
    """Durable adapter that commits a recovery-grade pre-mutation snapshot."""

    is_persistent: bool
    is_in_memory: bool

    async def capture_pre_action_checkpoint(
        self,
        *,
        tenant_id: str,
        branch_id: Optional[str],
        actor_id: str,
        agent_id: str,
        proposal_id: str,
        action_id: str,
        trace_id: Optional[str],
        idempotency_key: str,
        tool_name: str,
        operation: str,
        parameters: Mapping[str, Any],
        memory_refs: list[str],
    ) -> Mapping[str, Any]:
        ...


class InMemoryPreActionCheckpointService:
    """Development/test-only metadata checkpoint; not a recovery-grade snapshot."""

    is_persistent = False
    is_in_memory = True

    def __init__(self) -> None:
        self._snapshots: Dict[str, Dict[str, Any]] = {}

    async def capture_pre_action_checkpoint(
        self,
        *,
        tenant_id: str,
        branch_id: Optional[str],
        actor_id: str,
        agent_id: str,
        proposal_id: str,
        action_id: str,
        trace_id: Optional[str],
        idempotency_key: str,
        tool_name: str,
        operation: str,
        parameters: Mapping[str, Any],
        memory_refs: list[str],
    ) -> Mapping[str, Any]:
        parameter_json = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
        parameter_hash = hashlib.sha256(parameter_json.encode("utf-8")).hexdigest()
        identity = f"{tenant_id}:{idempotency_key}"
        checkpoint_id = f"chk-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"
        snapshot = {
            "tenant_id": tenant_id,
            "branch_id": branch_id,
            "actor_id": actor_id,
            "agent_id": agent_id,
            "proposal_id": proposal_id,
            "action_id": action_id,
            "trace_id": trace_id,
            "tool_name": tool_name,
            "operation": operation,
            "parameters_sha256": parameter_hash,
            "memory_refs": list(memory_refs),
            "scope": "PROPOSAL_METADATA_ONLY",
        }
        existing = self._snapshots.get(checkpoint_id)
        if existing is not None:
            retry_snapshot = dict(snapshot)
            # Proposal IDs are generated per request; the idempotency key owns
            # the checkpoint identity, so compare all caller-controlled content
            # while retaining the original proposal correlation.
            retry_snapshot["proposal_id"] = existing["snapshot"]["proposal_id"]
            retry_snapshot["trace_id"] = existing["snapshot"]["trace_id"]
            canonical = json.dumps(retry_snapshot, sort_keys=True, separators=(",", ":"), default=str)
            integrity_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if existing["integrity_hash"] != integrity_hash:
                raise ValueError("Checkpoint idempotency key was reused with different proposal data.")
            snapshot = existing["snapshot"]
        else:
            canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
            integrity_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            self._snapshots[checkpoint_id] = {
                "snapshot": snapshot,
                "integrity_hash": integrity_hash,
            }
        return {
            "committed": True,
            "complete": False,
            "scope": "PROPOSAL_METADATA_ONLY",
            "checkpoint_id": checkpoint_id,
            "integrity_hash": integrity_hash,
            "memory_refs": list(memory_refs),
        }


_SENSITIVE_PARAM_KEYS = frozenset({
    "password", "secret", "token", "api_key", "apikey", "authorization",
    "credential", "private_key", "access_token", "refresh_token",
})


def _sanitize_parameters_for_hash(params: Any) -> Any:
    if isinstance(params, Mapping):
        sanitized: Dict[str, Any] = {}
        for k, v in params.items():
            if str(k).lower() in _SENSITIVE_PARAM_KEYS:
                sanitized[str(k)] = "[REDACTED]"
            else:
                sanitized[str(k)] = _sanitize_parameters_for_hash(v)
        return sanitized
    if isinstance(params, (list, tuple)):
        return [_sanitize_parameters_for_hash(item) for item in params]
    return params


def _extract_candidate_resource_ids(parameters: Mapping[str, Any]) -> Dict[str, List[str]]:
    candidates: Dict[str, List[str]] = {
        "FILE": [],
        "FILE_VERSION": [],
        "FILE_TRANSFER": [],
        "TASK": [],
        "WORKSPACE": [],
        "MESSAGE": [],
        "NOTIFICATION": [],
    }
    key_map = {
        "file_id": "FILE",
        "file_version_id": "FILE_VERSION",
        "transfer_id": "FILE_TRANSFER",
        "file_transfer_id": "FILE_TRANSFER",
        "task_id": "TASK",
        "workspace_id": "WORKSPACE",
        "message_id": "MESSAGE",
        "notification_id": "NOTIFICATION",
    }
    for key, rtype in key_map.items():
        val = parameters.get(key)
        if isinstance(val, str) and val.strip():
            candidates[rtype].append(val.strip())

    explicit_type = parameters.get("resource_type")
    explicit_id = parameters.get("resource_id") or parameters.get("target_id")
    if isinstance(explicit_type, str) and isinstance(explicit_id, str) and explicit_id.strip():
        norm_type = explicit_type.strip().upper()
        if norm_type in candidates:
            candidates[norm_type].append(explicit_id.strip())
    elif isinstance(explicit_id, str) and explicit_id.strip():
        for rtype in candidates:
            candidates[rtype].append(explicit_id.strip())
    return {k: list(dict.fromkeys(v)) for k, v in candidates.items() if v}


class SqlPreActionCheckpointService:
    """Durable SQLAlchemy-backed pre-action checkpoint service.

    Captures actual pre-mutation company resource and memory state into
    ``checkpoints`` and ``checkpoint_items`` and verifies durable commit
    before any protected mutation may proceed.
    """

    is_persistent = True
    is_in_memory = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def capture_pre_action_checkpoint(
        self,
        *,
        tenant_id: str,
        branch_id: Optional[str],
        actor_id: str,
        agent_id: str,
        proposal_id: str,
        action_id: str,
        trace_id: Optional[str],
        idempotency_key: str,
        tool_name: str,
        operation: str,
        parameters: Mapping[str, Any],
        memory_refs: list[str],
    ) -> Mapping[str, Any]:
        clean_params = _sanitize_parameters_for_hash(parameters)
        parameter_json = json.dumps(clean_params, sort_keys=True, separators=(",", ":"), default=str)
        parameter_hash = hashlib.sha256(parameter_json.encode("utf-8")).hexdigest()
        identity = f"{tenant_id}:{idempotency_key}"
        checkpoint_id = f"chk-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"

        request_content = {
            "tenant_id": tenant_id,
            "branch_id": branch_id,
            "actor_id": actor_id,
            "agent_id": agent_id,
            "action_id": action_id,
            "tool_name": tool_name,
            "operation": operation,
            "parameters_sha256": parameter_hash,
            "memory_refs": list(memory_refs),
            "scope": "COMPLETE",
        }
        request_content_hash = hashlib.sha256(
            json.dumps(request_content, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()

        async with self._session_factory() as session:
            existing = (
                await session.execute(
                    select(Checkpoint).where(
                        Checkpoint.tenant_id == tenant_id,
                        Checkpoint.id == checkpoint_id,
                    )
                )
            ).scalar_one_or_none()

            if existing is not None:
                stored_data = existing.snapshot_data_json or {}
                if stored_data.get("request_content_hash") != request_content_hash:
                    raise ValueError("Checkpoint idempotency key was reused with different proposal data.")
                return {
                    "committed": True,
                    "complete": True,
                    "scope": stored_data.get("scope", "COMPLETE"),
                    "checkpoint_id": existing.id,
                    "integrity_hash": existing.integrity_hash,
                    "memory_refs": list(stored_data.get("memory_refs", memory_refs)),
                    "resources": list(stored_data.get("resources", [])),
                }

            captured_resources: List[Dict[str, Any]] = []
            candidates = _extract_candidate_resource_ids(parameters)

            for fid in candidates.get("FILE", []):
                row = (
                    await session.execute(
                        select(CompanyFile).where(CompanyFile.tenant_id == tenant_id, CompanyFile.id == fid)
                    )
                ).scalar_one_or_none()
                if row is not None:
                    ver = (
                        await session.execute(
                            select(CompanyFileVersion).where(
                                CompanyFileVersion.tenant_id == tenant_id,
                                CompanyFileVersion.file_id == row.id,
                                CompanyFileVersion.version_number == row.current_version,
                            )
                        )
                    ).scalar_one_or_none()
                    captured_resources.append({
                        "resource_type": "FILE",
                        "resource_id": row.id,
                        "workspace_id": row.workspace_id,
                        "owner_user_id": row.owner_user_id,
                        "name": row.name,
                        "current_version": row.current_version,
                        "status": row.status,
                        "version_id": ver.id if ver else None,
                        "version_checksum": ver.checksum if ver else None,
                    })

            for fvid in candidates.get("FILE_VERSION", []):
                ver_row = (
                    await session.execute(
                        select(CompanyFileVersion).where(
                            CompanyFileVersion.tenant_id == tenant_id,
                            CompanyFileVersion.id == fvid,
                        )
                    )
                ).scalar_one_or_none()
                if ver_row is not None:
                    captured_resources.append({
                        "resource_type": "FILE_VERSION",
                        "resource_id": ver_row.id,
                        "file_id": ver_row.file_id,
                        "version_number": ver_row.version_number,
                        "checksum": ver_row.checksum,
                    })

            for tr_id in candidates.get("FILE_TRANSFER", []):
                row = (
                    await session.execute(
                        select(CompanyFileTransfer).where(
                            CompanyFileTransfer.tenant_id == tenant_id,
                            CompanyFileTransfer.id == tr_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is not None:
                    captured_resources.append({
                        "resource_type": "FILE_TRANSFER",
                        "resource_id": row.id,
                        "file_id": row.file_id,
                        "sender_user_id": row.sender_user_id,
                        "recipient_user_id": row.recipient_user_id,
                        "status": row.status,
                    })
                    if row.file_id not in candidates.get("FILE", []):
                        file_row = (
                            await session.execute(
                                select(CompanyFile).where(
                                    CompanyFile.tenant_id == tenant_id,
                                    CompanyFile.id == row.file_id,
                                )
                            )
                        ).scalar_one_or_none()
                        if file_row is not None:
                            captured_resources.append({
                                "resource_type": "FILE",
                                "resource_id": file_row.id,
                                "workspace_id": file_row.workspace_id,
                                "current_version": file_row.current_version,
                                "status": file_row.status,
                            })

            for tid in candidates.get("TASK", []):
                row = (
                    await session.execute(
                        select(CompanyTask).where(CompanyTask.tenant_id == tenant_id, CompanyTask.id == tid)
                    )
                ).scalar_one_or_none()
                if row is not None:
                    captured_resources.append({
                        "resource_type": "TASK",
                        "resource_id": row.id,
                        "workspace_id": row.workspace_id,
                        "branch_id": row.branch_id,
                        "status": row.status,
                        "priority": row.priority,
                        "assigned_to_user_id": row.assigned_to_user_id,
                    })

            for wid in candidates.get("WORKSPACE", []):
                row = (
                    await session.execute(
                        select(CompanyWorkspace).where(
                            CompanyWorkspace.tenant_id == tenant_id,
                            CompanyWorkspace.id == wid,
                        )
                    )
                ).scalar_one_or_none()
                if row is not None:
                    captured_resources.append({
                        "resource_type": "WORKSPACE",
                        "resource_id": row.id,
                        "branch_id": row.branch_id,
                        "owner_user_id": row.owner_user_id,
                        "visibility": row.visibility,
                    })

            for mid in candidates.get("MESSAGE", []):
                row = (
                    await session.execute(
                        select(CompanyMessage).where(CompanyMessage.tenant_id == tenant_id, CompanyMessage.id == mid)
                    )
                ).scalar_one_or_none()
                if row is not None:
                    captured_resources.append({
                        "resource_type": "MESSAGE",
                        "resource_id": row.id,
                        "sender_user_id": row.sender_user_id,
                        "recipient_user_id": row.recipient_user_id,
                        "status": row.status,
                    })

            for nid in candidates.get("NOTIFICATION", []):
                row = (
                    await session.execute(
                        select(CompanyNotification).where(
                            CompanyNotification.tenant_id == tenant_id,
                            CompanyNotification.id == nid,
                        )
                    )
                ).scalar_one_or_none()
                if row is not None:
                    captured_resources.append({
                        "resource_type": "NOTIFICATION",
                        "resource_id": row.id,
                        "user_id": row.user_id,
                        "event_type": row.event_type,
                        "read_at": row.read_at.isoformat() if row.read_at else None,
                    })

            memory_snapshots: List[Dict[str, Any]] = []
            checkpoint_items: List[CheckpointItem] = []
            for mem_id in list(dict.fromkeys(memory_refs)):
                mem_rec = (
                    await session.execute(
                        select(MemoryRecord).where(MemoryRecord.tenant_id == tenant_id, MemoryRecord.id == mem_id)
                    )
                ).scalar_one_or_none()
                if mem_rec is not None:
                    mem_ver = (
                        await session.execute(
                            select(MemoryVersion).where(
                                MemoryVersion.tenant_id == tenant_id,
                                MemoryVersion.record_id == mem_rec.id,
                                MemoryVersion.version == mem_rec.current_version,
                            )
                        )
                    ).scalar_one_or_none()
                    if mem_ver is not None:
                        memory_snapshots.append({
                            "record_id": mem_rec.id,
                            "trust_state": mem_rec.trust_state,
                            "current_version": mem_rec.current_version,
                            "version_id": mem_ver.id,
                            "checksum": mem_ver.checksum,
                        })
                        checkpoint_items.append(
                            CheckpointItem(
                                id=f"chki-{uuid.uuid4().hex[:24]}",
                                tenant_id=tenant_id,
                                checkpoint_id=checkpoint_id,
                                record_id=mem_rec.id,
                                version_id=mem_ver.id,
                                checksum=mem_ver.checksum,
                            )
                        )

            snapshot = {
                **request_content,
                "proposal_id": proposal_id,
                "trace_id": trace_id,
                "request_content_hash": request_content_hash,
                "resources": captured_resources,
                "memory_snapshots": memory_snapshots,
            }
            canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
            integrity_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            db_agent_id: Optional[str] = None
            if agent_id:
                from backend.app.database.models.agents import Agent
                agent_row = (
                    await session.execute(
                        select(Agent.id).where(Agent.tenant_id == tenant_id, Agent.id == agent_id)
                    )
                ).scalar_one_or_none()
                db_agent_id = agent_row

            chk = Checkpoint(
                id=checkpoint_id,
                tenant_id=tenant_id,
                agent_id=db_agent_id,
                name=f"pre-action:{tool_name}:{operation}"[:255],
                integrity_hash=integrity_hash,
                record_count=len(captured_resources) + len(memory_snapshots),
                snapshot_data_json=snapshot,
            )
            session.add(chk)
            for item in checkpoint_items:
                session.add(item)
            await session.commit()

        # Verify durable commit in a fresh session before allowing mutation.
        async with self._session_factory() as verify_session:
            verified = (
                await verify_session.execute(
                    select(Checkpoint).where(
                        Checkpoint.tenant_id == tenant_id,
                        Checkpoint.id == checkpoint_id,
                    )
                )
            ).scalar_one_or_none()
            if verified is None or verified.integrity_hash != integrity_hash:
                raise SecurityDependencyError("Pre-action checkpoint durable commit verification failed.")

        return {
            "committed": True,
            "complete": True,
            "scope": "COMPLETE",
            "checkpoint_id": checkpoint_id,
            "integrity_hash": integrity_hash,
            "memory_refs": list(memory_refs),
            "resources": captured_resources,
        }


__all__ = [
    "InMemoryPreActionCheckpointService",
    "PreActionCheckpointService",
    "SqlPreActionCheckpointService",
]
