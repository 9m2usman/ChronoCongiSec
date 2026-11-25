"""Pre-action checkpoint contracts for protected gateway mutations.

Production adapters must snapshot every affected company resource and memory
reference into durable storage before the gateway dispatches an adapter. The
in-memory implementation is for tests/development only and records proposal
metadata; it is never accepted by production startup or execution.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Protocol


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
        canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
        integrity_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        existing = self._snapshots.get(checkpoint_id)
        if existing is not None and existing["integrity_hash"] != integrity_hash:
            raise ValueError("Checkpoint idempotency key was reused with different proposal data.")
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


__all__ = ["InMemoryPreActionCheckpointService", "PreActionCheckpointService"]
