"""Phase 4 pre-action checkpoint contract tests."""

import pytest

from backend.app.security.checkpoints import InMemoryPreActionCheckpointService


@pytest.mark.asyncio
async def test_development_checkpoint_is_idempotent_and_explicitly_metadata_only():
    service = InMemoryPreActionCheckpointService()
    values = {
        "tenant_id": "tenant-a",
        "branch_id": "branch-lahore",
        "actor_id": "analyst-a",
        "agent_id": "agent-a",
        "proposal_id": "proposal-a",
        "action_id": "action-a",
        "trace_id": "trace-a",
        "idempotency_key": "idempotency-a",
        "tool_name": "company_file",
        "operation": "read",
        "parameters": {"file_id": "file-a"},
        "memory_refs": ["memory-a"],
    }

    first = await service.capture_pre_action_checkpoint(**values)
    retry_values = {**values, "proposal_id": "proposal-retry"}
    second = await service.capture_pre_action_checkpoint(**retry_values)

    assert first["committed"] is True
    assert first["complete"] is False
    assert first["scope"] == "PROPOSAL_METADATA_ONLY"
    assert first["checkpoint_id"] == second["checkpoint_id"]
    assert first["integrity_hash"] == second["integrity_hash"]
    assert service.is_in_memory is True
    assert service.is_persistent is False


@pytest.mark.asyncio
async def test_checkpoint_rejects_idempotency_key_reuse_with_changed_proposal():
    service = InMemoryPreActionCheckpointService()
    values = {
        "tenant_id": "tenant-a",
        "branch_id": "branch-lahore",
        "actor_id": "analyst-a",
        "agent_id": "agent-a",
        "proposal_id": "proposal-a",
        "action_id": "action-a",
        "trace_id": "trace-a",
        "idempotency_key": "idempotency-a",
        "tool_name": "company_file",
        "operation": "read",
        "parameters": {"file_id": "file-a"},
        "memory_refs": ["memory-a"],
    }
    await service.capture_pre_action_checkpoint(**values)
    values["parameters"] = {"file_id": "different-file"}

    with pytest.raises(ValueError, match="reused with different proposal data"):
        await service.capture_pre_action_checkpoint(**values)
