from pathlib import Path

import pytest

from chronocongisec.security.audit import JsonlHashChainAuditSink
from chronocongisec.security.gateway import (
    AgentPrincipal,
    GatewayDenied,
    MemoryEvidence,
    ToolGovernanceGateway,
    ToolProposal,
    ToolSpec,
)


@pytest.fixture
def setup_gateway(tmp_path: Path):
    calls = []
    sink = JsonlHashChainAuditSink(tmp_path / "audit.jsonl")
    gateway = ToolGovernanceGateway(
        sink,
        (
            ToolSpec(
                name="notes.read",
                required_capabilities=frozenset({"notes:read"}),
                validate_arguments=lambda args: (
                    None if set(args) == {"note_id"} and isinstance(args["note_id"], str)
                    else (_ for _ in ()).throw(ValueError("invalid arguments"))
                ),
                handler=lambda args: calls.append(args["note_id"]) or {"note_id": args["note_id"]},
            ),
        ),
    )
    principal = AgentPrincipal("tenant-a", "agent-a", frozenset({"notes:read"}))
    return gateway, sink, principal, calls


def test_trusted_memory_and_capability_allow_execution(setup_gateway):
    gateway, sink, principal, calls = setup_gateway
    outcome = gateway.execute(
        principal,
        ToolProposal(
            "notes.read",
            {"note_id": "n-1"},
            memory_evidence=(MemoryEvidence("m-1", "tenant-a", "TRUSTED"),),
        ),
    )
    assert outcome.executed is True
    assert outcome.audit_complete is True
    assert calls == ["n-1"]
    assert sink.verify()["valid"] is True


@pytest.mark.parametrize(
    "evidence,expected",
    [
        (MemoryEvidence("m-1", "tenant-a", "QUARANTINED"), "untrusted_or_quarantined_memory"),
        (MemoryEvidence("m-2", "tenant-b", "TRUSTED"), "cross_tenant_memory_reference"),
    ],
)
def test_untrusted_or_cross_tenant_memory_blocks_adapter(setup_gateway, evidence, expected):
    gateway, sink, principal, calls = setup_gateway
    with pytest.raises(GatewayDenied, match=expected):
        gateway.execute(principal, ToolProposal("notes.read", {"note_id": "n-1"}, memory_evidence=(evidence,)))
    assert calls == []
    assert sink.verify()["event_count"] == 1


def test_missing_capability_blocks_adapter(setup_gateway):
    gateway, sink, _, calls = setup_gateway
    principal = AgentPrincipal("tenant-a", "agent-a", frozenset())
    with pytest.raises(GatewayDenied, match="missing_capability"):
        gateway.execute(principal, ToolProposal("notes.read", {"note_id": "n-1"}))
    assert calls == []


def test_invalid_arguments_block_adapter(setup_gateway):
    gateway, sink, principal, calls = setup_gateway
    with pytest.raises(GatewayDenied, match="invalid_tool_arguments"):
        gateway.execute(principal, ToolProposal("notes.read", {"note_id": 12}))
    assert calls == []


def test_hash_chain_detects_interior_tampering(setup_gateway):
    _, sink, _, _ = setup_gateway
    sink.append({"event_type": "TEST", "value": "original"})
    sink.append({"event_type": "TEST", "value": "second"})
    lines = sink.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("original", "modified")
    sink.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert sink.verify()["valid"] is False


def test_unknown_tool_is_denied(setup_gateway):
    gateway, _, principal, calls = setup_gateway
    with pytest.raises(GatewayDenied, match="unknown_or_disabled_tool"):
        gateway.execute(principal, ToolProposal("shell.exec", {"command": "blocked"}))
    assert calls == []
