"""M2 adapter and credential-containment regression tests."""

from __future__ import annotations

import pytest

from backend.app.api.gateway import SandboxTransferAdapter
from crewai_service.config.settings import CrewAISettings
from crewai_service.tools.amsc_client import ChronoCogniSecClient


@pytest.mark.asyncio
async def test_sandbox_transfer_is_synthetic_and_idempotent() -> None:
    adapter = SandboxTransferAdapter()
    proposal_context = {
        "tenant_id": "tenant-a-uuid-001",
        "agent_id": "agent-crew-finance-003",
        "idempotency_key": "idem-transfer-001",
        "trace_id": "trace-001",
    }
    parameters = {"destination_account": "ACC-LEGIT-123", "amount": "10.50", "currency": "USD"}

    first = await adapter.execute("transfer_funds", parameters, proposal_context)
    retry = await adapter.execute("transfer_funds", parameters, proposal_context)

    assert first.status == "SUCCESS"
    assert first.result_payload["status"] == "SETTLED_IN_SANDBOX"
    assert first.result_payload["transaction_id"] == retry.result_payload["transaction_id"]
    assert "credential" not in str(first.result_payload).lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "parameters",
    [
        {"destination_account": "ACC-LEGIT-123", "amount": 0, "currency": "USD"},
        {"destination_account": "ACC-LEGIT-123", "amount": "NaN", "currency": "USD"},
        {"destination_account": "ACC-ATTACKER-999", "amount": 1, "currency": "USD"},
    ],
)
async def test_sandbox_transfer_rejects_invalid_or_forbidden_requests(parameters: dict[str, object]) -> None:
    result = await SandboxTransferAdapter().execute("transfer_funds", parameters, {})
    assert result.status == "FAILED"
    assert result.status_code in {400, 403}


def test_crewai_client_fails_closed_without_backend_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    import crewai_service.tools.amsc_client as client_module

    settings = CrewAISettings(
        EXECUTION_MODE="live",
        CHRONOCONGISEC_AUTH_TOKEN=None,
        CHRONOCONGISEC_AUTH_PASSWORD=None,
    )
    monkeypatch.setattr(client_module, "get_crewai_settings", lambda: settings)
    client = ChronoCogniSecClient()

    assert client.auth_token is None
    assert client.authenticate() is False
