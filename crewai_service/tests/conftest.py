"""Pytest Test Configuration and Shared Fixtures for CrewAI Service.

Module: crewai_service.tests.conftest
Owner: ChronoCogniSec QA Council
"""

import os
import pytest

from crewai_service.config.provider import TestDoubleLLMAdapter
from crewai_service.config.settings import (
    CrewAISettings,
    ExecutionMode,
    SupportedProvider,
)
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient


@pytest.fixture(autouse=True)
def clean_telemetry_and_test_settings(monkeypatch):
    """Ensure telemetry accumulator is clean and settings use test double by default."""
    import crewai_service.config.settings as s_mod
    tracer = get_tracer()
    tracer.clear()

    # Save original settings
    orig_settings = s_mod._settings_instance
    s_mod._settings_instance = CrewAISettings(
        EXECUTION_MODE=ExecutionMode.TEST_DOUBLE,
        LLM_PROVIDER=SupportedProvider.TEST_DOUBLE,
        LLM_MODEL="test-double-deterministic",
        CHRONOCONGISEC_API_BASE_URL="http://127.0.0.1:8000/api/v1",
        CHRONOCONGISEC_TENANT_ID="tenant-a-uuid-001",
        DEFAULT_BRANCH_ID="branch-ho-001",
        LAHORE_BRANCH_ID="branch-lhr-002",
        KARACHI_BRANCH_ID="branch-khi-003",
        ISLAMABAD_BRANCH_ID="branch-isb-004",
    )

    yield

    s_mod._settings_instance = orig_settings
    tracer.clear()


@pytest.fixture
def test_settings() -> CrewAISettings:
    """Settings configured for deterministic test double execution."""
    return CrewAISettings(
        EXECUTION_MODE=ExecutionMode.TEST_DOUBLE,
        LLM_PROVIDER=SupportedProvider.TEST_DOUBLE,
        LLM_MODEL="test-double-deterministic",
        CHRONOCONGISEC_API_BASE_URL="http://127.0.0.1:8000/api/v1",
        CHRONOCONGISEC_TENANT_ID="tenant-a-uuid-001",
        DEFAULT_BRANCH_ID="branch-ho-001",
        LAHORE_BRANCH_ID="branch-lhr-002",
        KARACHI_BRANCH_ID="branch-khi-003",
        ISLAMABAD_BRANCH_ID="branch-isb-004",
    )


@pytest.fixture
def test_double_llm() -> TestDoubleLLMAdapter:
    """Deterministic test double LLM adapter."""
    return TestDoubleLLMAdapter(model="test-double-deterministic")


@pytest.fixture
def mock_amsc_client(monkeypatch) -> ChronoCogniSecClient:
    """Client configured with mock HTTP responses for offline unit testing."""
    client = ChronoCogniSecClient()

    # Provide deterministic mock implementations for offline unit tests
    def mock_query_trusted(agent_id=None, limit=50, offset=0):
        return [
            {
                "id": "mem-supp-faq-001",
                "tenant_id": "tenant-a-uuid-001",
                "agent_id": "agent-crew-support-001",
                "trust_state": "TRUSTED",
                "content": (
                    "ChronoCogniSec Return & Refund Policy:\n"
                    "Full refund permitted within 14 calendar days of purchase with valid receipt. "
                    "Disbursements over $300 require dual-custody managerial approval."
                ),
            },
            {
                "id": "mem-hr-pol-001",
                "tenant_id": "tenant-a-uuid-001",
                "agent_id": "agent-crew-hr-002",
                "trust_state": "TRUSTED",
                "content": (
                    "ChronoCogniSec HR Handbook:\n"
                    "Annual leave entitlement is 22 working days per year for full-time employees. "
                    "Sick leave up to 10 days with certificate required after 2 days."
                ),
            },
            {
                "id": "mem-fin-proc-001",
                "tenant_id": "tenant-a-uuid-001",
                "agent_id": "agent-crew-finance-003",
                "trust_state": "TRUSTED",
                "content": (
                    "ChronoCogniSec Financial Governance:\n"
                    "Disbursements and reimbursements over $300.00 USD strictly require dual-custody "
                    "approval from a Finance Manager. Self-approval is strictly forbidden."
                ),
            },
        ]

    def mock_propose_action(
        agent_id,
        tool_name,
        operation,
        parameters,
        memory_refs=None,
        action_id=None,
        idempotency_key=None,
        trace_id=None,
    ):
        amount = float(parameters.get("amount", 0.0))
        # Enforce $300 ceiling rule
        if amount > 300.00:
            return {
                "action_id": action_id or "act-test",
                "proposal_id": "prop-test-blocked",
                "decision": "BLOCK",
                "memory_trust": "TRUSTED",
                "policy_result": "DENIED",
                "reasons": [
                    f"Action amount (${amount:.2f}) exceeds dual-custody threshold ($300.00)."
                ],
                "execution_status": "NOT_EXECUTED",
            }
        return {
            "action_id": action_id or "act-test",
            "proposal_id": "prop-test-allowed",
            "decision": "ALLOW",
            "memory_trust": "TRUSTED",
            "policy_result": "PERMITTED",
            "reasons": ["All authorization and operational ceiling checks passed."],
            "execution_status": "EXECUTED",
            "result": {
                "transaction_id": "tx-sbx-mock-001",
                "amount": amount,
                "status": "SETTLED_IN_SANDBOX",
            },
        }

    monkeypatch.setattr(client, "query_trusted_memory", mock_query_trusted)
    monkeypatch.setattr(client, "propose_tool_action", mock_propose_action)
    return client
