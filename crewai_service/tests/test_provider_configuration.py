"""Tests for LLM Provider Configuration & Validation Layer.

Module: crewai_service.tests.test_provider_configuration
Owner: ChronoCogniSec AI Integration Council
"""

import os
import pytest

from crewai_service.config.provider import (
    BaseLLMAdapter,
    GeminiLLMAdapter,
    OpenAILLMAdapter,
    ProviderExecutionError,
    TestDoubleLLMAdapter,
    get_llm_adapter,
)
from crewai_service.config.settings import (
    CrewAISettings,
    ExecutionMode,
    SupportedProvider,
)


def test_test_double_adapter_explicitly_labeled():
    """Verify test double is explicitly marked as non-real execution."""
    adapter = TestDoubleLLMAdapter(model="test-model")
    assert adapter.is_real_execution is False
    assert adapter.provider_name == "test_double"
    assert adapter.model_name == "test-model"

    output = adapter.complete("customer support ticket")
    assert "Customer Support Analysis" in output or "ticket_id" in output


def test_missing_gemini_credentials_raises_startup_validation_error(monkeypatch):
    """Verify startup validation fails closed when live Gemini credentials are missing."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    settings = CrewAISettings(
        EXECUTION_MODE=ExecutionMode.LIVE,
        LLM_PROVIDER=SupportedProvider.GEMINI,
        GEMINI_API_KEY=None,
    )
    with pytest.raises(ProviderExecutionError, match="GEMINI_API_KEY is not configured"):
        get_llm_adapter(settings=settings)


def test_missing_openai_credentials_raises_startup_validation_error(monkeypatch):
    """Verify startup validation fails closed when live OpenAI credentials are missing."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = CrewAISettings(
        EXECUTION_MODE=ExecutionMode.LIVE,
        LLM_PROVIDER=SupportedProvider.OPENAI,
        OPENAI_API_KEY=None,
    )
    with pytest.raises(ProviderExecutionError, match="OPENAI_API_KEY is not configured"):
        get_llm_adapter(settings=settings)


def test_model_identifier_is_configurable_via_settings():
    """Verify model identifier is dynamically configurable without code changes."""
    settings = CrewAISettings(
        EXECUTION_MODE=ExecutionMode.TEST_DOUBLE,
        LLM_PROVIDER=SupportedProvider.TEST_DOUBLE,
        LLM_MODEL="gemini-2.0-flash-custom",
    )
    adapter = get_llm_adapter(settings=settings)
    assert adapter.model_name == "gemini-2.0-flash-custom"


def test_provider_adapter_is_replaceable_without_rewriting_agents():
    """Verify any BaseLLMAdapter can be injected into any agent without code changes."""
    class CustomMockLLM(BaseLLMAdapter):
        @property
        def is_real_execution(self) -> bool:
            return False

        @property
        def provider_name(self) -> str:
            return "custom_mock"

        @property
        def model_name(self) -> str:
            return "custom-v1"

        def complete(self, prompt: str) -> str:
            return "Custom mock response"

        def generate_structured(self, prompt: str, schema):
            return schema.model_validate({"ticket_id": "cust-1", "classification": "GENERAL", "priority": "LOW", "resolution_text": "OK", "action_taken": "NONE"})

    custom_adapter = CustomMockLLM()
    assert isinstance(custom_adapter, BaseLLMAdapter)
    assert custom_adapter.complete("hello") == "Custom mock response"
