"""CrewAI Service Configuration & Environment Settings.

Module: crewai_service.config.settings
Owner: ChronoCogniSec CrewAI Architect

Provides typed, validated configuration supporting local dev, automated testing,
and future cloud deployment.
"""

from enum import Enum
import os
from pathlib import Path
from typing import Dict, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SERVICE_DIR = Path(__file__).resolve().parent.parent
_SERVICE_ENV = _SERVICE_DIR / ".env"


class ExecutionMode(str, Enum):
    LIVE = "live"
    TEST_DOUBLE = "test_double"


class SupportedProvider(str, Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    TEST_DOUBLE = "test_double"


class EnterpriseBranch(str, Enum):
    HEAD_OFFICE = "branch-ho-001"
    LAHORE = "branch-lhr-002"
    KARACHI = "branch-khi-003"
    ISLAMABAD = "branch-isb-004"


class CrewAISettings(BaseSettings):
    """Central configuration for CrewAI agents and platform integration."""

    model_config = SettingsConfigDict(
        env_file=(_SERVICE_ENV, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Execution Mode & Provider ---
    EXECUTION_MODE: ExecutionMode = ExecutionMode.LIVE
    LLM_PROVIDER: SupportedProvider = SupportedProvider.GEMINI
    LLM_MODEL: str = "gemini-1.5-flash"

    # --- Credentials (Configured securely via environment) ---
    GEMINI_API_KEY: Optional[str] = Field(default_factory=lambda: os.environ.get("GEMINI_API_KEY"))
    OPENAI_API_KEY: Optional[str] = Field(default_factory=lambda: os.environ.get("OPENAI_API_KEY"))
    ANTHROPIC_API_KEY: Optional[str] = Field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY"))
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # --- ChronoCogniSec Platform Integration ---
    CHRONOCONGISEC_API_BASE_URL: str = "http://127.0.0.1:8000/api/v1"
    CHRONOCONGISEC_TENANT_ID: str = "tenant-a-uuid-001"
    CHRONOCONGISEC_AUTH_TOKEN: Optional[str] = None

    # --- Enterprise Simulated Branches ---
    DEFAULT_BRANCH_ID: str = EnterpriseBranch.HEAD_OFFICE.value
    LAHORE_BRANCH_ID: str = EnterpriseBranch.LAHORE.value
    KARACHI_BRANCH_ID: str = EnterpriseBranch.KARACHI.value
    ISLAMABAD_BRANCH_ID: str = EnterpriseBranch.ISLAMABAD.value

    # --- Guardrails & Governance ---
    AGENT_EXECUTION_TIMEOUT_SECONDS: int = 60
    MAX_SUBTASK_DELEGATIONS: int = 5
    DUAL_CUSTODY_FINANCE_THRESHOLD_USD: float = 300.00
    FAIL_CLOSED_ON_SECURITY_ANOMALY: bool = True

    @property
    def branch_map(self) -> Dict[str, str]:
        return {
            "HEAD_OFFICE": self.DEFAULT_BRANCH_ID,
            "LAHORE": self.LAHORE_BRANCH_ID,
            "KARACHI": self.KARACHI_BRANCH_ID,
            "ISLAMABAD": self.ISLAMABAD_BRANCH_ID,
        }

    def validate_provider_configuration(self) -> None:
        """Validate that credentials exist for the selected provider when in live mode."""
        if self.EXECUTION_MODE == ExecutionMode.TEST_DOUBLE or self.LLM_PROVIDER == SupportedProvider.TEST_DOUBLE:
            return

        if self.LLM_PROVIDER == SupportedProvider.GEMINI:
            if not self.GEMINI_API_KEY:
                raise ValueError(
                    "Startup validation failure: LLM_PROVIDER is set to 'gemini' but GEMINI_API_KEY is not configured."
                )
        elif self.LLM_PROVIDER == SupportedProvider.OPENAI:
            if not self.OPENAI_API_KEY:
                raise ValueError(
                    "Startup validation failure: LLM_PROVIDER is set to 'openai' but OPENAI_API_KEY is not configured."
                )
        elif self.LLM_PROVIDER == SupportedProvider.ANTHROPIC:
            if not self.ANTHROPIC_API_KEY:
                raise ValueError(
                    "Startup validation failure: LLM_PROVIDER is set to 'anthropic' but ANTHROPIC_API_KEY is not configured."
                )


_settings_instance: Optional[CrewAISettings] = None


def get_crewai_settings() -> CrewAISettings:
    """Return singleton configuration instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = CrewAISettings()
    return _settings_instance
