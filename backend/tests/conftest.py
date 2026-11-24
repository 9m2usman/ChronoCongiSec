import os
os.environ.setdefault("EXECUTION_MODE", "test_double")
os.environ.setdefault("LLM_PROVIDER", "test_double")
"""Pytest Configuration and Platform-Specific Environment Fixtures.

Module: backend.tests.conftest
Owner: M1 / M7
"""


# Windows Sandbox loopback socket fallback for ProactorEventLoop inter-thread signaling
import backend.app.core.windows_compat  # noqa: F401
