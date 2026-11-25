import os
os.environ.setdefault("EXECUTION_MODE", "test_double")
os.environ.setdefault("LLM_PROVIDER", "test_double")
"""Pytest Configuration and Platform-Specific Environment Fixtures.

Module: backend.tests.conftest
Owner: M1 / M7
"""


# Windows Sandbox loopback socket fallback for ProactorEventLoop inter-thread signaling
import backend.app.core.windows_compat  # noqa: F401


# TEMPORARY (Phase 3 CI diagnosis, to be removed): surface failures as GitHub
# annotations because job logs are not readable without credentials.
if os.environ.get("GITHUB_ACTIONS") == "true":
    import sys as _sys

    import pytest as _pytest

    @_pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(item, call):
        outcome = yield
        rep = outcome.get_result()
        if rep.failed:
            text = str(rep.longrepr)[-1800:].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
            _sys.__stdout__.write(f"::error title={item.nodeid[:180]}::{text}\n")
            _sys.__stdout__.flush()
