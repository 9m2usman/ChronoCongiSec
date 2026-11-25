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

    def _annotate(nodeid, longrepr):
        text = str(longrepr)[-1800:].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        title = nodeid.replace("::", " ").replace(",", " ")[:180]
        _sys.__stdout__.write(f"::error title={title}::{text}\n")
        _sys.__stdout__.flush()

    @_pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(item, call):
        outcome = yield
        rep = outcome.get_result()
        if rep.failed:
            _annotate(item.nodeid, rep.longrepr)

    def pytest_collectreport(report):
        if report.failed:
            _annotate(report.nodeid or "collection", report.longrepr)
