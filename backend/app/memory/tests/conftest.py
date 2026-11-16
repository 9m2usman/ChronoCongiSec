"""Pytest configuration for memory subsystem tests."""

import sys
from pathlib import Path

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# Import the Windows Sandbox proactor pipe patch from backend.tests.conftest
import backend.tests.conftest  # noqa: F401
