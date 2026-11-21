"""Runtime wiring for M4 security services inside the FastAPI app (shared by M1 routes).

Module: backend.app.security.runtime
Owner: M4 — Security Engine & Incident Response Lead

M1 routes must obtain M4 services from here instead of constructing their own logic:

- ``get_trust_evaluator(app_state, memory_repo)``: one shared ``TrustEvaluator`` per memory
  repository. Sharing matters: its per-record lock (M4-F5) only serialises transitions that go
  through the same instance.
- ``get_quarantine_workflow(app_state, memory_repo)``: the authoritative ``QuarantineWorkflow``.
- ``get_policy_engine(app_state, memory_repo)`` / ``get_execution_guard(...)``: the authoritative
  ``PolicyEngine`` and ``ProtectedExecutionGuard`` (one per trust evaluator, so the execution
  ledger and issued-grant registry are shared across requests).

The trust decision store comes from ``app_state.trust_decision_store``. When it is absent, an
in-memory store is created; ``TrustEvaluator`` itself refuses a non-durable store outside
``development``/``test`` (M4-F6), which is surfaced as ``SecurityDependencyError`` (HTTP 503).
No service ever falls back to a weaker path.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.security.policy import PolicyEngine, ProtectedExecutionGuard
from backend.app.security.quarantine import QuarantineWorkflow
from backend.app.security.trust import InMemoryTrustDecisionStore, TrustEvaluator

_lock = threading.Lock()


def _app_env(app_state: Any) -> Optional[str]:
    settings = getattr(app_state, "settings", None)
    env = getattr(settings, "APP_ENV", None)
    return env if isinstance(env, str) else None


def get_trust_evaluator(app_state: Any, memory_repo: Any) -> TrustEvaluator:
    if memory_repo is None:
        raise SecurityDependencyError("Memory repository is not configured.")
    with _lock:
        current = getattr(app_state, "trust_evaluator", None)
        if isinstance(current, TrustEvaluator) and current.repository is memory_repo:
            return current
        store = getattr(app_state, "trust_decision_store", None)
        if store is None:
            store = InMemoryTrustDecisionStore()
            app_state.trust_decision_store = store
        try:
            evaluator = TrustEvaluator(memory_repo, store, app_env=_app_env(app_state))
        except RuntimeError as exc:
            # A non-durable trust store/repository outside development/test: refuse, never degrade.
            raise SecurityDependencyError("Durable trust decision persistence is not configured.") from exc
        app_state.trust_evaluator = evaluator
        app_state.policy_engine = None          # bound to the previous evaluator
        app_state.execution_guard = None
        return evaluator


def get_quarantine_workflow(app_state: Any, memory_repo: Any) -> QuarantineWorkflow:
    return QuarantineWorkflow(get_trust_evaluator(app_state, memory_repo), memory_repo)


def get_policy_engine(app_state: Any, memory_repo: Any, tool_grants: Any) -> PolicyEngine:
    trust = get_trust_evaluator(app_state, memory_repo)
    with _lock:
        engine = getattr(app_state, "policy_engine", None)
        if isinstance(engine, PolicyEngine) and getattr(app_state, "_policy_engine_grants", None) is tool_grants:
            return engine
        engine = PolicyEngine(trust, memory_repo, tool_grants)
        app_state.policy_engine = engine
        app_state._policy_engine_grants = tool_grants
        app_state.execution_guard = ProtectedExecutionGuard(engine)
        return engine


def get_execution_guard(app_state: Any, memory_repo: Any, tool_grants: Any) -> ProtectedExecutionGuard:
    get_policy_engine(app_state, memory_repo, tool_grants)
    return app_state.execution_guard


__all__ = ["get_execution_guard", "get_policy_engine", "get_quarantine_workflow", "get_trust_evaluator"]
