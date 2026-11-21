"""Runtime wiring for M4 security services inside the FastAPI app (shared by M1 routes).

Module: backend.app.security.runtime
Owner: M4 — Security Engine & Incident Response Lead

M1 routes must obtain M4 services from here instead of constructing their own logic:

- ``get_trust_evaluator(app_state, memory_repo)``: one shared ``TrustEvaluator`` per memory
  repository. Sharing matters: its per-record lock (M4-F5) only serialises transitions that go
  through the same instance.
- ``get_quarantine_workflow(app_state, memory_repo)``: the authoritative ``QuarantineWorkflow``.
- ``get_gateway_enforcement(app_state, memory_repo, agent_repo, tool_registry)``: the authoritative
  ``PolicyEngine`` and ``ProtectedExecutionGuard`` for the gateway, cached so the execution ledger
  and issued-grant registry (M4-F1) are shared across requests.

The trust decision store comes from ``app_state.trust_decision_store``. When it is absent, an
in-memory store is created; ``TrustEvaluator`` itself refuses a non-durable store outside
``development``/``test`` (M4-F6), which is surfaced as ``SecurityDependencyError`` (HTTP 503).
No service ever falls back to a weaker path.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.security.policy import PolicyEngine, ProtectedExecutionGuard, ToolGrant
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
        return evaluator


def get_quarantine_workflow(app_state: Any, memory_repo: Any) -> QuarantineWorkflow:
    return QuarantineWorkflow(get_trust_evaluator(app_state, memory_repo), memory_repo)


class AgentRegistryDirectory:
    """M4 ``AgentDirectory`` port over M1's agent registry (``get_agent_by_id``, async)."""

    def __init__(self, agent_repo: Any) -> None:
        self._repo = agent_repo

    async def get_agent(self, agent_id: str, tenant_id: str) -> Any:
        return await self._repo.get_agent_by_id(agent_id, tenant_id)


class AgentRegistryToolGrants:
    """M4 ``ToolGrantDirectory`` port over M1's agent registry and tool adapter registry.

    Permission records (``agent_repo.get_agent_tool_permissions``) must be mappings with
    ``tool_name``, ``allowed_operations`` (list of operation names) and optional ``constraints``
    (M4 keys: ``max_*``, ``min_*``, ``approval_threshold_*``, ``allowed_*``). No record, or a
    malformed one, means no grant: the engine blocks with TOOL_NOT_ASSIGNED (fail closed). A tool
    without a server-side adapter is reported as not registered.
    """

    def __init__(self, agent_repo: Any, tool_registry: Any) -> None:
        self._repo, self._tools = agent_repo, tool_registry

    async def get_tool_grant(self, tenant_id: str, agent_id: str, tool_name: str) -> Optional[ToolGrant]:
        permissions = await self._repo.get_agent_tool_permissions(agent_id, tenant_id)
        for perm in permissions or ():
            if not isinstance(perm, dict) or perm.get("tool_name") != tool_name:
                continue
            ops = perm.get("allowed_operations")
            constraints = perm.get("constraints") or {}
            if not isinstance(ops, (list, tuple)) or not isinstance(constraints, dict):
                return None
            registered = bool(self._tools is not None and self._tools.get_adapter(tool_name) is not None)
            return ToolGrant(tool_name=tool_name, allowed_operations=tuple(ops), constraints=dict(constraints),
                             tool_registered=registered)
        return None


def get_gateway_enforcement(app_state: Any, memory_repo: Any, agent_repo: Any,
                            tool_registry: Any) -> "tuple[PolicyEngine, ProtectedExecutionGuard]":
    """The authoritative engine and guard for the M1 gateway, cached per (memory, agents, tools).

    Caching keeps M4's issued-grant registry and execution ledger (M4-F1) across requests.
    """
    if agent_repo is None:
        raise SecurityDependencyError("Agent registry is not configured.")
    trust = get_trust_evaluator(app_state, memory_repo)
    key = (id(trust), id(agent_repo), id(tool_registry))
    with _lock:
        cached = getattr(app_state, "_gateway_enforcement", None)
        if cached is not None and cached[0] == key:
            return cached[1], cached[2]
        engine = PolicyEngine(trust, AgentRegistryDirectory(agent_repo), AgentRegistryToolGrants(agent_repo, tool_registry))
        guard = ProtectedExecutionGuard(engine)
        app_state._gateway_enforcement = (key, engine, guard)
        return engine, guard


__all__ = ["AgentRegistryDirectory", "AgentRegistryToolGrants", "get_gateway_enforcement",
           "get_quarantine_workflow", "get_trust_evaluator"]
