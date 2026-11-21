"""Audit actor identities for M4-written audit events (OD-9).

Module: backend.app.security.audit_identity
Owner: M4 — Security Engine & Incident Response Lead

``audit_events`` is append-only and hash-chained (M6 migration 0009), so a wrong actor value can
never be corrected. Every audit event M4 writes therefore names its actor in the M4/M6 contract
format (``docs/security-design/m6-integration-decisions.md`` §3.4):

- ``user:<users.id>``      a human, taken from M1's verified ``TenantContext.user_id``;
- ``agent:<agents.id>``    a registered agent;
- ``system:<component>``   an M4 server process, from the fixed ``SYSTEM_COMPONENTS`` list.

Identities are built only from trusted, server-side values. Request bodies, headers or query
parameters are never an input. A value that does not fit the format raises ``ValueError`` so the
caller fails closed before anything is written (finding M4-F4).
"""

import re
from typing import FrozenSet

# Mirrors the NOT VALID CHECK proposed to M6 for audit_events.actor_id.
_PRINCIPAL_ID = re.compile(r"[A-Za-z0-9_.:-]{1,120}")
SYSTEM_COMPONENTS: FrozenSet[str] = frozenset({
    "gateway", "policy-engine", "trust-evaluator", "quarantine", "drift-monitor", "recovery", "reconciler",
})


def _principal(kind: str, value: object) -> str:
    if type(value) is not str or not _PRINCIPAL_ID.fullmatch(value):
        raise ValueError(f"Invalid {kind} identifier for an audit actor.")
    return f"{kind}:{value}"


def user_actor(user_id: object) -> str:
    """``user:<id>`` for a human principal (the verified ``TenantContext.user_id``)."""
    return _principal("user", user_id)


def agent_actor(agent_id: object) -> str:
    """``agent:<id>`` for a registered agent."""
    return _principal("agent", agent_id)


def system_actor(component: object) -> str:
    """``system:<component>`` for an M4 server process; only the fixed components are allowed."""
    if type(component) is not str or component not in SYSTEM_COMPONENTS:
        raise ValueError("Unknown system component for an audit actor.")
    return f"system:{component}"


__all__ = ["SYSTEM_COMPONENTS", "agent_actor", "system_actor", "user_actor"]
