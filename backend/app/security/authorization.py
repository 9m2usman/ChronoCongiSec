"""Deterministic, default-deny Role-Based Access Control (RBAC) evaluator.

Module: backend.app.security.authorization
Owner: M4 — Security Engine & Incident Response Lead

Implements the M4 Day 2 deliverable from ``docs/06-TEAM-IMPLEMENTATION-PLAN.md`` (basic RBAC
check; exit criterion: unauthorized roles rejected with HTTP 403), aligned on 2026-11-19 to the
canonical project role vocabulary (PRD FR-003, TRD §11, Doc 04, Doc 05): TENANT_ADMIN,
SECURITY_ANALYST, AI_DEVELOPER, AUDITOR. Doc 06's "DEVELOPER" was shorthand for AI_DEVELOPER;
it is not an alias and is denied as an unknown role (finding M4-F2).

Design (see ``docs/security-design/rbac-design.md``):

* **Trusted input only.** The only source of identity, tenant and role is M1's
  server-verified, immutable ``TenantContext`` (role read from the membership
  repository, never from JWT claims, headers, query parameters or bodies).
* **Default deny.** ``evaluate_role_access`` starts from DENY and returns ALLOW only
  when every check passes. Any unexpected error yields DENY (fail closed).
* **Closed role vocabulary.** Only the four canonical roles are recognized. Unknown,
  unsupported, malformed or missing roles are denied. Matching is exact: no case
  folding, trimming, aliasing or role hierarchy (TENANT_ADMIN does not implicitly
  satisfy other roles' requirements).
* **Explicit policy.** An empty or invalid allowed-role set is a configuration error;
  it is rejected when a route dependency is defined and denied at evaluation time.
  An absent policy never means "everyone".
* **Tenant-scoped.** Authorization is evaluated inside the authenticated tenant only.
  Callers that act on a tenant-addressed resource pass ``expected_tenant_id`` (taken
  from the server-side resource, never from client input) and a mismatch is denied.
* **Stateless.** No module-level mutable state and no caching of decisions, so no
  cross-request, cross-user or cross-tenant leakage.

RBAC is one layer only. It does not replace object-level ownership checks, memory
trust checks, the policy engine or protected-tool authorization.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, FrozenSet, Iterable, Optional, Tuple, Union

from fastapi import Depends

from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import ForbiddenError
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.authorization")


class Role(str, Enum):
    """The canonical project roles (PRD FR-003, TRD §11). Recognition grants nothing by itself:
    every protected operation names its own allow-list.

    - ``TENANT_ADMIN``: tenant governance; may also act as a security operator.
    - ``SECURITY_ANALYST``: triage, review, quarantine, forensic access, recovery.
    - ``AI_DEVELOPER``: agent configuration and action-proposal submission; no security
      operations, no approvals, no forensic access.
    - ``AUDITOR``: read-only (audit evidence and security read views); never mutates state,
      never approves, never proposes.
    """

    TENANT_ADMIN = "TENANT_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AI_DEVELOPER = "AI_DEVELOPER"
    AUDITOR = "AUDITOR"


RECOGNIZED_ROLES: FrozenSet[str] = frozenset(role.value for role in Role)

# Shared allow-lists (least privilege). Kept here so every M4 module uses the same sets.
SECURITY_OPERATOR_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)
READER_ROLES: Tuple[Role, ...] = (Role.TENANT_ADMIN, Role.SECURITY_ANALYST, Role.AI_DEVELOPER, Role.AUDITOR)
PROPOSER_ROLES: Tuple[Role, ...] = (Role.AI_DEVELOPER,)

# memberships.role is VARCHAR(64) (Doc 05 §3.1); canonical role names are upper snake case.
MAX_ROLE_LENGTH = 64
# Used with fullmatch(): "$" alone would accept a trailing newline.
_ROLE_SHAPE = re.compile(r"[A-Z][A-Z_]{0,63}")


class AuthorizationReason(str, Enum):
    """Machine-readable reason codes. Logged server-side; never returned to clients."""

    ROLE_PERMITTED = "ROLE_PERMITTED"
    POLICY_MISSING = "POLICY_MISSING"
    POLICY_INVALID = "POLICY_INVALID"
    CONTEXT_MISSING = "CONTEXT_MISSING"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    CONTEXT_INACTIVE = "CONTEXT_INACTIVE"
    TENANT_MISSING = "TENANT_MISSING"
    USER_MISSING = "USER_MISSING"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    ROLE_MISSING = "ROLE_MISSING"
    ROLE_MALFORMED = "ROLE_MALFORMED"
    ROLE_UNRECOGNIZED = "ROLE_UNRECOGNIZED"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    EVALUATION_ERROR = "EVALUATION_ERROR"


@dataclass(frozen=True)
class AuthorizationDecision:
    """Immutable result of one RBAC evaluation.

    ``role`` is populated only when the role was recognized, so malformed or
    attacker-influenced values are never echoed into logs or audit records.
    """

    allowed: bool
    reason: AuthorizationReason
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None


RoleSpec = Union[Role, str]


class AuthorizationPolicyError(ValueError):
    """Raised when an allowed-role policy is empty or references unrecognized roles."""


def _is_plain_role_string(value: object) -> bool:
    """Accept only exact ``str`` or ``Role`` members (rejects str subclasses with custom __eq__)."""
    return type(value) is str or type(value) is Role


def _is_nonempty_identifier(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def normalize_allowed_roles(allowed_roles: Iterable[RoleSpec]) -> FrozenSet[str]:
    """Validate an allowed-role policy and return it as an immutable set of role values.

    Raises:
        AuthorizationPolicyError: if the policy is empty, is a bare string (which would
            otherwise be iterated character by character), or contains any value that
            is not exactly one of the recognized roles.
    """
    if allowed_roles is None or isinstance(allowed_roles, (str, bytes)):
        raise AuthorizationPolicyError(
            "Allowed roles must be a non-empty collection of recognized roles."
        )
    try:
        candidates = tuple(allowed_roles)
    except TypeError as exc:
        raise AuthorizationPolicyError("Allowed roles must be iterable.") from exc

    if not candidates:
        raise AuthorizationPolicyError(
            "Allowed roles must not be empty; an absent policy never grants access."
        )

    normalized = set()
    for candidate in candidates:
        if not _is_plain_role_string(candidate):
            raise AuthorizationPolicyError("Allowed roles must be strings or Role members.")
        value = candidate.value if isinstance(candidate, Role) else candidate
        if value not in RECOGNIZED_ROLES:
            raise AuthorizationPolicyError(
                f"Allowed roles contain an unrecognized role; recognized roles: {sorted(RECOGNIZED_ROLES)}."
            )
        normalized.add(value)
    return frozenset(normalized)


def _classify_role(role: object) -> tuple[Optional[str], Optional[AuthorizationReason]]:
    """Return ``(role_value, None)`` for a recognized role, else ``(None, deny_reason)``."""
    if role is None or (type(role) is str and role == ""):
        return None, AuthorizationReason.ROLE_MISSING
    if not _is_plain_role_string(role):
        return None, AuthorizationReason.ROLE_MALFORMED
    value = role.value if isinstance(role, Role) else role
    if value in RECOGNIZED_ROLES:
        return value, None
    if len(value) > MAX_ROLE_LENGTH or not _ROLE_SHAPE.fullmatch(value):
        return None, AuthorizationReason.ROLE_MALFORMED
    return None, AuthorizationReason.ROLE_UNRECOGNIZED


def _deny(
    reason: AuthorizationReason,
    context: Optional[TenantContext] = None,
    role: Optional[str] = None,
) -> AuthorizationDecision:
    tenant_id = getattr(context, "tenant_id", None) if isinstance(context, TenantContext) else None
    user_id = getattr(context, "user_id", None) if isinstance(context, TenantContext) else None
    return AuthorizationDecision(
        allowed=False,
        reason=reason,
        tenant_id=tenant_id if type(tenant_id) is str else None,
        user_id=user_id if type(user_id) is str else None,
        role=role,
    )


def evaluate_role_access(
    context: Optional[TenantContext],
    allowed_roles: Iterable[RoleSpec],
    *,
    expected_tenant_id: Optional[str] = None,
) -> AuthorizationDecision:
    """Evaluate whether a verified tenant context may perform an operation.

    This is a total function: it never raises. Every failure, including an internal
    error, produces a DENY decision.

    Args:
        context: M1's server-verified ``TenantContext`` for the current request.
        allowed_roles: The roles explicitly permitted for the operation.
        expected_tenant_id: Optional tenant that owns the target resource, obtained
            from server-side state. If supplied, it must equal ``context.tenant_id``.

    Returns:
        An immutable ``AuthorizationDecision``.
    """
    try:
        roles_input: object = allowed_roles
        if roles_input is not None and not isinstance(roles_input, (str, bytes)):
            try:
                roles_input = tuple(roles_input)  # materialize once (generators are single-pass)
            except TypeError:
                pass
        if roles_input is None or roles_input == ():
            return _deny(AuthorizationReason.POLICY_MISSING, context)
        try:
            policy = normalize_allowed_roles(roles_input)  # type: ignore[arg-type]
        except AuthorizationPolicyError:
            return _deny(AuthorizationReason.POLICY_INVALID, context)

        if context is None:
            return _deny(AuthorizationReason.CONTEXT_MISSING)
        if not isinstance(context, TenantContext):
            return _deny(AuthorizationReason.CONTEXT_INVALID)
        if context.is_active is not True:
            return _deny(AuthorizationReason.CONTEXT_INACTIVE, context)
        if not _is_nonempty_identifier(context.tenant_id):
            return _deny(AuthorizationReason.TENANT_MISSING, context)
        if not _is_nonempty_identifier(context.user_id):
            return _deny(AuthorizationReason.USER_MISSING, context)

        if expected_tenant_id is not None and (
            not _is_nonempty_identifier(expected_tenant_id)
            or expected_tenant_id != context.tenant_id
        ):
            return _deny(AuthorizationReason.TENANT_MISMATCH, context)

        role_value, role_problem = _classify_role(context.role)
        if role_problem is not None:
            return _deny(role_problem, context)

        if role_value not in policy:
            return _deny(AuthorizationReason.ROLE_NOT_PERMITTED, context, role=role_value)

        return AuthorizationDecision(
            allowed=True,
            reason=AuthorizationReason.ROLE_PERMITTED,
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            role=role_value,
        )
    except Exception:  # noqa: BLE001 — fail closed on any unexpected error
        logger.exception("RBAC evaluation error; access denied (fail closed).")
        return _deny(AuthorizationReason.EVALUATION_ERROR)


def authorize(
    context: Optional[TenantContext],
    allowed_roles: Iterable[RoleSpec],
    *,
    expected_tenant_id: Optional[str] = None,
) -> TenantContext:
    """Enforce an RBAC decision, returning the context on ALLOW.

    Raises:
        ForbiddenError: (HTTP 403, code ``FORBIDDEN_ACTION``) on any DENY. M1's global
            handler returns only the allowlisted public message, so reason codes and
            role mappings are never exposed to the client.
    """
    decision = evaluate_role_access(context, allowed_roles, expected_tenant_id=expected_tenant_id)
    if decision.allowed:
        return context  # type: ignore[return-value]  # allowed implies a valid TenantContext

    logger.warning(
        "RBAC denied: reason=%s tenant_id=%s user_id=%s role=%s",
        decision.reason.value,
        decision.tenant_id,
        decision.user_id,
        decision.role,
    )
    raise ForbiddenError(f"Authorization denied ({decision.reason.value}).")


def require_role_access(*allowed_roles: RoleSpec) -> Callable[..., object]:
    """FastAPI dependency factory enforcing the M4 RBAC evaluator on a route.

    The policy is validated when the route is defined, so an empty or misspelled role
    list fails at application start-up instead of silently allowing or denying.

    Authentication and tenant resolution are delegated to M1's ``get_tenant_context``
    (401 for missing/invalid credentials, 403 for tenant/membership violations, 503
    when the auth repository is unavailable); this dependency then applies RBAC (403).

    Example::

        @router.post("/memory/{id}/quarantine")
        async def quarantine(ctx: TenantContext = Depends(require_role_access(Role.SECURITY_ANALYST))):
            ...
    """
    policy = normalize_allowed_roles(allowed_roles)

    async def rbac_dependency(
        context: TenantContext = Depends(get_tenant_context),
    ) -> TenantContext:
        return authorize(context, policy)

    return rbac_dependency
