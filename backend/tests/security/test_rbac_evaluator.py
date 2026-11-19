"""Unit tests for the M4 Day 2 RBAC evaluator.

Module: backend.tests.security.test_rbac_evaluator
Owner: M4 — Security Engine & Incident Response Lead

Covers: valid roles, invalid roles, context validation, tenant mismatch, policy
misconfiguration and fail-closed behaviour of ``backend.app.security.authorization``.
"""

import dataclasses

import pytest

from backend.app.core.exceptions import ForbiddenError
from backend.app.security import authorization as authz
from backend.app.security.authorization import (
    RECOGNIZED_ROLES,
    AuthorizationPolicyError,
    AuthorizationReason,
    Role,
    authorize,
    evaluate_role_access,
    normalize_allowed_roles,
    require_role_access,
)
from backend.app.tenancy.context import TenantContext

TENANT_A = "tenant-a-uuid-001"
TENANT_B = "tenant-b-uuid-002"
ALL_DAY2_ROLES = (Role.TENANT_ADMIN, Role.SECURITY_ANALYST, Role.DEVELOPER)


def make_ctx(**overrides) -> TenantContext:
    values = dict(
        tenant_id=TENANT_A,
        tenant_slug="company-a",
        tenant_name="Company A",
        user_id="user-a-001",
        role="SECURITY_ANALYST",
        is_active=True,
    )
    values.update(overrides)
    return TenantContext(**values)


# ---------------------------------------------------------------------------
# A. Valid roles
# ---------------------------------------------------------------------------

def test_recognized_roles_are_exactly_the_three_day2_roles():
    assert RECOGNIZED_ROLES == {"TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER"}


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER"])
def test_each_day2_role_allowed_when_explicitly_permitted(role):
    decision = evaluate_role_access(make_ctx(role=role), [role])
    assert decision.allowed is True
    assert decision.reason is AuthorizationReason.ROLE_PERMITTED
    assert decision.role == role
    assert decision.tenant_id == TENANT_A


def test_role_enum_members_and_strings_are_equivalent_in_policy():
    assert evaluate_role_access(make_ctx(role="DEVELOPER"), [Role.DEVELOPER]).allowed
    assert evaluate_role_access(make_ctx(role=Role.DEVELOPER), ["DEVELOPER"]).allowed


@pytest.mark.parametrize(
    "role,allowed",
    [
        ("SECURITY_ANALYST", [Role.TENANT_ADMIN]),
        ("DEVELOPER", [Role.TENANT_ADMIN, Role.SECURITY_ANALYST]),
        ("TENANT_ADMIN", [Role.SECURITY_ANALYST]),  # no implicit admin super-role
        ("TENANT_ADMIN", [Role.DEVELOPER]),
    ],
)
def test_recognized_role_not_in_allowed_list_is_denied(role, allowed):
    decision = evaluate_role_access(make_ctx(role=role), allowed)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.ROLE_NOT_PERMITTED


def test_authorize_returns_same_context_on_allow():
    ctx = make_ctx(role="TENANT_ADMIN")
    assert authorize(ctx, [Role.TENANT_ADMIN]) is ctx


def test_authorize_raises_forbidden_403_on_deny():
    with pytest.raises(ForbiddenError) as exc_info:
        authorize(make_ctx(role="DEVELOPER"), [Role.TENANT_ADMIN])
    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "FORBIDDEN_ACTION"


# ---------------------------------------------------------------------------
# B. Invalid roles
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "role,reason",
    [
        # Unsupported roles from Doc 01/02/05 are NOT aliased to Day 2 roles.
        ("AI_DEVELOPER", AuthorizationReason.ROLE_UNRECOGNIZED),
        ("AUDITOR", AuthorizationReason.ROLE_UNRECOGNIZED),
        ("PLATFORM_ADMIN", AuthorizationReason.ROLE_UNRECOGNIZED),
        ("SUPERUSER", AuthorizationReason.ROLE_UNRECOGNIZED),
        # Missing / empty
        ("", AuthorizationReason.ROLE_MISSING),
        (None, AuthorizationReason.ROLE_MISSING),
        # Malformed: no case folding, trimming or normalization.
        ("tenant_admin", AuthorizationReason.ROLE_MALFORMED),
        ("Tenant_Admin", AuthorizationReason.ROLE_MALFORMED),
        (" TENANT_ADMIN", AuthorizationReason.ROLE_MALFORMED),
        ("TENANT_ADMIN ", AuthorizationReason.ROLE_MALFORMED),
        ("TENANT_ADMIN\n", AuthorizationReason.ROLE_MALFORMED),
        ("TENANT_ADMIN,SECURITY_ANALYST", AuthorizationReason.ROLE_MALFORMED),
        ("*", AuthorizationReason.ROLE_MALFORMED),
        ("A" * 65, AuthorizationReason.ROLE_MALFORMED),
        ("ТENANT_ADMIN", AuthorizationReason.ROLE_MALFORMED),  # Cyrillic 'Т' homoglyph
        # Wrong types
        (1, AuthorizationReason.ROLE_MALFORMED),
        (["TENANT_ADMIN"], AuthorizationReason.ROLE_MALFORMED),
        ({"role": "TENANT_ADMIN"}, AuthorizationReason.ROLE_MALFORMED),
        (b"TENANT_ADMIN", AuthorizationReason.ROLE_MALFORMED),
        (True, AuthorizationReason.ROLE_MALFORMED),
    ],
)
def test_invalid_roles_are_denied_even_when_every_day2_role_is_allowed(role, reason):
    decision = evaluate_role_access(make_ctx(role=role), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is reason
    assert decision.role is None  # never echo an unrecognized value


def test_str_subclass_spoofing_equality_is_rejected():
    class Sneaky(str):
        def __eq__(self, other):  # pretends to equal every role
            return True

        __hash__ = str.__hash__

    decision = evaluate_role_access(make_ctx(role=Sneaky("ANYTHING")), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.ROLE_MALFORMED


# ---------------------------------------------------------------------------
# C. Context validation
# ---------------------------------------------------------------------------

def test_missing_context_denied():
    decision = evaluate_role_access(None, ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.CONTEXT_MISSING


def test_missing_context_raises_403_via_authorize():
    with pytest.raises(ForbiddenError):
        authorize(None, ALL_DAY2_ROLES)


def test_duck_typed_context_object_is_rejected():
    fake = type("FakeCtx", (), dict(tenant_id=TENANT_A, user_id="u", role="TENANT_ADMIN", is_active=True))()
    decision = evaluate_role_access(fake, ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.CONTEXT_INVALID


@pytest.mark.parametrize("is_active", [False, None, 1, "true", "True"])
def test_inactive_or_non_boolean_active_flag_denied(is_active):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN", is_active=is_active), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.CONTEXT_INACTIVE


@pytest.mark.parametrize("tenant_id", ["", "   ", None, 123])
def test_missing_or_invalid_tenant_identifier_denied(tenant_id):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN", tenant_id=tenant_id), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.TENANT_MISSING


@pytest.mark.parametrize("user_id", ["", "   ", None, 42])
def test_missing_or_invalid_user_identifier_denied(user_id):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN", user_id=user_id), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.USER_MISSING


def test_context_is_immutable():
    ctx = make_ctx(role="DEVELOPER")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.role = "TENANT_ADMIN"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# D. Tenant isolation at the evaluator layer
# ---------------------------------------------------------------------------

def test_role_in_tenant_a_does_not_authorize_resource_in_tenant_b():
    ctx_admin_a = make_ctx(role="TENANT_ADMIN", tenant_id=TENANT_A)
    decision = evaluate_role_access(ctx_admin_a, [Role.TENANT_ADMIN], expected_tenant_id=TENANT_B)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.TENANT_MISMATCH


def test_matching_expected_tenant_allows():
    ctx = make_ctx(role="TENANT_ADMIN")
    assert evaluate_role_access(ctx, [Role.TENANT_ADMIN], expected_tenant_id=TENANT_A).allowed


@pytest.mark.parametrize("expected", ["", "  ", 7, TENANT_A.upper(), f" {TENANT_A}"])
def test_malformed_or_non_exact_expected_tenant_denied(expected):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN"), [Role.TENANT_ADMIN], expected_tenant_id=expected)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.TENANT_MISMATCH


def test_tenant_check_precedes_role_check_so_admin_gets_no_cross_tenant_bypass():
    # Even a fully privileged role in the allowed list is denied for another tenant's resource.
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN"), ALL_DAY2_ROLES, expected_tenant_id=TENANT_B)
    assert decision.reason is AuthorizationReason.TENANT_MISMATCH


# ---------------------------------------------------------------------------
# F. Policy misconfiguration and fail-closed behaviour
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy", [[], (), set(), None])
def test_missing_policy_denies_everyone(policy):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN"), policy)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.POLICY_MISSING


@pytest.mark.parametrize(
    "policy",
    [
        "TENANT_ADMIN",  # bare string would iterate characters
        ["AI_DEVELOPER"],
        ["TENANT_ADMIN", "AUDITOR"],
        ["*"],
        ["tenant_admin"],
        [None],
        [1],
        42,
    ],
)
def test_invalid_policy_denies_everyone(policy):
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN"), policy)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.POLICY_INVALID


def test_generator_policy_is_evaluated_correctly():
    decision = evaluate_role_access(make_ctx(role="DEVELOPER"), (r for r in ["DEVELOPER"]))
    assert decision.allowed is True


@pytest.mark.parametrize("policy", [(), ("AI_DEVELOPER",), ("TENANT_ADMIN", "nope")])
def test_dependency_factory_rejects_invalid_policy_at_definition_time(policy):
    with pytest.raises(AuthorizationPolicyError):
        require_role_access(*policy)


def test_normalize_allowed_roles_returns_immutable_set():
    policy = normalize_allowed_roles([Role.TENANT_ADMIN, "TENANT_ADMIN", Role.DEVELOPER])
    assert policy == frozenset({"TENANT_ADMIN", "DEVELOPER"})
    assert isinstance(policy, frozenset)


def test_unexpected_internal_error_fails_closed(monkeypatch):
    def boom(_role):
        raise RuntimeError("simulated evaluator fault")

    monkeypatch.setattr(authz, "_classify_role", boom)
    decision = evaluate_role_access(make_ctx(role="TENANT_ADMIN"), ALL_DAY2_ROLES)
    assert decision.allowed is False
    assert decision.reason is AuthorizationReason.EVALUATION_ERROR
    with pytest.raises(ForbiddenError):
        authorize(make_ctx(role="TENANT_ADMIN"), ALL_DAY2_ROLES)


def test_evaluator_never_raises_for_hostile_inputs():
    hostile_inputs = [object(), 3.14, ["x"], {"a": 1}, b"\x00"]
    for ctx in hostile_inputs:
        for policy in [None, "x", [object()], ALL_DAY2_ROLES]:
            decision = evaluate_role_access(ctx, policy)  # type: ignore[arg-type]
            assert decision.allowed is False


def test_decisions_are_deterministic_and_stateless():
    ctx_allow = make_ctx(role="SECURITY_ANALYST")
    ctx_deny = make_ctx(role="DEVELOPER", tenant_id=TENANT_B, user_id="user-b-1")
    for _ in range(50):
        assert evaluate_role_access(ctx_allow, [Role.SECURITY_ANALYST]).allowed is True
        assert evaluate_role_access(ctx_deny, [Role.SECURITY_ANALYST]).allowed is False
