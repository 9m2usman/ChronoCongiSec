"""M4 engine output vs. the M4 -> M6 database contract for ``policy_decisions``.

Module: backend.tests.security.test_db_contract
Owner: M4 — Security Engine & Incident Response Lead

Pins the decisions in ``docs/security-design/m6-integration-decisions.md`` (OD-1 to OD-4)
against what M4's PolicyEngine actually persists via ``PolicyDecision.to_persistence_record``:

- every value M4 writes is inside the canonical vocabulary M6 will CHECK;
- ``REVIEW`` is never written as a decision (OD-1);
- every row satisfies the proposed cross-column CHECK ``ck_policy_decisions_consistent``;
- the initial ``execution_status`` matches the proposed insert rule (OD-4): a complete
  ALLOW starts PENDING_EXECUTION (permitted, not executed), REQUIRES_APPROVAL starts
  PENDING_APPROVAL, BLOCK and any non-executable ALLOW start NOT_EXECUTED.

No database is used; the predicate below mirrors the SQL proposed to M6.
"""

import asyncio
import dataclasses

import pytest

from backend.app.security.policy import (
    PolicyConfig, PolicyOutcome, PolicyResult, ToolPolicy, decision_is_executable,
)
from backend.tests.security.conftest import DEV, T_B, World, proposal

# --- Canonical vocabularies decided by M4 (m6-integration-decisions.md) -------------
DECISIONS = {"ALLOW", "BLOCK", "REQUIRES_APPROVAL"}
POLICY_RESULTS = {"PERMITTED", "DENIED", "ELEVATED"}
TRUST_STATES = {"TRUSTED", "UNVERIFIED", "SUSPICIOUS", "QUARANTINED", "REJECTED", "SUPERSEDED"}
MEMORY_TRUST = TRUST_STATES | {"NOT_REFERENCED", "NOT_FOUND", "INELIGIBLE", "UNKNOWN", "UNAVAILABLE"}
EXECUTION_STATUSES = {"NOT_EXECUTED", "PENDING_APPROVAL", "PENDING_EXECUTION", "EXECUTED", "FAILED", "UNKNOWN"}
INITIAL_EXECUTION_STATUS = {"ALLOW": "PENDING_EXECUTION", "REQUIRES_APPROVAL": "PENDING_APPROVAL",
                            "BLOCK": "NOT_EXECUTED"}
VARCHAR32_COLUMNS = ("decision", "memory_trust", "policy_result", "execution_status")


def satisfies_consistency_check(row) -> bool:
    """Python mirror of the proposed ck_policy_decisions_consistent (see the decisions doc)."""
    d, pr, mt, es = row["decision"], row["policy_result"], row["memory_trust"], row["execution_status"]
    reasons = row["reasons_json"]
    if not isinstance(reasons, list):
        return False
    if d == "ALLOW":
        return pr == "PERMITTED" and mt in {"TRUSTED", "NOT_REFERENCED"} and es in (EXECUTION_STATUSES - {"PENDING_APPROVAL"})
    if d == "REQUIRES_APPROVAL":
        return pr == "ELEVATED" and mt in {"TRUSTED", "NOT_REFERENCED"} and es in EXECUTION_STATUSES
    if d == "BLOCK":
        return pr == "DENIED" and es == "NOT_EXECUTED" and len(reasons) > 0
    return False


def run(coro):
    return asyncio.run(coro)


def _scenarios():
    """(name, builder) pairs; builder(world, monkeypatch) -> proposal to evaluate."""

    def broken_trust(w, mp):
        def boom(*a, **k):
            raise RuntimeError("trust evaluator down")
        mp.setattr(w.trust, "assess_for_action", boom)
        return proposal([w.trusted_memory()])

    def unknown_state(w, mp):
        rid = w.trusted_memory()
        w.repo._records[rid].trust_state = "MOSTLY_TRUSTED"
        return proposal([rid])

    out = [
        ("allow_trusted", lambda w, mp: proposal([w.trusted_memory()])),
        ("allow_no_refs", lambda w, mp: proposal([])),        # uses NO_JUSTIFICATION_CONFIG
        ("requires_approval", lambda w, mp: proposal([w.trusted_memory()], amount=450.0)),
        ("block_ceiling", lambda w, mp: proposal([w.trusted_memory()], amount=10_000_000)),
        ("block_not_found", lambda w, mp: proposal(["does-not-exist"])),
        ("block_cross_tenant", lambda w, mp: proposal([w.memory(tenant=T_B)])),
        ("block_input_invalid", lambda w, mp: proposal(["dup", "dup"])),
        ("block_trust_unavailable", broken_trust),
        ("block_unknown_state", unknown_state),
    ]
    for state in sorted(TRUST_STATES - {"TRUSTED"}):
        out.append((f"block_{state.lower()}", lambda w, mp, s=state: proposal([w.memory_in_state(s)])))
    return out


SCENARIOS = _scenarios()
# A tool policy that does not require memory justification, so a proposal without
# references can be ALLOWed and persisted with memory_trust NOT_REFERENCED.
NO_JUSTIFICATION_CONFIG = PolicyConfig(tool_policies={("sandbox_transfer", "transfer_funds"): ToolPolicy(
    mandatory_constraints=("max_amount",), requires_memory_justification=False)})
CONFIG_FOR = {"allow_no_refs": NO_JUSTIFICATION_CONFIG}


@pytest.fixture
def row_for(monkeypatch):
    def _row(builder):
        name = next(n for n, b in SCENARIOS if b is builder)
        w = World(CONFIG_FOR.get(name))
        p = builder(w, monkeypatch)
        d = run(w.engine.evaluate(p, DEV))
        return d, d.to_persistence_record()
    return _row


@pytest.mark.parametrize("name,builder", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_persisted_values_are_in_canonical_vocabulary(row_for, name, builder):
    _, row = row_for(builder)
    assert row["decision"] in DECISIONS and row["decision"] != "REVIEW"
    assert row["policy_result"] in POLICY_RESULTS
    assert row["memory_trust"] in MEMORY_TRUST, row["memory_trust"]
    assert row["execution_status"] in EXECUTION_STATUSES
    for col in VARCHAR32_COLUMNS:
        assert len(row[col]) <= 32, col


@pytest.mark.parametrize("name,builder", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_persisted_row_satisfies_proposed_consistency_check(row_for, name, builder):
    _, row = row_for(builder)
    assert satisfies_consistency_check(row), row


@pytest.mark.parametrize("name,expected", [
    ("allow_trusted", "ALLOW"), ("allow_no_refs", "ALLOW"), ("requires_approval", "REQUIRES_APPROVAL"),
    ("block_quarantined", "BLOCK"), ("block_trust_unavailable", "BLOCK"),
])
def test_scenarios_reach_intended_outcome(row_for, name, expected):
    """Guards the scenario table itself: the ALLOW/REQUIRES_APPROVAL rows really are produced."""
    builder = dict(SCENARIOS)[name]
    d, _ = row_for(builder)
    assert d.outcome is PolicyOutcome(expected), d.reason_codes


@pytest.mark.parametrize("name", [n for n, _ in SCENARIOS if not n.startswith("allow")])
def test_initial_execution_status_for_block_and_approval(row_for, name):
    _, row = row_for(dict(SCENARIOS)[name])
    assert row["execution_status"] == INITIAL_EXECUTION_STATUS[row["decision"]]


@pytest.mark.parametrize("name", ["allow_trusted", "allow_no_refs"])
def test_initial_execution_status_for_allow_is_pending_execution(row_for, name):
    """OD-4 (fixed; was a strict xfail). PENDING_EXECUTION means permitted and persisted,
    not executed: the row never claims EXECUTED before the adapter has run."""
    d, row = row_for(dict(SCENARIOS)[name])
    assert decision_is_executable(d)
    assert row["execution_status"] == "PENDING_EXECUTION" != "EXECUTED"


@pytest.mark.parametrize("tamper", [
    {"policy_result": PolicyResult.DENIED},
    {"execution_eligible": False},
    {"evaluation_status": "TIMEOUT"},
    {"policy_version": "amsc-policy/0.0.1"},
    {"reason_codes": ("ALL_CHECKS_PASSED", "EXTRA")},
    {"checks": ()},
])
def test_non_executable_allow_starts_not_executed(row_for, tamper):
    """Fail closed: an ALLOW label alone never yields PENDING_EXECUTION."""
    d, _ = row_for(dict(SCENARIOS)["allow_trusted"])
    bad = dataclasses.replace(d, **tamper)
    assert bad.outcome is PolicyOutcome.ALLOW and not decision_is_executable(bad)
    assert bad.to_persistence_record()["execution_status"] == "NOT_EXECUTED"


def test_contradictory_requires_approval_starts_not_executed(row_for):
    d, _ = row_for(dict(SCENARIOS)["requires_approval"])
    assert d.initial_execution_status == "PENDING_APPROVAL"
    bad = dataclasses.replace(d, policy_result=PolicyResult.PERMITTED)
    assert bad.initial_execution_status == "NOT_EXECUTED"


@pytest.mark.parametrize("name", [n for n, _ in SCENARIOS if n.startswith("block")])
def test_block_never_starts_pending(row_for, name):
    d, row = row_for(dict(SCENARIOS)[name])
    assert row["execution_status"] == "NOT_EXECUTED" and not decision_is_executable(d)


@pytest.mark.parametrize("bad", [
    {"decision": "REVIEW", "policy_result": "ELEVATED", "memory_trust": "TRUSTED", "execution_status": "PENDING_APPROVAL"},
    {"decision": "ALLOW", "policy_result": "DENIED", "memory_trust": "TRUSTED", "execution_status": "EXECUTED"},
    {"decision": "ALLOW", "policy_result": "PERMITTED", "memory_trust": "SUPERSEDED", "execution_status": "EXECUTED"},
    {"decision": "ALLOW", "policy_result": "PERMITTED", "memory_trust": "TRUSTED", "execution_status": "PENDING_APPROVAL"},
    {"decision": "BLOCK", "policy_result": "DENIED", "memory_trust": "QUARANTINED", "execution_status": "EXECUTED"},
    {"decision": "BLOCK", "policy_result": "DENIED", "memory_trust": "QUARANTINED", "execution_status": "NOT_EXECUTED",
     "reasons_json": []},
    {"decision": "REQUIRES_APPROVAL", "policy_result": "PERMITTED", "memory_trust": "TRUSTED",
     "execution_status": "PENDING_APPROVAL"},
    {"decision": "REQUIRES_APPROVAL", "policy_result": "ELEVATED", "memory_trust": "UNVERIFIED",
     "execution_status": "PENDING_APPROVAL"},
])
def test_consistency_check_rejects_contradictory_rows(bad):
    """The proposed CHECK is not vacuous: rows M1's current gateway can write are rejected."""
    row = {"reasons_json": ["r"], **bad}
    assert not satisfies_consistency_check(row)


EXPECTED_MEMORY_TRUST = {
    "allow_trusted": "TRUSTED", "allow_no_refs": "NOT_REFERENCED", "requires_approval": "TRUSTED",
    "block_not_found": "NOT_FOUND", "block_cross_tenant": "NOT_FOUND", "block_input_invalid": "NOT_REFERENCED",
    "block_trust_unavailable": "UNAVAILABLE", "block_unknown_state": "UNKNOWN",
    **{f"block_{s.lower()}": s for s in TRUST_STATES - {"TRUSTED"}},
}


@pytest.mark.parametrize("name", sorted(EXPECTED_MEMORY_TRUST))
def test_memory_trust_label_is_honest(row_for, name):
    """OD-2: the summary column names the worst state found; a missing, cross-tenant or
    unknown record is never labelled with a real trust state (M1 labels missing ones QUARANTINED)."""
    _, row = row_for(dict(SCENARIOS)[name])
    assert row["memory_trust"] == EXPECTED_MEMORY_TRUST[name]
