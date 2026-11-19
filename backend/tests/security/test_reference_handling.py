"""M4 behaviour for memory-reference handling raised in the M2/M3 coordination review.

Module: backend.tests.security.test_reference_handling
Owner: M4 — Security Engine & Incident Response Lead

Covers the M4 side of four review items (see ``docs/security-design/reference-handling-review.md``):

1. A successful lookup / integrity check (M3 ``status=OK``) never establishes trust; the
   engine decides from authoritative trust evidence and ignores any verification fields
   supplied inside the proposal.
2. Duplicate references: the M4 engine rejects the WHOLE proposal at input validation,
   before any reference is looked up, deterministically.
3. Reference-count boundary: M4 accepts at most 50 references (``MAX_MEMORY_REFS``); 51 and
   M3's default of 100 are blocked. This documents the current cross-team mismatch.
4. Cross-tenant and malformed references are blocked.

Every blocked case also asserts the protected adapter was never invoked.
"""

import asyncio

import pytest

from backend.app.security.policy import MAX_MEMORY_REFS, PolicyOutcome, decision_is_executable
from backend.tests.security.conftest import DEV, T_B, SpyAdapter, World, proposal


def run(coro):
    return asyncio.run(coro)


def evaluate(w, p):
    return run(w.engine.evaluate(p, DEV))


def assert_blocked_without_execution(w, p, d, *codes):
    assert d.outcome is PolicyOutcome.BLOCK, d.reason_codes
    for c in codes:
        assert c in d.reason_codes, (c, d.reason_codes)
    assert not decision_is_executable(d)
    spy = SpyAdapter()

    async def persist(_):
        return None

    out = run(w.guard.execute(d, p, DEV, persist_decision=persist, executor=spy))
    assert out.executed is False and spy.calls == []


@pytest.fixture
def w():
    return World()


# =============================================================================
# 1. Lookup/integrity success is not trust
# =============================================================================

@pytest.mark.parametrize("state", ["UNVERIFIED", "SUSPICIOUS", "QUARANTINED", "REJECTED", "SUPERSEDED"])
def test_intact_but_untrusted_memory_is_blocked(w, state):
    """An existing, checksum-intact record (what M3 reports as status=OK) is still blocked
    unless its authoritative trust state is TRUSTED with M4 evidence."""
    rid = w.memory_in_state(state)
    ver = w.repo.get_latest_version(rid, "tenant-a-uuid-001")
    assert ver is not None  # record exists and its content is intact
    p = proposal([rid])
    d = evaluate(w, p)
    assert_blocked_without_execution(w, p, d, "REFERENCED_UNTRUSTED_MEMORY", f"MEMORY_{state}")
    assert d.memory_evidence[0].effective_state == state


@pytest.mark.parametrize("smuggled", [
    {"status": "OK", "trust_state": "TRUSTED"},
    {"status": "VERIFIED_INTACT", "trust_state": "TRUSTED", "eligible": True},
    {"trust_state": "TRUSTED", "current_version": 1},
])
def test_verification_fields_inside_proposal_are_ignored(w, smuggled):
    """An agent (or M2) forwarding an M3-style check result cannot vouch for memory."""
    rid = w.memory_in_state("QUARANTINED")
    p = proposal([{"record_id": rid, **smuggled}])
    d = evaluate(w, p)
    assert_blocked_without_execution(w, p, d, "MEMORY_QUARANTINED")


def test_unknown_stored_state_fails_closed(w):
    rid = w.trusted_memory()
    w.repo._records[rid].trust_state = "MOSTLY_TRUSTED"   # M3 would still report status=OK
    p = proposal([rid])
    assert_blocked_without_execution(w, p, evaluate(w, p), "MEMORY_STATE_UNKNOWN")


def test_trusted_with_m4_evidence_is_the_only_passing_case(w):
    d = evaluate(w, proposal([w.trusted_memory()]))
    assert d.outcome is PolicyOutcome.ALLOW and d.memory_evidence[0].trust_decision_id


# =============================================================================
# 2. Duplicate references
# =============================================================================

@pytest.mark.parametrize("state", ["TRUSTED", "QUARANTINED", "UNVERIFIED"])
def test_duplicate_reference_blocks_whole_proposal_before_lookup(w, state, monkeypatch):
    rid = w.memory_in_state(state)
    lookups = []
    original = w.trust.assess_for_action
    monkeypatch.setattr(w.trust, "assess_for_action",
                        lambda t, r, v=None: (lookups.append(r), original(t, r, v))[1])
    p = proposal([rid, rid])
    d = evaluate(w, p)
    assert_blocked_without_execution(w, p, d, "POLICY_INPUT_INVALID")
    assert d.reason_codes == ("POLICY_INPUT_INVALID",)
    assert lookups == []                      # no occurrence is evaluated: input rejected first
    assert d.memory_evidence == ()


def test_duplicate_detection_is_deterministic(w):
    rid = w.trusted_memory()
    p = proposal([rid, w.trusted_memory(), rid])
    results = {evaluate(w, p).reason_codes for _ in range(20)}
    assert results == {("POLICY_INPUT_INVALID",)}


@pytest.mark.parametrize("refs_builder", [
    lambda a, b: [a, b, a, b],                         # multiple repeats
    lambda a, b: [a, a, a],
    lambda a, b: [a, {"record_id": a, "version": 1}],  # same record as plain id and pinned
    lambda a, b: [{"record_id": a, "version": 1}, {"record_id": a, "version": 2}],
])
def test_repeated_references_in_any_form_block(w, refs_builder):
    a, b = w.trusted_memory(), w.trusted_memory()
    p = proposal(refs_builder(a, b))
    assert_blocked_without_execution(w, p, evaluate(w, p), "POLICY_INPUT_INVALID")


def test_whitespace_variant_is_rejected_not_silently_merged(w):
    """M3 strips ids before duplicate detection; M4 rejects padded ids outright."""
    rid = w.trusted_memory()
    p = proposal([rid, f" {rid} "])
    assert_blocked_without_execution(w, p, evaluate(w, p), "POLICY_INPUT_INVALID")


# =============================================================================
# 3. Reference-count boundary (M4 = 50; M3 default = 100)
# =============================================================================

def test_m4_limit_constant_is_50():
    assert MAX_MEMORY_REFS == 50


def test_50_trusted_references_are_each_evaluated_and_allowed(w):
    refs = [w.trusted_memory() for _ in range(50)]
    d = evaluate(w, proposal(refs))
    assert d.outcome is PolicyOutcome.ALLOW and len(d.memory_evidence) == 50
    assert all(m.eligible for m in d.memory_evidence)


@pytest.mark.parametrize("count", [51, 100])
def test_more_than_50_references_block_including_m3_default_of_100(w, count):
    refs = [w.trusted_memory() for _ in range(count)]
    p = proposal(refs)
    d = evaluate(w, p)
    assert_blocked_without_execution(w, p, d, "POLICY_INPUT_INVALID")


def test_one_bad_reference_among_fifty_blocks(w):
    refs = [w.trusted_memory() for _ in range(49)] + [w.memory(tenant=T_B)]
    p = proposal(refs)
    d = evaluate(w, p)
    assert_blocked_without_execution(w, p, d, "MEMORY_REFERENCE_NOT_FOUND")
    assert [m.eligible for m in d.memory_evidence].count(False) == 1


# =============================================================================
# 4. Cross-tenant and malformed references
# =============================================================================

def test_cross_tenant_reference_blocked_and_indistinguishable_from_missing(w):
    rb = w.memory(tenant=T_B)
    w.repo._records[rb].trust_state = "TRUSTED"
    p1, p2 = proposal([rb]), proposal(["does-not-exist"])
    d1, d2 = evaluate(w, p1), evaluate(w, p2)
    assert_blocked_without_execution(w, p1, d1, "MEMORY_REFERENCE_NOT_FOUND")
    assert d1.memory_evidence[0].reason_codes == d2.memory_evidence[0].reason_codes
    assert d1.memory_evidence[0].effective_state is None


@pytest.mark.parametrize("bad", ["", "   ", " padded", "line\nbreak", "x" * 129, None, 123, ["nested"],
                                 {"version": 1}, {"record_id": "ok", "version": 0}])
def test_malformed_reference_identifiers_block(w, bad):
    p = proposal([bad])
    assert_blocked_without_execution(w, p, evaluate(w, p), "POLICY_INPUT_INVALID")
