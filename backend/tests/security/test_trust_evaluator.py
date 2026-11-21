"""Tests for the M4 Day 3 memory trust state machine and trust evaluator.

Module: backend.tests.security.test_trust_evaluator
Owner: M4 — Security Engine & Incident Response Lead

Uses M3's real in-memory repository and services (no mocks of memory behaviour),
M1's ``TenantContext`` and the M4 Day 2 RBAC evaluator.
"""

import logging
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory import (
    InMemoryMemoryRepository,
    MemoryNotFoundError,
    MemoryRecord,
    ProvenanceEdge,
    TrustState,
    get_memory_detail,
    ingest_memory,
    retrieve_memory,
    transition_memory_trust_state,
    update_memory,
)
from backend.app.security.trust import (
    OPERATION_TARGET,
    TRANSITION_MATRIX,
    TRUST_POLICY_VERSION,
    ActorType,
    InMemoryTrustDecisionStore,
    SystemActor,
    TrustDimension,
    TrustEvaluator,
    TrustOperation,
    TrustReason,
    UserActor,
    raise_for_decision,
)
from backend.app.tenancy.context import TenantContext
from backend.app.memory.tests.trust_helpers import force_trust_state

T_A = "tenant-a-uuid-001"
T_B = "tenant-b-uuid-002"
SRC_A = "src-doc-001"            # seeded ACTIVE source in tenant A
SRC_A_INACTIVE = "src-inactive-001"
FIXED_NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)

U, T, S, Q, R, X = (
    TrustState.UNVERIFIED, TrustState.TRUSTED, TrustState.SUSPICIOUS,
    TrustState.QUARANTINED, TrustState.REJECTED, TrustState.SUPERSEDED,
)
OP = TrustOperation

# Expected matrix written out independently of the implementation (design doc §3).
EXPECTED_ALLOWED = {
    (OP.VALIDATE, U),
    (OP.FLAG_SUSPICIOUS, U), (OP.FLAG_SUSPICIOUS, T),
    (OP.QUARANTINE, U), (OP.QUARANTINE, T), (OP.QUARANTINE, S), (OP.QUARANTINE, X),
    (OP.REJECT, U), (OP.REJECT, S), (OP.REJECT, Q), (OP.REJECT, X),
    (OP.INVALIDATE, T),
    (OP.SUPERSEDE, T),
    (OP.CLEAR_SUSPICION, S),
    (OP.RELEASE_QUARANTINE, Q),
    (OP.RECOVERY_RESTORE, Q), (OP.RECOVERY_RESTORE, S), (OP.RECOVERY_RESTORE, T), (OP.RECOVERY_RESTORE, X),
}


def make_ctx(role="SECURITY_ANALYST", tenant=T_A, user="analyst-1", active=True) -> TenantContext:
    return TenantContext(tenant_id=tenant, tenant_slug="s", tenant_name="n", user_id=user, role=role, is_active=active)


ANALYST = UserActor(make_ctx())
ANALYST_2 = UserActor(make_ctx(user="analyst-2"))
ADMIN = UserActor(make_ctx(role="TENANT_ADMIN", user="admin-1"))
ANALYST_B = UserActor(make_ctx(tenant=T_B, user="analyst-b"))
DETECTOR = SystemActor(tenant_id=T_A, actor_type=ActorType.SYSTEM_DETECTOR, process_ref="injection-rules@1")
INTEGRITY = SystemActor(tenant_id=T_A, actor_type=ActorType.SYSTEM_INTEGRITY, process_ref="checksum-verifier")
UPDATER = SystemActor(tenant_id=T_A, actor_type=ActorType.SYSTEM_UPDATE, process_ref="memory-update")


class Harness:
    def __init__(self):
        self.repo = InMemoryMemoryRepository()
        self.store = InMemoryTrustDecisionStore()
        self.ev = TrustEvaluator(self.repo, self.store, clock=lambda: FIXED_NOW, app_env="test")

    # -- records ---------------------------------------------------------------
    def new(self, source_id=SRC_A, parent=None, content=None) -> str:
        rec, _ = ingest_memory(
            T_A, content or f"memo {uuid.uuid4()}", source_id=source_id, parent_record_id=parent, repository=self.repo
        )
        return rec.id

    def rec(self, rid, tenant=T_A):
        return self.repo.get_record(rid, tenant)

    def state(self, rid):
        return self.rec(rid).trust_state

    # -- requests --------------------------------------------------------------
    def validation(self, rid, **dims):
        rec = self.rec(rid)
        ver = self.repo.get_version(rid, rec.current_version, T_A)
        d = {dim.value: {"status": "PASS", "evidence_ref": f"ev-{dim.value.lower()}"} for dim in TrustDimension}
        d.update({k: v for k, v in dims.items()})
        return {"assessed_version": rec.current_version, "assessed_checksum": ver.checksum, "dimensions": d}

    def request(self, rid, op, *, target=None, expected_state=None, expected_version=None,
                reason="analyst review", evidence=None, full_evidence=True):
        ev = {}
        if full_evidence:
            ev = {"evidence_refs": ["det-001"], "incident_id": "inc-001",
                  "recovery_plan_id": "plan-001", "checkpoint_id": "cp-001"}
            if op is OP.VALIDATE:
                ev["validation"] = self.validation(rid)
        if evidence:
            ev.update(evidence)
        rec = self.rec(rid)
        return {
            "record_id": rid,
            "operation": op.value,
            "target_state": (target or OPERATION_TARGET[op]).value,
            "expected_state": (expected_state or self.ev.effective_state(T_A, rid) or rec.trust_state),
            "expected_version": expected_version or rec.current_version,
            "reason": reason,
            "evidence": ev,
        }

    def do(self, rid, op, actor=ANALYST, **kw):
        return self.ev.apply(self.request(rid, op, **kw), actor)

    def must(self, rid, op, actor=ANALYST, **kw):
        d = self.do(rid, op, actor, **kw)
        assert d.applied, d.reason_codes
        return d

    # -- drive a record into a state through valid transitions only ----------------
    def drive(self, state: TrustState) -> str:
        rid = self.new()
        if state is U:
            return rid
        if state is T:
            self.must(rid, OP.VALIDATE)
        elif state is S:
            self.must(rid, OP.FLAG_SUSPICIOUS)
        elif state is Q:
            self.must(rid, OP.QUARANTINE)
        elif state is R:
            self.must(rid, OP.REJECT)
        elif state is X:
            self.must(rid, OP.VALIDATE)
            succ = self.successor_for(rid)
            self.must(rid, OP.SUPERSEDE, evidence={"successor_record_id": succ})
        assert self.state(rid) == state.value
        return rid

    def successor_for(self, rid) -> str:
        succ = self.new()
        self.must(succ, OP.VALIDATE)
        self.repo.create_edge(ProvenanceEdge(
            id=str(uuid.uuid4()), tenant_id=T_A, from_record_id=succ, to_record_id=rid, relation_type="SUPERSEDES"))
        return succ


@pytest.fixture
def h():
    return Harness()


# =============================================================================
# A. Initialization and state vocabulary
# =============================================================================

def test_newly_ingested_memory_is_unverified(h):
    rid = h.new()
    assert h.state(rid) == "UNVERIFIED"
    assert h.ev.history(ANALYST, rid) == ()


def test_all_six_schema_states_are_preserved():
    assert {s.value for s in TrustState} == {"UNVERIFIED", "TRUSTED", "SUSPICIOUS", "QUARANTINED", "REJECTED", "SUPERSEDED"}


def test_matrix_implementation_matches_independent_expectation():
    assert set(TRANSITION_MATRIX) == EXPECTED_ALLOWED


def test_trusted_reachable_only_from_unverified_via_validate():
    to_trusted = [(op, src) for (op, src), rule in TRANSITION_MATRIX.items() if rule.to_state is T]
    assert to_trusted == [(OP.VALIDATE, U)]


def test_rejected_is_terminal():
    assert not [k for k in TRANSITION_MATRIX if k[1] is R]


def test_system_actors_never_relax_restriction():
    for rule in TRANSITION_MATRIX.values():
        if rule.relaxes_restriction or rule.to_state is T:
            assert rule.actor_types == {ActorType.USER}, rule.transition_id


def test_unknown_stored_state_is_denied(h):
    rid = h.new()
    h.repo._records[rid].trust_state = "TRUSTED_BOGUS"  # simulated corruption
    d = h.ev.apply(h.request(rid, OP.QUARANTINE, expected_state="UNVERIFIED"), ANALYST)
    assert not d.allowed and TrustReason.CURRENT_STATE_UNKNOWN.value in d.reason_codes


@pytest.mark.parametrize("field,value", [("target_state", "TRUSTED_BOGUS"), ("expected_state", "ALLOWED"),
                                         ("operation", "PROMOTE"), ("operation", "validate")])
def test_unknown_state_or_operation_names_are_denied(h, field, value):
    rid = h.new()
    req = h.request(rid, OP.FLAG_SUSPICIOUS)
    req[field] = value
    d = h.ev.apply(req, ANALYST)
    assert not d.allowed and d.reason_codes == (TrustReason.REQUEST_INVALID.value,)
    assert h.state(rid) == "UNVERIFIED"


# =============================================================================
# B/C. Exhaustive transition matrix (9 operations x 6 states)
# =============================================================================

@pytest.mark.parametrize("op", list(TrustOperation))
@pytest.mark.parametrize("src", list(TrustState))
def test_every_operation_from_every_state(h, op, src):
    rid = h.drive(src)
    extra = {"successor_record_id": h.successor_for(rid)} if op is OP.SUPERSEDE else None
    req = h.request(rid, op, evidence=extra)
    if op is OP.VALIDATE and src is not U:
        req["evidence"]["validation"] = h.validation(rid)
    d = h.ev.apply(req, ADMIN)
    if (op, src) in EXPECTED_ALLOWED:
        assert d.applied, (op, src, d.reason_codes)
        assert h.state(rid) == OPERATION_TARGET[op].value
        assert d.resulting_state == OPERATION_TARGET[op].value
        assert d.current_state == src.value
        assert d.transition_id == TRANSITION_MATRIX[(op, src)].transition_id
    else:
        assert not d.allowed
        assert d.reason_codes == (TrustReason.TRANSITION_NOT_ALLOWED.value,), d.reason_codes
        assert h.state(rid) == src.value


@pytest.mark.parametrize("op", list(TrustOperation))
def test_target_state_must_match_operation(h, op):
    rid = h.drive(U)
    wrong = T if OPERATION_TARGET[op] is not T else Q
    d = h.do(rid, op, actor=ADMIN, target=wrong)
    assert not d.allowed and d.reason_codes == (TrustReason.TARGET_STATE_MISMATCH.value,)


def test_recovery_can_never_target_trusted(h):
    rid = h.drive(Q)
    d = h.do(rid, OP.RECOVERY_RESTORE, actor=ADMIN, target=T)
    assert not d.allowed and h.state(rid) == "QUARANTINED"
    restored = h.must(rid, OP.RECOVERY_RESTORE, actor=ADMIN)
    assert restored.resulting_state == "UNVERIFIED"


def test_recovery_requires_plan_and_checkpoint(h):
    rid = h.drive(Q)
    d = h.do(rid, OP.RECOVERY_RESTORE, actor=ADMIN, full_evidence=False, evidence={"evidence_refs": ["x"]})
    assert TrustReason.RECOVERY_EVIDENCE_MISSING.value in d.reason_codes


def test_recovered_record_requires_full_revalidation(h):
    rid = h.drive(Q)
    h.must(rid, OP.RECOVERY_RESTORE, actor=ADMIN)
    bad = h.do(rid, OP.VALIDATE, evidence={"validation": h.validation(rid, CONTRADICTION={"status": "UNAVAILABLE"})})
    assert not bad.allowed
    assert h.must(rid, OP.VALIDATE, actor=ANALYST_2).resulting_state == "TRUSTED"


@pytest.mark.parametrize("reason", ["", "   ", "\n\t"])
def test_reason_is_required(h, reason):
    rid = h.drive(U)
    d = h.do(rid, OP.FLAG_SUSPICIOUS, reason=reason)
    assert d.reason_codes == (TrustReason.REASON_MISSING.value,)


@pytest.mark.parametrize("op,src", [(OP.FLAG_SUSPICIOUS, U), (OP.QUARANTINE, T), (OP.REJECT, S),
                                    (OP.CLEAR_SUSPICION, S), (OP.RELEASE_QUARANTINE, Q)])
def test_evidence_refs_required(h, op, src):
    rid = h.drive(src)
    d = h.do(rid, op, actor=ADMIN, full_evidence=False, evidence={"incident_id": "inc-1"})
    assert TrustReason.EVIDENCE_MISSING.value in d.reason_codes
    assert h.state(rid) == src.value


@pytest.mark.parametrize("op,src", [(OP.REJECT, U), (OP.REJECT, Q), (OP.RELEASE_QUARANTINE, Q), (OP.QUARANTINE, X)])
def test_incident_required(h, op, src):
    rid = h.drive(src)
    d = h.do(rid, op, actor=ADMIN, full_evidence=False, evidence={"evidence_refs": ["e1"]})
    assert TrustReason.INCIDENT_REQUIRED.value in d.reason_codes


# =============================================================================
# Actor authorization (Day 2 RBAC contract)
# =============================================================================

@pytest.mark.parametrize("role", ["DEVELOPER", "AI_DEVELOPER", "AUDITOR", "PLATFORM_ADMIN", "tenant_admin", ""])
def test_non_analyst_roles_cannot_change_trust(h, role):
    rid = h.drive(U)
    for op in (OP.VALIDATE, OP.QUARANTINE, OP.FLAG_SUSPICIOUS):
        d = h.do(rid, op, actor=UserActor(make_ctx(role=role, user="u-x")))
        assert not d.allowed and TrustReason.ACTOR_NOT_AUTHORIZED.value in d.reason_codes
    assert h.state(rid) == "UNVERIFIED"


@pytest.mark.parametrize("system", [DETECTOR, INTEGRITY, UPDATER])
@pytest.mark.parametrize("op,src", [(OP.VALIDATE, U), (OP.CLEAR_SUSPICION, S), (OP.RELEASE_QUARANTINE, Q),
                                    (OP.RECOVERY_RESTORE, Q), (OP.REJECT, S), (OP.SUPERSEDE, T)])
def test_system_actors_cannot_promote_release_reject_or_supersede(h, system, op, src):
    rid = h.drive(src)
    d = h.do(rid, op, actor=system)
    assert not d.allowed and TrustReason.ACTOR_TYPE_NOT_PERMITTED.value in d.reason_codes
    assert h.state(rid) == src.value


@pytest.mark.parametrize("system,op,src,dst", [
    (DETECTOR, OP.FLAG_SUSPICIOUS, U, S), (DETECTOR, OP.FLAG_SUSPICIOUS, T, S),
    (INTEGRITY, OP.QUARANTINE, U, Q), (INTEGRITY, OP.QUARANTINE, T, Q), (INTEGRITY, OP.QUARANTINE, S, Q),
    (UPDATER, OP.INVALIDATE, T, U),
])
def test_system_actors_may_restrict(h, system, op, src, dst):
    rid = h.drive(src)
    d = h.must(rid, op, actor=system)
    assert h.state(rid) == dst.value and d.actor_type == system.actor_type.value


def test_detector_cannot_quarantine_and_integrity_cannot_flag(h):
    rid = h.drive(U)
    assert TrustReason.ACTOR_TYPE_NOT_PERMITTED.value in h.do(rid, OP.QUARANTINE, actor=DETECTOR).reason_codes
    assert TrustReason.ACTOR_TYPE_NOT_PERMITTED.value in h.do(rid, OP.FLAG_SUSPICIOUS, actor=INTEGRITY).reason_codes


def test_forged_system_actor_with_user_type_is_rejected(h):
    rid = h.drive(U)
    forged = SystemActor(tenant_id=T_A, actor_type=ActorType.USER, process_ref="evil")
    d = h.do(rid, OP.VALIDATE, actor=forged)
    assert d.reason_codes == (TrustReason.ACTOR_INVALID.value,)


def test_release_requires_different_analyst_or_admin(h):
    rid = h.drive(Q)  # quarantined by analyst-1
    same = h.do(rid, OP.RELEASE_QUARANTINE, actor=ANALYST)
    assert same.reason_codes == (TrustReason.SEPARATION_OF_DUTIES.value,)
    assert h.must(rid, OP.RELEASE_QUARANTINE, actor=ANALYST_2).resulting_state == "UNVERIFIED"


def test_release_by_admin_allowed_even_if_admin_quarantined(h):
    rid = h.new()
    h.must(rid, OP.QUARANTINE, actor=ADMIN)
    assert h.must(rid, OP.RELEASE_QUARANTINE, actor=ADMIN).applied


def test_release_with_unknown_quarantine_origin_requires_admin(h):
    rid = h.new()
    h.repo._records[rid].trust_state = "QUARANTINED"  # set outside M4: no history
    d = h.do(rid, OP.RELEASE_QUARANTINE, actor=ANALYST)
    assert d.reason_codes == (TrustReason.QUARANTINE_ORIGIN_UNKNOWN.value,)
    assert h.must(rid, OP.RELEASE_QUARANTINE, actor=ADMIN).applied


# =============================================================================
# Validation evidence (multidimensional; missing never means pass)
# =============================================================================

def test_validation_evidence_required_for_promotion(h):
    rid = h.drive(U)
    d = h.do(rid, OP.VALIDATE, full_evidence=False, evidence={"evidence_refs": ["x"]})
    assert d.reason_codes == (TrustReason.VALIDATION_EVIDENCE_MISSING.value,)
    assert h.state(rid) == "UNVERIFIED"


@pytest.mark.parametrize("dim", [d.value for d in TrustDimension])
@pytest.mark.parametrize("status,code", [("FAIL", TrustReason.DIMENSION_FAILED),
                                         ("UNAVAILABLE", TrustReason.DIMENSION_UNAVAILABLE)])
def test_any_failed_or_unavailable_dimension_blocks_promotion(h, dim, status, code):
    rid = h.drive(U)
    d = h.do(rid, OP.VALIDATE, evidence={"validation": h.validation(rid, **{dim: {"status": status}})})
    assert not d.allowed and code.value in d.reason_codes
    assert h.state(rid) == "UNVERIFIED"


@pytest.mark.parametrize("dim", [d.value for d in TrustDimension])
def test_missing_dimension_blocks_promotion(h, dim):
    rid = h.drive(U)
    val = h.validation(rid)
    del val["dimensions"][dim]
    d = h.do(rid, OP.VALIDATE, evidence={"validation": val})
    assert TrustReason.DIMENSION_UNAVAILABLE.value in d.reason_codes


@pytest.mark.parametrize("dim", ["SOURCE_IDENTITY", "SOURCE_AUTHORITY", "INTEGRITY", "FRESHNESS", "CONTRADICTION", "LINEAGE"])
def test_not_applicable_forbidden_for_core_dimensions(h, dim):
    rid = h.drive(U)
    val = h.validation(rid, **{dim: {"status": "NOT_APPLICABLE", "note": "n/a"}})
    d = h.do(rid, OP.VALIDATE, evidence={"validation": val})
    assert TrustReason.DIMENSION_NOT_APPLICABLE_FORBIDDEN.value in d.reason_codes


def test_not_applicable_for_sensitivity_requires_explicit_note(h):
    rid = h.drive(U)
    no_note = h.validation(rid, SENSITIVITY={"status": "NOT_APPLICABLE"})
    assert TrustReason.DIMENSION_NOT_APPLICABLE_FORBIDDEN.value in h.do(
        rid, OP.VALIDATE, evidence={"validation": no_note}).reason_codes
    with_note = h.validation(rid, SENSITIVITY={"status": "NOT_APPLICABLE", "note": "no label attribute yet (D-08)"},
                             POLICY_SCOPE={"status": "NOT_APPLICABLE", "note": "no scope attribute yet (D-08)"})
    d = h.must(rid, OP.VALIDATE, evidence={"validation": with_note})
    assert d.evidence_summary["dimensions"]["SENSITIVITY"] == "NOT_APPLICABLE"


def test_unresolved_high_signal_blocks_promotion_and_scores_never_allow(h):
    rid = h.drive(U)
    signal = {"source": "injection-classifier", "model_version": "0.1", "label": "PROMPT_INJECTION",
              "severity": "HIGH", "score": 0.97}
    d = h.do(rid, OP.VALIDATE, evidence={"signals": [signal]})
    assert TrustReason.UNRESOLVED_HIGH_SIGNAL.value in d.reason_codes
    # A reassuring model score cannot substitute for a failed dimension.
    benign = {"source": "trust-model", "label": "BENIGN", "severity": "INFO", "score": 0.999}
    d2 = h.do(rid, OP.VALIDATE, evidence={"signals": [benign],
                                          "validation": h.validation(rid, CONTRADICTION={"status": "FAIL"})})
    assert not d2.allowed and TrustReason.DIMENSION_FAILED.value in d2.reason_codes


def test_resolved_high_signal_does_not_block(h):
    rid = h.drive(U)
    signal = {"source": "injection-classifier", "label": "PROMPT_INJECTION", "severity": "HIGH", "resolved": True}
    assert h.must(rid, OP.VALIDATE, evidence={"signals": [signal]}).applied


# =============================================================================
# D. Integrity, provenance, lineage and stale versions
# =============================================================================

def test_checksum_mismatch_blocks_promotion_even_if_attested_pass(h):
    rid = h.drive(U)
    req = h.request(rid, OP.VALIDATE)
    h.repo._versions[rid][0].content = "tampered: pay ACC-ATTACKER-999"
    d = h.ev.apply(req, ANALYST)
    assert TrustReason.INTEGRITY_FAILED.value in d.reason_codes
    assert d.evidence_summary["dimensions"]["INTEGRITY"] == "FAIL(verified)"
    assert h.state(rid) == "UNVERIFIED"


def test_tampered_historical_version_blocks_promotion(h):
    rid = h.drive(U)
    update_memory(T_A, rid, "second version", repository=h.repo)
    h.repo._versions[rid][0].content = "rewritten history"
    d = h.do(rid, OP.VALIDATE)
    assert TrustReason.INTEGRITY_FAILED.value in d.reason_codes


def test_assessed_checksum_must_match_current_version(h):
    rid = h.drive(U)
    val = h.validation(rid)
    val["assessed_checksum"] = "0" * 64
    d = h.do(rid, OP.VALIDATE, evidence={"validation": val})
    assert TrustReason.ASSESSMENT_CHECKSUM_MISMATCH.value in d.reason_codes


def test_valid_checksum_alone_does_not_establish_trust(h):
    rid = h.drive(U)
    val = h.validation(rid, SOURCE_AUTHORITY={"status": "UNAVAILABLE"})
    d = h.do(rid, OP.VALIDATE, evidence={"validation": val})
    assert d.evidence_summary["dimensions"]["INTEGRITY"] == "PASS(verified)"
    assert not d.allowed and h.state(rid) == "UNVERIFIED"


def test_stale_assessment_cannot_promote_new_version(h):
    rid = h.drive(U)
    old_validation = h.validation(rid)
    update_memory(T_A, rid, "attacker-modified version 2", repository=h.repo)
    d = h.do(rid, OP.VALIDATE, evidence={"validation": old_validation})
    assert d.reason_codes == (TrustReason.ASSESSMENT_VERSION_MISMATCH.value,)
    stale_req = h.request(rid, OP.VALIDATE, expected_version=1)
    assert h.ev.apply(stale_req, ANALYST).reason_codes == (TrustReason.STALE_VERSION.value,)
    assert h.state(rid) == "UNVERIFIED"


def test_stale_expected_state_is_denied(h):
    rid = h.drive(U)
    req = h.request(rid, OP.QUARANTINE)
    h.must(rid, OP.FLAG_SUSPICIOUS, actor=DETECTOR)  # state changes in between
    d = h.ev.apply(req, ANALYST)
    assert d.reason_codes == (TrustReason.STALE_STATE.value,)
    assert h.state(rid) == "SUSPICIOUS"


def test_concurrent_identical_requests_apply_once(h):
    rid = h.drive(U)
    req = h.request(rid, OP.QUARANTINE)
    first, second = h.ev.apply(req, ANALYST), h.ev.apply(req, ANALYST_2)
    assert first.applied and not second.allowed and TrustReason.STALE_STATE.value in second.reason_codes


def test_missing_provenance_blocks_promotion(h):
    rid = h.new(source_id=None)
    d = h.do(rid, OP.VALIDATE)
    assert TrustReason.PROVENANCE_MISSING.value in d.reason_codes


def test_inactive_source_blocks_promotion(h):
    rid = h.new()
    h.repo._records[rid].source_id = SRC_A_INACTIVE
    d = h.do(rid, OP.VALIDATE)
    assert TrustReason.SOURCE_INVALID.value in d.reason_codes


def test_trusted_parent_provides_provenance_for_child_without_source(h):
    parent = h.drive(T)
    child = h.new(source_id=None, parent=parent)
    assert h.must(child, OP.VALIDATE).evidence_summary["lineage"]["ancestors"] == {parent: "TRUSTED"}


@pytest.mark.parametrize("parent_state,code", [
    (S, TrustReason.LINEAGE_TAINTED),
    (U, TrustReason.LINEAGE_UNVERIFIED),
])
def test_untrusted_parent_blocks_derived_promotion(h, parent_state, code):
    parent = h.drive(parent_state)
    child = h.new(parent=parent)
    d = h.do(child, OP.VALIDATE)
    assert code.value in d.reason_codes and h.state(child) == "UNVERIFIED"


def test_quarantined_grandparent_blocks_derived_promotion(h):
    gp = h.drive(T)
    p = h.new(parent=gp)
    h.must(p, OP.VALIDATE)
    c = h.new(parent=p)
    h.must(gp, OP.QUARANTINE)  # discovered poisoned after derivation
    d = h.do(c, OP.VALIDATE)
    assert TrustReason.LINEAGE_TAINTED.value in d.reason_codes
    assert d.evidence_summary["lineage"]["ancestors"][gp] == "QUARANTINED"


def test_superseded_parent_blocks_derived_promotion(h):
    parent = h.drive(T)
    child = h.new(parent=parent)
    h.must(parent, OP.SUPERSEDE, evidence={"successor_record_id": h.successor_for(parent)})
    assert TrustReason.LINEAGE_SUPERSEDED.value in h.do(child, OP.VALIDATE).reason_codes


def _trusted_record(h, rid):
    h.repo.create_record(MemoryRecord(id=rid, tenant_id=T_A, trust_state="TRUSTED"))


def _edge(h, parent, child):
    h.repo.create_edge(ProvenanceEdge(id=str(uuid.uuid4()), tenant_id=T_A, from_record_id=parent,
                                      to_record_id=child, relation_type="DERIVED_FROM"))


def test_lineage_depth_budget_exhaustion_fails_closed(h):
    target = h.new()
    child = target
    for i in range(7):
        pid = f"anc-depth-{i}"
        _trusted_record(h, pid)
        _edge(h, pid, child)
        child = pid
    d = h.do(target, OP.VALIDATE)
    assert TrustReason.LINEAGE_INCOMPLETE.value in d.reason_codes


def test_lineage_node_budget_exhaustion_fails_closed(h):
    target = h.new()
    for i in range(60):
        pid = f"anc-wide-{i}"
        _trusted_record(h, pid)
        _edge(h, pid, target)
    d = h.do(target, OP.VALIDATE)
    assert TrustReason.LINEAGE_INCOMPLETE.value in d.reason_codes


def test_dangling_or_cross_tenant_lineage_edge_fails_closed(h):
    target = h.new()
    _edge(h, "does-not-exist", target)
    assert TrustReason.LINEAGE_INCOMPLETE.value in h.do(target, OP.VALIDATE).reason_codes


def test_shared_ancestor_diamond_is_evaluated_once(h):
    root = h.drive(T)
    a = h.new(parent=root)
    h.must(a, OP.VALIDATE)
    b = h.new(parent=root)
    h.must(b, OP.VALIDATE)
    c = h.new(parent=a)
    _edge(h, b, c)
    d = h.must(c, OP.VALIDATE)
    assert set(d.evidence_summary["lineage"]["ancestors"]) == {a, b, root}


# =============================================================================
# Supersession
# =============================================================================

def test_supersede_requires_trusted_successor_and_edge(h):
    rid = h.drive(T)
    untrusted = h.new()
    assert h.do(rid, OP.SUPERSEDE, evidence={"successor_record_id": untrusted}).reason_codes == (
        TrustReason.SUCCESSOR_INVALID.value,)
    trusted_no_edge = h.drive(T)
    assert h.do(rid, OP.SUPERSEDE, evidence={"successor_record_id": trusted_no_edge}).reason_codes == (
        TrustReason.SUPERSESSION_EDGE_MISSING.value,)
    assert h.do(rid, OP.SUPERSEDE, evidence={"successor_record_id": rid}).reason_codes == (
        TrustReason.SUCCESSOR_INVALID.value,)
    assert h.state(rid) == "TRUSTED"


def test_supersede_with_cross_tenant_successor_denied(h):
    rid = h.drive(T)
    rec_b, _ = ingest_memory(T_B, "tenant b memo", repository=h.repo)
    d = h.do(rid, OP.SUPERSEDE, evidence={"successor_record_id": rec_b.id})
    assert d.reason_codes == (TrustReason.SUCCESSOR_INVALID.value,)


# =============================================================================
# E. Tenant isolation
# =============================================================================

def test_cross_tenant_transition_denied_and_indistinguishable_from_missing(h):
    rid = h.drive(U)
    d_cross = h.ev.apply(h.request(rid, OP.QUARANTINE), ANALYST_B)
    d_missing = h.ev.apply({**h.request(rid, OP.QUARANTINE), "record_id": "no-such-record"}, ANALYST_B)
    assert d_cross.reason_codes == d_missing.reason_codes == (TrustReason.RECORD_NOT_FOUND.value,)
    assert d_cross.current_state is None and d_cross.record_version is None
    assert h.state(rid) == "UNVERIFIED"


def test_cross_tenant_admin_cannot_promote(h):
    rid = h.drive(U)
    admin_b = UserActor(make_ctx(role="TENANT_ADMIN", tenant=T_B, user="admin-b"))
    d = h.ev.apply(h.request(rid, OP.VALIDATE), admin_b)
    assert d.reason_codes == (TrustReason.RECORD_NOT_FOUND.value,)


@pytest.mark.parametrize("smuggled", [{"tenant_id": T_B}, {"actor_id": "admin-1"}, {"role": "TENANT_ADMIN"},
                                      {"actor_type": "SYSTEM_INTEGRITY"}])
def test_client_supplied_tenant_or_actor_fields_rejected(h, smuggled):
    rid = h.drive(U)
    d = h.ev.apply({**h.request(rid, OP.QUARANTINE), **smuggled}, ANALYST)
    assert d.reason_codes == (TrustReason.REQUEST_INVALID.value,)
    assert h.state(rid) == "UNVERIFIED"


def test_system_actor_bound_to_other_tenant_cannot_touch_record(h):
    rid = h.drive(U)
    other = SystemActor(tenant_id=T_B, actor_type=ActorType.SYSTEM_INTEGRITY, process_ref="checksum-verifier")
    assert h.do(rid, OP.QUARANTINE, actor=other).reason_codes == (TrustReason.RECORD_NOT_FOUND.value,)


@pytest.mark.parametrize("actor", [
    None,
    UserActor(None),
    UserActor(make_ctx(active=False)),
    UserActor(make_ctx(tenant="")),
    UserActor(make_ctx(user="  ")),
    SystemActor(tenant_id="", actor_type=ActorType.SYSTEM_DETECTOR, process_ref="d"),
    SystemActor(tenant_id=T_A, actor_type=ActorType.SYSTEM_DETECTOR, process_ref=""),
    "SECURITY_ANALYST",
])
def test_missing_or_invalid_actor_context_denied(h, actor):
    rid = h.drive(U)
    d = h.do(rid, OP.FLAG_SUSPICIOUS, actor=actor)
    assert not d.allowed
    assert d.reason_codes[0] in {TrustReason.ACTOR_MISSING.value, TrustReason.ACTOR_INVALID.value}
    assert h.state(rid) == "UNVERIFIED"


def test_history_is_tenant_scoped(h):
    rid = h.drive(Q)
    assert len(h.ev.history(ANALYST, rid)) == 1
    assert h.ev.history(ANALYST_B, rid) == ()
    with pytest.raises(ForbiddenError):
        h.ev.history(UserActor(make_ctx(active=False)), rid)


# =============================================================================
# F. Fail-closed behaviour
# =============================================================================

class _Boom(Exception):
    pass


def test_repository_read_failure_denies(h, monkeypatch):
    rid = h.drive(U)
    req = h.request(rid, OP.QUARANTINE)
    monkeypatch.setattr(h.repo, "get_record", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    d = h.ev.apply(req, ANALYST)
    assert d.reason_codes == (TrustReason.REPOSITORY_UNAVAILABLE.value,)


def test_repository_write_failure_leaves_state_unchanged(h, monkeypatch):
    rid = h.drive(U)
    req = h.request(rid, OP.QUARANTINE)
    monkeypatch.setattr(h.repo, "update_record", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    d = h.ev.apply(req, ANALYST)
    assert not d.allowed and d.reason_codes == (TrustReason.REPOSITORY_UNAVAILABLE.value,)
    assert h.state(rid) == "UNVERIFIED"


def test_decision_store_append_failure_reverts_transition(h, monkeypatch):
    rid = h.drive(U)
    req = h.request(rid, OP.VALIDATE)
    monkeypatch.setattr(h.store, "append", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    d = h.ev.apply(req, ANALYST)
    assert not d.allowed and d.reason_codes == (TrustReason.DECISION_STORE_UNAVAILABLE.value,)
    assert h.state(rid) == "UNVERIFIED"  # promotion without recorded evidence is undone


def test_decision_store_read_failure_denies(h, monkeypatch):
    rid = h.drive(U)
    req = h.request(rid, OP.QUARANTINE)
    monkeypatch.setattr(h.store, "list_for_record", lambda *a, **k: (_ for _ in ()).throw(_Boom()))
    d = h.ev.apply(req, ANALYST)
    assert d.reason_codes == (TrustReason.DECISION_STORE_UNAVAILABLE.value,)
    assert h.state(rid) == "UNVERIFIED"


def test_unexpected_internal_error_denies(h, monkeypatch):
    rid = h.drive(U)
    req = h.request(rid, OP.VALIDATE)
    monkeypatch.setattr(TrustEvaluator, "_check_operation_specific", lambda *a, **k: 1 / 0)
    d = h.ev.apply(req, ANALYST)
    assert d.reason_codes == (TrustReason.EVALUATION_ERROR.value,) and not d.allowed
    assert h.state(rid) == "UNVERIFIED"


@pytest.mark.parametrize("request_obj", [None, 42, "VALIDATE", ["x"], object()])
def test_non_request_inputs_denied(h, request_obj):
    d = h.ev.apply(request_obj, ANALYST)
    assert d.reason_codes == (TrustReason.REQUEST_INVALID.value,)


def test_production_refuses_non_persistent_store_or_repository(h):
    with pytest.raises(RuntimeError):
        TrustEvaluator(h.repo, h.store, app_env="production")

    class PersistentStore(InMemoryTrustDecisionStore):
        is_persistent = True

    with pytest.raises(RuntimeError):
        TrustEvaluator(h.repo, PersistentStore(), app_env="production")  # repo still in-memory


def test_evaluate_is_side_effect_free(h):
    rid = h.drive(U)
    d = h.ev.evaluate(h.request(rid, OP.VALIDATE), ANALYST)
    assert d.allowed and not d.applied and d.decision == "PERMITTED"
    assert h.state(rid) == "UNVERIFIED" and h.ev.history(ANALYST, rid) == ()


@pytest.mark.parametrize("codes,exc,status", [
    ((TrustReason.REPOSITORY_UNAVAILABLE.value,), SecurityDependencyError, 503),
    ((TrustReason.EVALUATION_ERROR.value,), SecurityDependencyError, 503),
    ((TrustReason.ACTOR_NOT_AUTHORIZED.value,), ForbiddenError, 403),
    ((TrustReason.RECORD_NOT_FOUND.value,), NotFoundError, 404),
    ((TrustReason.REQUEST_INVALID.value,), ValidationError, 400),
    ((TrustReason.TRANSITION_NOT_ALLOWED.value,), AMSCException, 409),
])
def test_raise_for_decision_maps_to_m1_errors(h, codes, exc, status):
    rid = h.drive(U)
    denied = h.do(rid, OP.VALIDATE, full_evidence=False)
    denied = denied.__class__(**{**denied.__dict__, "reason_codes": codes})
    with pytest.raises(exc) as info:
        raise_for_decision(denied)
    assert info.value.status_code == status


def test_raise_for_decision_returns_allowed_decision(h):
    rid = h.drive(U)
    d = h.do(rid, OP.QUARANTINE)
    assert raise_for_decision(d) is d


# =============================================================================
# G. Audit evidence and history
# =============================================================================

def test_applied_decision_records_actor_reason_evidence_policy_and_time(h):
    rid = h.drive(U)
    d = h.must(rid, OP.VALIDATE, reason="Reviewed against Treasury Manual v2026")
    assert d.actor_type == "USER" and d.actor_id == "analyst-1" and d.actor_role == "SECURITY_ANALYST"
    assert d.reason == "Reviewed against Treasury Manual v2026"
    assert d.policy_version == TRUST_POLICY_VERSION
    assert d.timestamp == FIXED_NOW
    assert d.tenant_id == T_A and d.record_version == 1
    assert d.version_checksum == h.repo.get_version(rid, 1, T_A).checksum
    assert set(d.evidence_summary["dimensions"]) == {dim.value for dim in TrustDimension}
    assert d.evidence_summary["evidence_refs"] == ["det-001"]
    assert h.ev.history(ANALYST, rid)[-1] is d


def test_denied_attempts_are_recorded_and_do_not_count_as_state(h):
    rid = h.drive(U)
    h.do(rid, OP.VALIDATE, actor=UserActor(make_ctx(role="AI_DEVELOPER", user="dev-1")))
    history = h.ev.history(ANALYST, rid)
    assert len(history) == 1 and history[0].decision == "DENIED" and history[0].actor_id == "dev-1"
    assert h.ev.effective_state(T_A, rid) == "UNVERIFIED"


def test_full_lifecycle_history_and_versions_remain_inspectable(h):
    rid = h.drive(U)
    h.must(rid, OP.VALIDATE)
    h.must(rid, OP.FLAG_SUSPICIOUS, actor=DETECTOR)
    h.must(rid, OP.QUARANTINE)
    h.must(rid, OP.RELEASE_QUARANTINE, actor=ANALYST_2)
    seq = [(d.current_state, d.resulting_state) for d in h.ev.history(ANALYST, rid) if d.applied]
    assert seq == [("UNVERIFIED", "TRUSTED"), ("TRUSTED", "SUSPICIOUS"),
                   ("SUSPICIOUS", "QUARANTINED"), ("QUARANTINED", "UNVERIFIED")]
    assert len(h.repo.get_versions(rid, T_A)) == 1


def test_history_entries_are_immutable(h):
    rid = h.drive(Q)
    d = h.ev.history(ANALYST, rid)[0]
    with pytest.raises(Exception):
        d.resulting_state = "TRUSTED"  # type: ignore[misc]
    assert not hasattr(h.store, "update") and not hasattr(h.store, "delete")


def test_logs_never_contain_reason_text_or_memory_content(h, caplog):
    rid = h.new(content="CONFIDENTIAL-PAYLOAD-123")
    caplog.set_level(logging.DEBUG, logger="amsc.security.trust")
    h.do(rid, OP.VALIDATE, reason="PII: john.doe@example.com")
    h.do(rid, OP.QUARANTINE, reason="SECRET-REASON-XYZ")
    assert "CONFIDENTIAL-PAYLOAD-123" not in caplog.text
    assert "john.doe@example.com" not in caplog.text and "SECRET-REASON-XYZ" not in caplog.text
    assert "TRANSITION_APPLIED" in caplog.text


# =============================================================================
# H. History reconciliation (compensating control for out-of-band changes)
# =============================================================================

def test_m3_laundered_quarantine_cannot_be_used_to_promote_trust(h):
    """F-1 is fixed in M3 (update refused), but the stored state can still be laundered via
    M3's unguarded setter (F-2) or a direct write; M4's reconciliation must still hold."""
    rid = h.drive(Q)
    force_trust_state(T_A, rid, "UNVERIFIED", repository=h.repo)  # out-of-band stored-state write
    assert h.state(rid) == "UNVERIFIED"
    assert h.ev.effective_state(T_A, rid) == "QUARANTINED"
    laundered = h.ev.apply(h.request(rid, OP.VALIDATE, expected_state="UNVERIFIED"), ANALYST)
    assert not laundered.allowed
    assert set(laundered.reason_codes) == {TrustReason.STALE_STATE.value, TrustReason.STATE_HISTORY_MISMATCH.value}
    release = h.do(rid, OP.RELEASE_QUARANTINE, actor=ADMIN)
    assert release.reason_codes == (TrustReason.STATE_HISTORY_MISMATCH.value,)
    # Restricting operations still work from the enforced state, and reconcile the record.
    h.must(rid, OP.REJECT, actor=ADMIN)
    assert h.state(rid) == "REJECTED" and h.ev.effective_state(T_A, rid) == "REJECTED"


def test_m3_update_on_suspicious_record_keeps_suspicion(h):
    rid = h.drive(S)
    update_memory(T_A, rid, "rewritten", repository=h.repo)
    assert h.ev.effective_state(T_A, rid) == "SUSPICIOUS"


def test_out_of_band_promotion_is_not_honoured(h):
    rid = h.drive(Q)
    h.repo._records[rid].trust_state = "TRUSTED"  # direct write bypassing M4
    assert h.ev.effective_state(T_A, rid) == "QUARANTINED"


def test_gap_002_update_after_validation_is_accepted_as_invalidation(h):
    rid = h.drive(T)
    update_memory(T_A, rid, "legitimate policy update v2", repository=h.repo)
    assert h.ev.effective_state(T_A, rid) == "UNVERIFIED"
    d = h.must(rid, OP.VALIDATE, actor=ANALYST_2)
    assert d.record_version == 2


# =============================================================================
# Regression: GAP-001 / GAP-002 / GAP-004 with evaluator-driven states
# =============================================================================

def test_gap_001_retrieval_reflects_evaluator_decisions(h):
    rid = h.drive(U)
    assert rid not in [r.id for r in retrieve_memory(T_A, repository=h.repo)]
    h.must(rid, OP.VALIDATE)
    assert rid in [r.id for r in retrieve_memory(T_A, repository=h.repo)]
    h.must(rid, OP.FLAG_SUSPICIOUS, actor=DETECTOR)
    assert rid not in [r.id for r in retrieve_memory(T_A, repository=h.repo)]


def test_gap_002_update_invalidates_evaluator_trust(h):
    rid = h.drive(T)
    rec, _ = update_memory(T_A, rid, "v2", repository=h.repo)
    assert rec.trust_state == "UNVERIFIED"
    assert rid not in [r.id for r in retrieve_memory(T_A, repository=h.repo)]


@pytest.mark.parametrize("state", [U, S, Q, R, X])
def test_gap_004_detail_hidden_for_non_trusted_evaluator_states(h, state):
    rid = h.drive(state)
    with pytest.raises(MemoryNotFoundError):
        get_memory_detail(T_A, rid, repository=h.repo)
    record, _, _ = get_memory_detail(T_A, rid, for_forensic=True, repository=h.repo)
    assert record.trust_state == state.value


# =============================================================================
# Known M3 bypasses outside M4 ownership (tracked; strict xfail flips when fixed)
# =============================================================================

def test_m3_direct_transition_path_enforces_matrix(h):
    """F-2 regression (fixed): direct trust transition path enforces matrix and refuses exits from REJECTED."""
    rid = h.drive(R)
    with pytest.raises(Exception):
        transition_memory_trust_state(T_A, rid, "TRUSTED", repository=h.repo)
    assert h.state(rid) == "REJECTED"


@pytest.mark.parametrize("state", [Q, R, X])
def test_m3_update_refused_for_quarantined_record(h, state):
    """F-1 regression (fixed by M3 in main a43308c; was a strict xfail): an ordinary update
    never clears a restrictive state, writes no version, and the record stays out of retrieval."""
    rid = h.drive(state)
    before = len(h.repo.get_versions(rid, T_A))
    with pytest.raises(ValidationError):
        update_memory(T_A, rid, "rewrite", repository=h.repo)
    assert h.state(rid) == state.value and h.ev.effective_state(T_A, rid) == state.value
    assert len(h.repo.get_versions(rid, T_A)) == before
    assert rid not in [r.id for r in retrieve_memory(T_A, repository=h.repo)]


def test_m3_update_refused_for_unknown_stored_state(h):
    """F-1a regression (fixed): update_memory refuses records with unknown stored trust state (fails closed)."""
    rid = h.new()
    h.repo._records[rid].trust_state = "MOSTLY_TRUSTED"
    with pytest.raises(ValidationError):
        update_memory(T_A, rid, "rewrite", repository=h.repo)
