"""Unit tests: drift scoring, review state machine and SQL adapter statements (M4 Day 6).

Module: backend.tests.security.test_drift_scoring
Owner: M4 — Security Engine & Incident Response Lead
"""

from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy.dialects import postgresql

from backend.app.security.drift import (
    DriftObservationView,
    DriftScoringPolicy,
    PlanKind,
    TriagePriority,
    assess_observation,
    build_compare_and_set_statement,
    build_lock_statement,
    decide_review,
    parse_divergence_score,
)

T_A = "tenant-a-uuid-001"


def obs(score="0.50", classification="POTENTIAL_POISONING", summary="Account number replaced", status="PENDING"):
    return DriftObservationView(id="obs-1", tenant_id=T_A, record_id="mem-1", classification=classification,
                                divergence_score=score, evidence_summary=summary, reviewer_status=status,
                                created_at=datetime(2026, 11, 18, tzinfo=timezone.utc))


# =============================================================================
# A. Scoring
# =============================================================================

@pytest.mark.parametrize("raw,expected", [
    ("0", Decimal("0")), ("0.0", Decimal("0")), ("0.05", Decimal("0.05")), ("0.35", Decimal("0.35")),
    ("0.78", Decimal("0.78")), ("1", Decimal("1")), ("1.0", Decimal("1")), ("1.000000", Decimal("1")),
    ("0.123456", Decimal("0.123456")),
])
def test_valid_scores_parse_exactly(raw, expected):
    assert parse_divergence_score(raw) == expected


@pytest.mark.parametrize("raw", [
    "-0.1", "-0", "1.01", "1.000001", "2", "NaN", "nan", "Infinity", "-Infinity", "inf", "1e-1", "0.1e0",
    " 0.5", "0.5 ", "+0.5", ".5", "0.", "0.1234567", "", "0,5", "0x1", None, 0.5, 1, True, Decimal("0.5"),
])
def test_invalid_scores_rejected_never_clamped(raw):
    assert parse_divergence_score(raw) is None


@pytest.mark.parametrize("score,classification,priority,exceeds", [
    ("0.05", "POTENTIAL_POISONING", TriagePriority.MEDIUM, False),   # low score, suspicious label
    ("0.50", "POTENTIAL_POISONING", TriagePriority.HIGH, True),      # moderate
    ("0.95", "POTENTIAL_POISONING", TriagePriority.HIGH, True),      # high
    ("0.95", "CONFLICTING_SOURCES", TriagePriority.MEDIUM, True),
    ("0.10", "CONFLICTING_SOURCES", TriagePriority.LOW, False),
    ("0.95", "OUTDATED", TriagePriority.MEDIUM, True),
    ("0.10", "OUTDATED", TriagePriority.LOW, False),
    ("0.95", "LEGITIMATE_UPDATE", TriagePriority.MEDIUM, True),      # detector's label is not trusted blindly
    ("0.10", "LEGITIMATE_UPDATE", TriagePriority.LOW, False),
])
def test_priority_matrix(score, classification, priority, exceeds):
    a = assess_observation(obs(score, classification))
    assert a.valid_evidence and a.priority is priority and a.exceeds_review_threshold is exceeds
    assert a.is_verdict is False


@pytest.mark.parametrize("score,exceeds", [("0.35", True), ("0.349999", False), ("0.350001", True)])
def test_threshold_boundaries(score, exceeds):
    a = assess_observation(obs(score))
    assert a.exceeds_review_threshold is exceeds and a.review_threshold == "0.35"
    assert ("SCORE_AT_OR_ABOVE_REVIEW_THRESHOLD" in a.reason_codes) is exceeds


@pytest.mark.parametrize("field,value,code", [
    ("divergence_score", "1.2", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", "-0.5", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", "NaN", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", "Infinity", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", "-Infinity", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", "", "SCORE_INVALID_OR_MISSING"),
    ("divergence_score", None, "SCORE_INVALID_OR_MISSING"),
    ("evidence_summary", "", "EVIDENCE_SUMMARY_MISSING"),
    ("evidence_summary", "   ", "EVIDENCE_SUMMARY_MISSING"),
    ("evidence_summary", None, "EVIDENCE_SUMMARY_MISSING"),
    ("classification", "MALICIOUS", "CLASSIFICATION_UNKNOWN"),
    ("classification", "potential_poisoning", "CLASSIFICATION_UNKNOWN"),
    ("classification", None, "CLASSIFICATION_UNKNOWN"),
])
def test_missing_or_malformed_evidence_is_never_low_risk(field, value, code):
    a = assess_observation(replace(obs("0.01", "LEGITIMATE_UPDATE"), **{field: value}))
    assert a.valid_evidence is False and a.priority is TriagePriority.TRIAGE_REQUIRED
    assert code in a.reason_codes and a.is_verdict is False


def test_scoring_is_deterministic():
    o = obs("0.6180", "CONFLICTING_SOURCES")
    results = {assess_observation(o) for _ in range(100)}
    assert len(results) == 1


def test_assessment_never_contains_evidence_text():
    a = assess_observation(obs(summary="SECRET vendor account ACC-123"))
    assert "SECRET" not in repr(a.to_dict()) and "ACC-123" not in repr(a.to_dict())


def test_canonical_score_formatting():
    assert assess_observation(obs("0.500")).score == "0.5"
    assert assess_observation(obs("0")).score == "0"
    assert assess_observation(obs("1.0")).score == "1"


def test_custom_policy_threshold_and_version_recorded():
    policy = DriftScoringPolicy(review_threshold=Decimal("0.6"), version="amsc-drift-scoring/test").validated()
    a = assess_observation(obs("0.5"), policy)
    assert a.exceeds_review_threshold is False and a.scoring_policy_version == "amsc-drift-scoring/test"


@pytest.mark.parametrize("threshold", [Decimal("0"), Decimal("1"), Decimal("-0.1"), Decimal("NaN"),
                                       Decimal("Infinity"), 0.35, "0.35"])
def test_invalid_policy_threshold_rejected(threshold):
    with pytest.raises(ValueError):
        DriftScoringPolicy(review_threshold=threshold).validated()  # type: ignore[arg-type]


# =============================================================================
# Review state machine
# =============================================================================

@pytest.mark.parametrize("current,requested,kind,code", [
    ("PENDING", "APPROVED", PlanKind.APPLY, "REVIEW_RECORDED"),
    ("PENDING", "REJECTED", PlanKind.APPLY, "REVIEW_RECORDED"),
    ("APPROVED", "APPROVED", PlanKind.UNCHANGED, "ALREADY_REVIEWED_SAME_DECISION"),
    ("REJECTED", "REJECTED", PlanKind.UNCHANGED, "ALREADY_REVIEWED_SAME_DECISION"),
    ("APPROVED", "REJECTED", PlanKind.REFUSE, "ALREADY_REVIEWED_DIFFERENT_DECISION"),
    ("REJECTED", "APPROVED", PlanKind.REFUSE, "ALREADY_REVIEWED_DIFFERENT_DECISION"),
    ("ESCALATED", "APPROVED", PlanKind.REFUSE, "STORED_STATUS_UNKNOWN"),
    ("pending", "APPROVED", PlanKind.REFUSE, "STORED_STATUS_UNKNOWN"),
])
def test_review_state_machine(current, requested, kind, code):
    plan = decide_review(obs(status=current), requested)
    assert plan.kind is kind and plan.reason_code == code
    if kind is PlanKind.APPLY:
        assert plan.new_status == requested


# =============================================================================
# PostgreSQL adapter statements (compiled against the real PostgreSQL dialect)
# =============================================================================

def _sql(stmt) -> str:
    return str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


def test_lock_statement_is_tenant_scoped_and_locks_row():
    sql = _sql(build_lock_statement(T_A, "obs-1"))
    assert "FROM drift_observations" in sql and "FOR UPDATE" in sql
    assert "drift_observations.tenant_id = 'tenant-a-uuid-001'" in sql
    assert "drift_observations.id = 'obs-1'" in sql


def test_compare_and_set_requires_tenant_id_and_expected_status():
    sql = _sql(build_compare_and_set_statement(T_A, "obs-1", "PENDING", "APPROVED"))
    assert sql.startswith("UPDATE drift_observations SET reviewer_status='APPROVED'")
    assert "drift_observations.tenant_id = 'tenant-a-uuid-001'" in sql
    assert "drift_observations.reviewer_status = 'PENDING'" in sql
    assert "RETURNING drift_observations.id" in sql
    # Evidence columns are never written by a review.
    for column in ("classification", "divergence_score", "evidence_summary", "record_id", "tenant_id ="):
        assert f"SET {column}" not in sql
