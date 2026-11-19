"""Drift Monitor: deterministic observation scoring and analyst review (M4 Day 6).

Module: backend.app.security.drift
Owner: M4 — Security Engine & Incident Response Lead

Plan: ``docs/06-TEAM-IMPLEMENTATION-PLAN.md`` Day 6, M4 row ("Implement Drift Monitor
observation review and scoring endpoints"; exit: "Drift observation review persists
analyst status"). Design: ``docs/security-design/drift-monitor.md``.

Three parts:

1. ``assess_observation`` — pure, deterministic triage of one stored
   ``drift_observations`` row. It validates the stored evidence (score, classification,
   summary) and returns a *priority for analyst attention* with reason codes. It never
   returns a verdict: a high divergence score is not proof of poisoning, and no
   assessment grants trust, changes trust state or authorizes anything.
2. ``DriftReviewService`` — authorization (Day 2 RBAC), validation and the explicit
   review state machine (PENDING -> APPROVED | REJECTED; repeat = idempotent; any other
   change = conflict), executed atomically by a ``DriftReviewStore``.
3. ``SqlDriftReviewStore`` — the PostgreSQL adapter over M6's ``UnitOfWork``: one
   transaction holds a row lock (SELECT ... FOR UPDATE), a compare-and-set UPDATE on
   ``reviewer_status`` and the hash-chained ``audit_events`` append. Any failure rolls
   back all three. No new table, model or migration.

Reviewer status is NOT memory trust state. APPROVED does not promote memory; REJECTED
does not quarantine. Quarantine remains the separate Day 5 ``QuarantineWorkflow``.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.security.authorization import Role, evaluate_role_access
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.drift")

DRIFT_REVIEW_POLICY_VERSION = "amsc-drift-review/1.0.0"
REVIEWER_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)
AUDIT_EVENT_TYPE = "DRIFT_OBSERVATION_REVIEWED"
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
# Stored as VARCHAR(32) (Doc 05 / M6 model). Accept only a plain decimal in [0, 1] with
# up to 6 fractional digits: no exponents, signs, whitespace, NaN or Infinity.
_SCORE_FORMAT = re.compile(r"^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$")


# =============================================================================
# 1. Vocabulary (Doc 04 Screen 08, Doc 05 drift_observations)
# =============================================================================

class DriftClassification(str, Enum):
    LEGITIMATE_UPDATE = "LEGITIMATE_UPDATE"
    CONFLICTING_SOURCES = "CONFLICTING_SOURCES"
    OUTDATED = "OUTDATED"
    POTENTIAL_POISONING = "POTENTIAL_POISONING"


class ReviewerStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"    # Screen 08 "Accept Change": the change is a legitimate update
    REJECTED = "REJECTED"    # Screen 08 "Reject & Quarantine": the change is treated as potential poisoning


class TriagePriority(str, Enum):
    """Order of analyst attention. Not a verdict, not an authorization input."""

    TRIAGE_REQUIRED = "TRIAGE_REQUIRED"   # evidence missing/malformed: never treated as low risk
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_PRIORITY_RANK = {TriagePriority.LOW: 0, TriagePriority.MEDIUM: 1, TriagePriority.HIGH: 2,
                  TriagePriority.TRIAGE_REQUIRED: 3}


# =============================================================================
# 2. Deterministic scoring / triage
# =============================================================================

@dataclass(frozen=True)
class DriftScoringPolicy:
    """Versioned scoring configuration.

    ``review_threshold`` defaults to 0.35, the anomaly threshold shown on Doc 04 Screen 08.
    It is PROVISIONAL and UNCALIBRATED (Doc 07 §3.6: thresholds are heuristics until
    calibrated on representative data); it only orders analyst attention.
    """

    review_threshold: Decimal = Decimal("0.35")
    version: str = "amsc-drift-scoring/1.0.0-provisional"
    threshold_source: str = "Doc 04 Screen 08 display value (uncalibrated)"

    def validated(self) -> "DriftScoringPolicy":
        t = self.review_threshold
        if not isinstance(t, Decimal) or not t.is_finite() or not (Decimal(0) < t < Decimal(1)):
            raise ValueError("review_threshold must be a finite Decimal strictly between 0 and 1.")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("Scoring policy version is required.")
        return self


@dataclass(frozen=True)
class DriftAssessment:
    valid_evidence: bool
    score: Optional[str]                  # canonical decimal string, None if invalid
    classification: Optional[str]         # None if unknown
    exceeds_review_threshold: Optional[bool]
    review_threshold: str
    priority: TriagePriority
    reason_codes: Tuple[str, ...]
    scoring_policy_version: str
    is_verdict: bool = False              # always False: triage only

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid_evidence": self.valid_evidence,
            "score": self.score,
            "classification": self.classification,
            "exceeds_review_threshold": self.exceeds_review_threshold,
            "review_threshold": self.review_threshold,
            "priority": self.priority.value,
            "reason_codes": list(self.reason_codes),
            "scoring_policy_version": self.scoring_policy_version,
            "is_verdict": self.is_verdict,
        }


def parse_divergence_score(raw: Any) -> Optional[Decimal]:
    """Strictly parse a stored divergence score; None for anything not a plain decimal in [0, 1].

    Never clamps: "1.2", "-0.1", "NaN", "Infinity", "1e-1", " 0.5", floats and bools are invalid.
    """
    if type(raw) is not str or not _SCORE_FORMAT.fullmatch(raw):
        return None
    value = Decimal(raw)
    return value if Decimal(0) <= value <= Decimal(1) else None


_CLASSIFICATION_RULES: Mapping[DriftClassification, Tuple[TriagePriority, TriagePriority, str]] = {
    # classification: (priority at/above threshold, priority below threshold, reason code)
    DriftClassification.POTENTIAL_POISONING: (TriagePriority.HIGH, TriagePriority.MEDIUM, "CLASSIFIED_POTENTIAL_POISONING"),
    DriftClassification.CONFLICTING_SOURCES: (TriagePriority.MEDIUM, TriagePriority.LOW, "CLASSIFIED_CONFLICTING_SOURCES"),
    DriftClassification.OUTDATED: (TriagePriority.MEDIUM, TriagePriority.LOW, "CLASSIFIED_OUTDATED"),
    # A detector's "legitimate" label is itself unverified evidence: a large shift still needs confirmation.
    DriftClassification.LEGITIMATE_UPDATE: (TriagePriority.MEDIUM, TriagePriority.LOW, "CLASSIFIED_LEGITIMATE_UPDATE"),
}


def assess_observation(observation: "DriftObservationView", policy: DriftScoringPolicy = DriftScoringPolicy()) -> DriftAssessment:
    """Deterministic triage of one observation. Same inputs and policy => same result."""
    codes: List[str] = []
    score = parse_divergence_score(getattr(observation, "divergence_score", None))
    if score is None:
        codes.append("SCORE_INVALID_OR_MISSING")

    raw_class = getattr(observation, "classification", None)
    try:
        classification = DriftClassification(raw_class) if type(raw_class) is str else None
    except ValueError:
        classification = None
    if classification is None:
        codes.append("CLASSIFICATION_UNKNOWN")

    summary = getattr(observation, "evidence_summary", None)
    if type(summary) is not str or not summary.strip():
        codes.append("EVIDENCE_SUMMARY_MISSING")

    threshold = policy.review_threshold
    if codes:
        # Missing or malformed evidence is never low risk.
        return DriftAssessment(False, None if score is None else _fmt(score),
                               classification.value if classification else None,
                               None if score is None else score >= threshold, _fmt(threshold),
                               TriagePriority.TRIAGE_REQUIRED, tuple(codes), policy.version)

    exceeds = score >= threshold  # at the threshold counts as exceeding
    above, below, class_code = _CLASSIFICATION_RULES[classification]
    priority = above if exceeds else below
    codes = [class_code, "SCORE_AT_OR_ABOVE_REVIEW_THRESHOLD" if exceeds else "SCORE_BELOW_REVIEW_THRESHOLD"]
    return DriftAssessment(True, _fmt(score), classification.value, exceeds, _fmt(threshold),
                           priority, tuple(codes), policy.version)


def _fmt(value: Decimal) -> str:
    return format(value.normalize(), "f") if value != 0 else "0"


# =============================================================================
# 3. Store contract (atomic review) and value objects
# =============================================================================

@dataclass(frozen=True)
class DriftObservationView:
    """Read-only projection of one ``drift_observations`` row (canonical fields only)."""

    id: str
    tenant_id: str
    record_id: str
    classification: str
    divergence_score: str
    evidence_summary: str
    reviewer_status: str
    created_at: Optional[datetime]


class PlanKind(str, Enum):
    APPLY = "APPLY"
    UNCHANGED = "UNCHANGED"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class ReviewPlan:
    kind: PlanKind
    new_status: Optional[str] = None
    reason_code: str = ""
    audit_details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditDraft:
    """What the store must append to ``audit_events`` in the same transaction."""

    actor_id: str
    trace_id: Optional[str]
    details: Mapping[str, Any]


@dataclass(frozen=True)
class StoreReviewResult:
    plan: ReviewPlan
    before: DriftObservationView
    after: DriftObservationView
    audit_event_id: Optional[str]
    audit_chain_seq: Optional[int] = None


class ReviewConflict(Exception):
    """The compare-and-set failed: the row changed between lock and update."""


class DriftReviewStore(Protocol):
    """Tenant-scoped persistence for drift observations (implemented over M6's UnitOfWork).

    ``review`` must, in ONE transaction: lock the row, call ``decide(view)``, and for an
    APPLY plan perform a compare-and-set update of ``reviewer_status`` (expected = the
    locked value) and append the audit event; any exception rolls everything back.
    """

    async def list_observations(self, tenant_id: str, *, limit: int, offset: int,
                                classification: Optional[str], reviewer_status: Optional[str]) -> Sequence[DriftObservationView]: ...

    async def review(self, tenant_id: str, observation_id: str,
                     decide: Callable[[DriftObservationView], ReviewPlan],
                     audit: Callable[[ReviewPlan, DriftObservationView], AuditDraft]) -> Optional[StoreReviewResult]: ...


# =============================================================================
# 4. Review service
# =============================================================================

class ReviewOutcomeKind(str, Enum):
    APPLIED = "APPLIED"
    UNCHANGED = "UNCHANGED"   # idempotent repeat of the same decision: no write, no audit


@dataclass(frozen=True)
class ReviewOutcome:
    kind: ReviewOutcomeKind
    observation: DriftObservationView
    previous_status: str
    assessment: DriftAssessment
    audit_event_id: Optional[str]
    follow_up: str
    policy_version: str = DRIFT_REVIEW_POLICY_VERSION


class DriftConflictError(AMSCException):
    def __init__(self, message: str = "Drift observation review conflicts with its current state.") -> None:
        super().__init__(message=message, code="CONFLICT", status_code=409)


_ALLOWED_REVIEW_TARGETS = {ReviewerStatus.APPROVED.value, ReviewerStatus.REJECTED.value}
_KNOWN_STATUSES = {s.value for s in ReviewerStatus}
MAX_PAGE = 100


def decide_review(current: DriftObservationView, requested: str) -> ReviewPlan:
    """Explicit review state machine (pure).

    PENDING -> APPROVED | REJECTED       apply
    X -> X (same decision repeated)      unchanged (idempotent)
    APPROVED <-> REJECTED                refused: changing a recorded decision needs a
                                         separate, explicitly authorized policy (not defined)
    unknown stored status                refused (fail closed)
    """
    status = current.reviewer_status
    if status not in _KNOWN_STATUSES:
        return ReviewPlan(PlanKind.REFUSE, reason_code="STORED_STATUS_UNKNOWN")
    if status == requested:
        return ReviewPlan(PlanKind.UNCHANGED, new_status=status, reason_code="ALREADY_REVIEWED_SAME_DECISION")
    if status == ReviewerStatus.PENDING.value:
        return ReviewPlan(PlanKind.APPLY, new_status=requested, reason_code="REVIEW_RECORDED")
    return ReviewPlan(PlanKind.REFUSE, reason_code="ALREADY_REVIEWED_DIFFERENT_DECISION")


class DriftReviewService:
    def __init__(self, store: DriftReviewStore, policy: Optional[DriftScoringPolicy] = None,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        if store is None:
            raise ValueError("A DriftReviewStore is required.")
        self._store = store
        self._policy = (policy or DriftScoringPolicy()).validated()
        self._clock = clock

    @property
    def policy(self) -> DriftScoringPolicy:
        return self._policy

    def assess(self, observation: DriftObservationView) -> DriftAssessment:
        return assess_observation(observation, self._policy)

    async def list_observations(self, context: Optional[TenantContext], *, limit: int = 50, offset: int = 0,
                                classification: Optional[str] = None, reviewer_status: Optional[str] = None,
                                ) -> List[Tuple[DriftObservationView, DriftAssessment]]:
        tenant_id = _require_context(context)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE:
            raise ValidationError("limit must be an integer between 1 and 100.")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValidationError("offset must be a non-negative integer.")
        if classification is not None and classification not in {c.value for c in DriftClassification}:
            raise ValidationError("Unknown classification filter.")
        if reviewer_status is not None and reviewer_status not in _KNOWN_STATUSES:
            raise ValidationError("Unknown reviewer_status filter.")
        try:
            rows = await self._store.list_observations(tenant_id, limit=limit, offset=offset,
                                                       classification=classification,
                                                       reviewer_status=reviewer_status)
        except AMSCException:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("Drift observation listing failed (%s).", type(exc).__name__)
            raise SecurityDependencyError("Drift observation store unavailable.") from exc
        if rows is None or isinstance(rows, (str, bytes, Mapping)):
            raise SecurityDependencyError("Drift observation store returned an invalid result.")
        out = []
        for row in rows:
            if not isinstance(row, DriftObservationView):
                raise SecurityDependencyError("Drift observation store returned an invalid result.")
            if row.tenant_id != tenant_id:  # defence in depth: never return another tenant's row
                logger.critical("Drift store returned a cross-tenant row; response suppressed.")
                raise SecurityDependencyError("Drift observation store returned inconsistent data.")
            out.append((row, self.assess(row)))
        return out

    async def review(self, context: Optional[TenantContext], observation_id: Any, requested_status: Any,
                     *, trace_id: Optional[str] = None) -> ReviewOutcome:
        tenant_id = _require_context(context)
        rbac = evaluate_role_access(context, REVIEWER_ROLES)
        if not rbac.allowed:
            raise ForbiddenError("Drift review requires SECURITY_ANALYST or TENANT_ADMIN.")
        if type(observation_id) is not str or not _SAFE_ID.fullmatch(observation_id):
            raise ValidationError("Invalid observation identifier.")
        if type(requested_status) is not str or requested_status not in _ALLOWED_REVIEW_TARGETS:
            raise ValidationError("status must be APPROVED or REJECTED.")
        trace = trace_id if type(trace_id) is str and _SAFE_ID.fullmatch(trace_id) else None
        reviewed_at = self._clock()

        def decide(view: DriftObservationView) -> ReviewPlan:
            return decide_review(view, requested_status)

        def audit(plan: ReviewPlan, before: DriftObservationView) -> AuditDraft:
            assessment = self.assess(before)
            return AuditDraft(actor_id=context.user_id, trace_id=trace, details={
                "observation_id": before.id,
                "record_id": before.record_id,
                "previous_status": before.reviewer_status,
                "new_status": plan.new_status,
                "classification": before.classification,
                "divergence_score": before.divergence_score,
                "assessment": assessment.to_dict(),
                "actor_role": rbac.role,
                "reviewed_at": reviewed_at.isoformat(),
                "review_policy_version": DRIFT_REVIEW_POLICY_VERSION,
                "memory_trust_changed": False,
            })

        try:
            result = await self._store.review(tenant_id, observation_id, decide, audit)
        except ReviewConflict:
            raise DriftConflictError("Drift observation was reviewed concurrently.")
        except AMSCException:
            raise
        except Exception as exc:  # noqa: BLE001 — store/audit failure: nothing committed
            logger.error("Drift review not persisted (%s); transaction rolled back.", type(exc).__name__)
            raise SecurityDependencyError("Drift review could not be persisted.") from exc

        if result is None:
            raise NotFoundError("Drift observation not found.")  # also for other tenants' ids
        if not isinstance(result, StoreReviewResult) or not isinstance(result.plan, ReviewPlan) \
                or not isinstance(result.before, DriftObservationView) or not isinstance(result.after, DriftObservationView):
            raise SecurityDependencyError("Drift observation store returned an invalid result.")
        if result.after.tenant_id != tenant_id or result.before.tenant_id != tenant_id:
            raise SecurityDependencyError("Drift observation store returned inconsistent data.")
        plan = result.plan
        if plan.kind is PlanKind.REFUSE:
            raise DriftConflictError()
        if plan.kind is PlanKind.APPLY and (result.after.reviewer_status != plan.new_status or not result.audit_event_id):
            raise SecurityDependencyError("Drift review post-condition failed.")

        kind = ReviewOutcomeKind.APPLIED if plan.kind is PlanKind.APPLY else ReviewOutcomeKind.UNCHANGED
        follow_up = ("QUARANTINE_DECISION_REQUIRED" if result.after.reviewer_status == ReviewerStatus.REJECTED.value
                     else "NO_TRUST_CHANGE")
        outcome = ReviewOutcome(kind=kind, observation=result.after, previous_status=result.before.reviewer_status,
                                assessment=self.assess(result.after), audit_event_id=result.audit_event_id,
                                follow_up=follow_up)
        logger.info("Drift review %s: tenant=%s observation=%s %s->%s actor=%s audit=%s",
                    kind.value, tenant_id, observation_id, outcome.previous_status,
                    result.after.reviewer_status, context.user_id, result.audit_event_id)
        return outcome


def _require_context(context: Any) -> str:
    if not isinstance(context, TenantContext) or context.is_active is not True \
            or type(context.tenant_id) is not str or not context.tenant_id.strip() \
            or type(context.user_id) is not str or not context.user_id.strip():
        raise ForbiddenError("A verified tenant context is required.")
    return context.tenant_id


# =============================================================================
# 5. PostgreSQL adapter over M6's UnitOfWork
# =============================================================================

def build_lock_statement(tenant_id: str, observation_id: str):
    """SELECT ... FOR UPDATE, tenant-filtered (exposed for SQL verification tests)."""
    from sqlalchemy import select

    from backend.app.database.models import DriftObservation

    return (
        select(DriftObservation)
        .where(DriftObservation.id == observation_id, DriftObservation.tenant_id == tenant_id)
        .with_for_update()
    )


def build_compare_and_set_statement(tenant_id: str, observation_id: str, expected: str, new: str):
    """UPDATE ... SET reviewer_status=new WHERE id AND tenant AND reviewer_status=expected RETURNING id.

    Returns only the id (Core-style) so no stale identity-mapped ORM object is involved.
    """
    from sqlalchemy import update

    from backend.app.database.models import DriftObservation

    return (
        update(DriftObservation)
        .where(DriftObservation.id == observation_id,
               DriftObservation.tenant_id == tenant_id,
               DriftObservation.reviewer_status == expected)
        .values(reviewer_status=new)
        .returning(DriftObservation.id)
        .execution_options(synchronize_session=False)
    )


def _view(row: Any) -> DriftObservationView:
    return DriftObservationView(id=row.id, tenant_id=row.tenant_id, record_id=row.record_id,
                                classification=row.classification, divergence_score=row.divergence_score,
                                evidence_summary=row.evidence_summary, reviewer_status=row.reviewer_status,
                                created_at=row.created_at)


class SqlDriftReviewStore:
    """``DriftReviewStore`` over M6's ``UnitOfWork`` and ``TenantScopedRepository``.

    Requires PostgreSQL (``postgresql+asyncpg``; M6 session factory). The audit event is
    appended through ``tx.audit.append`` (append-only, hash-chained by migration 0009).
    """

    def __init__(self, session_factory: Any) -> None:
        from backend.app.database.unit_of_work import UnitOfWork

        if session_factory is None:
            raise ValueError("An M6 session factory is required.")
        self._uow = UnitOfWork(session_factory)

    async def list_observations(self, tenant_id: str, *, limit: int, offset: int,
                                classification: Optional[str], reviewer_status: Optional[str]) -> Sequence[DriftObservationView]:
        from backend.app.database.models import DriftObservation
        from backend.app.database.repositories.base import TenantScopedRepository

        filters: Dict[str, Any] = {}
        if classification is not None:
            filters["classification"] = classification
        if reviewer_status is not None:
            filters["reviewer_status"] = reviewer_status
        async with self._uow(tenant_id) as tx:
            repo = TenantScopedRepository(tx.session, tenant_id, model=DriftObservation)
            rows = await repo.list(limit=limit, offset=offset, **filters)
            return [_view(r) for r in rows]

    async def review(self, tenant_id: str, observation_id: str,
                     decide: Callable[[DriftObservationView], ReviewPlan],
                     audit: Callable[[ReviewPlan, DriftObservationView], AuditDraft]) -> Optional[StoreReviewResult]:
        from backend.app.database.models import AuditEvent

        async with self._uow(tenant_id) as tx:  # COMMIT on exit, ROLLBACK on any exception
            row = (await tx.session.execute(build_lock_statement(tenant_id, observation_id))).scalar_one_or_none()
            if row is None:
                return None
            before = _view(row)
            plan = decide(before)
            if plan.kind is not PlanKind.APPLY:
                return StoreReviewResult(plan=plan, before=before, after=before, audit_event_id=None)
            updated_id = (await tx.session.execute(
                build_compare_and_set_statement(tenant_id, observation_id, before.reviewer_status, plan.new_status)
            )).scalar_one_or_none()
            if updated_id != observation_id:
                raise ReviewConflict()
            after = replace(before, reviewer_status=plan.new_status)
            draft = audit(plan, before)
            event = await tx.audit.append(AuditEvent(
                id=str(uuid.uuid4()), actor_id=draft.actor_id, event_type=AUDIT_EVENT_TYPE,
                resource_id=observation_id, action="REVIEW", outcome="SUCCESS",
                trace_id=draft.trace_id, details_json=dict(draft.details),
            ))
            return StoreReviewResult(plan=plan, before=before, after=after,
                                     audit_event_id=event.id, audit_chain_seq=getattr(event, "chain_seq", None))
