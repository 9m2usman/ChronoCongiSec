"""M4 quarantine security workflow and authorized forensic access.

Module: backend.app.security.quarantine
Owner: M4 — Security Engine & Incident Response Lead

Implements the M4 Day 5 deliverable (``docs/06-TEAM-IMPLEMENTATION-PLAN.md`` Day 5:
"Implement quarantine workflow: exclude quarantined records from retrieval queries").
Design and integration contract: ``docs/security-design/quarantine-workflow.md``.

``QuarantineWorkflow.quarantine`` is the only M4-sanctioned way to quarantine memory:

1. Strict request (no tenant/actor fields), verified M1 ``TenantContext``.
2. RBAC: SECURITY_ANALYST or TENANT_ADMIN via the Day 2 evaluator.
3. Tenant-scoped record lookup (cross-tenant ids look identical to missing ids).
4. Effective state from the Day 3 ``TrustEvaluator`` (history-aware).
5. Idempotency: already QUARANTINED => no new transition, no duplicate evidence;
   if history says QUARANTINED but the stored state was relaxed out of band, the
   stored state is reconciled back to QUARANTINED (restrictive direction only).
6. Transition applied ONLY through ``TrustEvaluator.apply`` (Day 3 matrix: T-04, T-07,
   T-10, T-16a). REJECTED is terminal and never re-labelled.
7. Bounded retry on concurrent change (STALE_STATE / STALE_VERSION).
8. Post-condition: stored AND effective state re-read as QUARANTINED.
9. Optional cache invalidation; then caller-supplied durable evidence persistence
   (M1/M6 ``quarantines`` row + ``audit_events``).

Failure semantics: the M4 trust decision record is mandatory durable evidence — if it
cannot be written the transition is reverted (Day 3) and the outcome is FAILED.
If the secondary evidence or cache step fails AFTER the transition, the record stays
QUARANTINED (never re-exposed to retrieval) and the outcome is NOT success
(``*_RECONCILIATION_REQUIRED``) — failing toward restriction, never toward exposure.

Normal retrieval exclusion is enforced by M3's trusted-only invariant (GAP-001/004);
this module never relaxes it. No LLM or score participates in any decision.
"""

from __future__ import annotations

import inspect
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol, Tuple, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory import MemoryRepository, TrustState, get_memory_detail
from backend.app.security.audit_identity import user_actor
from backend.app.security.authorization import Role, evaluate_role_access
from backend.app.security.trust import (
    TRANSITION_MATRIX,
    TRUST_POLICY_VERSION,
    TrustDecision,
    TrustEvaluator,
    TrustOperation,
    UserActor,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.quarantine")

QUARANTINE_POLICY_VERSION = "amsc-quarantine/1.0.0"
QUARANTINE_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)
MAX_CONCURRENCY_RETRIES = 1
# Anchored: Pydantic ``pattern`` performs a search, so an unanchored pattern would accept
# "../etc" or "inc 1" because a valid substring matches.
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")


# =============================================================================
# 1. Vocabulary
# =============================================================================

class QuarantineReasonCode(str, Enum):
    """Quarantine trigger classifications (same values as M1's Day 5 branch).

    Quarantine is containment, not a verdict: it does not assert confirmed compromise.
    Confirmed malice is expressed separately by REJECT (Day 3 T-13).
    """

    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    UNTRUSTED_MEMORY_ACTION = "UNTRUSTED_MEMORY_ACTION"
    DRIFT_DIVERGENCE_THRESHOLD = "DRIFT_DIVERGENCE_THRESHOLD"
    MANUAL_ANALYST_ISOLATION = "MANUAL_ANALYST_ISOLATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class QuarantineStatus(str, Enum):
    QUARANTINED = "QUARANTINED"                                   # success: transition applied
    ALREADY_QUARANTINED = "ALREADY_QUARANTINED"                   # success: idempotent, no new transition
    DENIED = "DENIED"                                             # not authorized / not permitted / invalid
    FAILED = "FAILED"                                             # dependency or unexpected failure; state unchanged
    EVIDENCE_RECONCILIATION_REQUIRED = "EVIDENCE_RECONCILIATION_REQUIRED"  # quarantined; secondary evidence write failed
    CACHE_RECONCILIATION_REQUIRED = "CACHE_RECONCILIATION_REQUIRED"        # quarantined; cache invalidation failed


SUCCESS_STATUSES = frozenset({QuarantineStatus.QUARANTINED, QuarantineStatus.ALREADY_QUARANTINED})


class QuarantineReason(str, Enum):
    QUARANTINE_APPLIED = "QUARANTINE_APPLIED"
    ALREADY_QUARANTINED = "ALREADY_QUARANTINED"
    STORED_STATE_RECONCILED = "STORED_STATE_RECONCILED"
    REQUEST_INVALID = "REQUEST_INVALID"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    ACTOR_NOT_AUTHORIZED = "ACTOR_NOT_AUTHORIZED"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    CURRENT_STATE_UNKNOWN = "CURRENT_STATE_UNKNOWN"
    TRANSITION_NOT_ALLOWED = "TRANSITION_NOT_ALLOWED"
    REJECTED_IS_TERMINAL = "REJECTED_IS_TERMINAL"
    INCIDENT_REQUIRED = "INCIDENT_REQUIRED"
    CONCURRENT_MODIFICATION = "CONCURRENT_MODIFICATION"
    REPOSITORY_UNAVAILABLE = "REPOSITORY_UNAVAILABLE"
    TRUST_DECISION_STORE_UNAVAILABLE = "TRUST_DECISION_STORE_UNAVAILABLE"
    TRUST_TRANSITION_FAILED = "TRUST_TRANSITION_FAILED"
    POSTCONDITION_FAILED = "POSTCONDITION_FAILED"
    EVIDENCE_PERSISTENCE_FAILED = "EVIDENCE_PERSISTENCE_FAILED"
    CACHE_INVALIDATION_FAILED = "CACHE_INVALIDATION_FAILED"
    EVALUATION_ERROR = "EVALUATION_ERROR"


# =============================================================================
# 2. Request and outcome
# =============================================================================

class QuarantineRequest(BaseModel):
    """Strict quarantine request (Doc 05 §6.2 plus classification and evidence refs).

    No tenant, actor or role fields: those come only from the verified TenantContext.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str = Field(min_length=1, max_length=128, pattern=_SAFE_ID.pattern)
    reason: str = Field(min_length=1, max_length=1000)
    reason_code: QuarantineReasonCode = QuarantineReasonCode.MANUAL_ANALYST_ISOLATION
    analyst_notes: Optional[str] = Field(default=None, max_length=2000)
    incident_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=_SAFE_ID.pattern)
    evidence_refs: Tuple[str, ...] = Field(default=(), max_length=50)
    trace_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=_SAFE_ID.pattern)


@dataclass(frozen=True)
class QuarantineOutcome:
    """Explainable, attributable result of one quarantine request (no memory content)."""

    outcome_id: str
    success: bool
    status: QuarantineStatus
    reason_codes: Tuple[str, ...]
    tenant_id: Optional[str]
    record_id: Optional[str]
    record_version: Optional[int]
    version_checksum: Optional[str]
    previous_state: Optional[str]
    resulting_state: Optional[str]
    actor_id: Optional[str]
    actor_role: Optional[str]
    reason_code: Optional[str]
    reason: Optional[str]
    analyst_notes: Optional[str]
    incident_id: Optional[str]
    evidence_refs: Tuple[str, ...]
    trust_decision_id: Optional[str]
    transition_id: Optional[str]
    policy_version: str
    trust_policy_version: str
    timestamp: datetime
    trace_id: Optional[str]
    reconciled_stored_state: bool = False
    retries: int = 0

    def to_audit_details(self) -> Dict[str, Any]:
        """``details_json`` for the MEMORY_QUARANTINED audit event (M1/M6)."""
        return {
            "outcome_id": self.outcome_id,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "record_version": self.record_version,
            "version_checksum": self.version_checksum,
            "previous_state": self.previous_state,
            "new_state": self.resulting_state,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "analyst_notes": self.analyst_notes,
            "incident_id": self.incident_id,
            "evidence_refs": list(self.evidence_refs),
            "trust_decision_id": self.trust_decision_id,
            "transition_id": self.transition_id,
            "actor_role": self.actor_role,
            "policy_version": self.policy_version,
            "trust_policy_version": self.trust_policy_version,
            "reconciled_stored_state": self.reconciled_stored_state,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_quarantine_row(self) -> Dict[str, Any]:
        """Fields for Doc 05 ``quarantines`` (id assigned by the persistence owner)."""
        return {
            "tenant_id": self.tenant_id,
            "record_id": self.record_id,
            "incident_id": self.incident_id,
            "reason": f"[{self.reason_code}] {self.reason}" if self.reason else None,
            "quarantined_by": self.actor_id,
        }


PersistEvidence = Callable[[QuarantineOutcome], Awaitable[Any]]
InvalidateCache = Callable[[str, str], Awaitable[Any]]


# =============================================================================
# 3. Workflow
# =============================================================================

class _Stop(Exception):
    def __init__(self, status: QuarantineStatus, *codes: QuarantineReason, **facts: Any):
        super().__init__(",".join(c.value for c in codes))
        self.status = status
        self.codes = codes
        self.facts = facts


def _needs_async_trust(trust: Any) -> bool:
    store = getattr(trust, "_store", None)
    repo = getattr(trust, "_repo", None)
    return (
        getattr(store, "session_factory", None) is not None
        or getattr(repo, "session_factory", None) is not None
        or inspect.iscoroutinefunction(getattr(repo, "get_record", None))
    )


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class QuarantineWorkflow:
    """Authorized, idempotent, fail-closed quarantine through the Day 3 trust evaluator."""

    def __init__(
        self,
        trust: TrustEvaluator,
        repository: MemoryRepository,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(trust, TrustEvaluator):
            raise TypeError("QuarantineWorkflow requires the Day 3 TrustEvaluator (single trust authority).")
        self._trust = trust
        self._repo = repository
        self._clock = clock

    # -- public ---------------------------------------------------------------

    def check_eligibility(self, context: Optional[TenantContext], request: Any) -> QuarantineOutcome:
        """Side-effect-free authorization + transition check (for UI/API pre-flight)."""
        facts: Dict[str, Any] = {}
        req: Optional[QuarantineRequest] = None
        try:
            req = self._coerce(request)
            self._authorize(context, facts)
            record, effective = self._load(context, req, facts)
            if effective == TrustState.QUARANTINED.value:
                return self._outcome(req, facts, QuarantineStatus.ALREADY_QUARANTINED,
                                     (QuarantineReason.ALREADY_QUARANTINED,), context)
            self._rule_for(effective, req)
            return self._outcome(req, facts, QuarantineStatus.QUARANTINED, (), context, success=True, dry_run=True)
        except _Stop as stop:
            facts.update(stop.facts)
            return self._outcome(req or _safe_req(request), facts, stop.status, stop.codes, context)
        except Exception:  # noqa: BLE001
            logger.exception("Quarantine eligibility check error (fail closed).")
            return self._outcome(req or _safe_req(request), facts, QuarantineStatus.FAILED,
                                 (QuarantineReason.EVALUATION_ERROR,), context)

    async def quarantine(
        self,
        context: Optional[TenantContext],
        request: Any,
        *,
        persist_evidence: PersistEvidence,
        invalidate_cache: Optional[InvalidateCache] = None,
    ) -> QuarantineOutcome:
        """Quarantine one memory record. Never raises; see ``raise_for_outcome``."""
        facts: Dict[str, Any] = {}
        req: Optional[QuarantineRequest] = None
        try:
            if persist_evidence is None or not callable(persist_evidence):
                raise _Stop(QuarantineStatus.FAILED, QuarantineReason.EVIDENCE_PERSISTENCE_FAILED)
            req = self._coerce(request)
            self._authorize(context, facts)
            outcome = await self._quarantine(context, req, facts, persist_evidence, invalidate_cache)
        except _Stop as stop:
            facts.update(stop.facts)
            outcome = self._outcome(req or _safe_req(request), facts, stop.status, stop.codes, context)
        except Exception:  # noqa: BLE001 — never report success on an unexpected error
            logger.exception("Quarantine workflow error (fail closed).")
            outcome = self._outcome(req or _safe_req(request), facts, QuarantineStatus.FAILED,
                                    (QuarantineReason.EVALUATION_ERROR,), context)
        self._log(outcome)
        return outcome

    # -- core -----------------------------------------------------------------

    async def _quarantine(self, context, req, facts, persist_evidence, invalidate_cache) -> QuarantineOutcome:
        retries = 0
        use_async = _needs_async_trust(self._trust)
        while True:
            record, effective = await self._aload(context, req, facts)

            if effective == TrustState.QUARANTINED.value:
                reconciled = self._reconcile_stored_state(context, req, record, facts)
                codes = [QuarantineReason.ALREADY_QUARANTINED]
                if reconciled:
                    codes.append(QuarantineReason.STORED_STATE_RECONCILED)
                facts["retries"] = retries
                # Idempotent: no new transition and no duplicate evidence rows.
                return self._outcome(req, facts, QuarantineStatus.ALREADY_QUARANTINED, tuple(codes), context)

            rule = self._rule_for(effective, req)
            if use_async and hasattr(self._trust, "aapply"):
                decision = await self._trust.aapply(self._trust_request(req, record, effective, facts), UserActor(context))
            else:
                decision = self._trust.apply(self._trust_request(req, record, effective, facts), UserActor(context))
            if decision.applied:
                break
            if self._is_stale(decision) and retries < MAX_CONCURRENCY_RETRIES:
                retries += 1
                continue  # re-read: a concurrent quarantine becomes ALREADY_QUARANTINED
            raise self._stop_for_denied_trust_decision(decision)

        facts.update(trust_decision_id=decision.decision_id, transition_id=rule.transition_id,
                     previous_state=effective, retries=retries)

        # Post-condition: stored and effective state must both read QUARANTINED.
        try:
            after = await _maybe_await(self._repo.get_record(req.record_id, context.tenant_id))
            if use_async and hasattr(self._trust, "aeffective_state"):
                after_effective = await self._trust.aeffective_state(context.tenant_id, req.record_id)
            else:
                after_effective = self._trust.effective_state(context.tenant_id, req.record_id)
        except Exception:  # noqa: BLE001
            after, after_effective = None, None
        stored_after = getattr(after, "trust_state", None) if after is not None else None
        stored_after = stored_after.value if isinstance(stored_after, TrustState) else stored_after
        if stored_after != TrustState.QUARANTINED.value or after_effective != TrustState.QUARANTINED.value:
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.POSTCONDITION_FAILED)
        facts["resulting_state"] = TrustState.QUARANTINED.value

        result_codes: List[QuarantineReason] = [QuarantineReason.QUARANTINE_APPLIED]
        status = QuarantineStatus.QUARANTINED

        if invalidate_cache is not None:
            try:
                await invalidate_cache(context.tenant_id, req.record_id)
            except Exception as exc:  # noqa: BLE001 — record stays quarantined; report not-success
                logger.error("Retrieval cache invalidation failed (%s) after quarantine.", type(exc).__name__)
                status = QuarantineStatus.CACHE_RECONCILIATION_REQUIRED
                result_codes.append(QuarantineReason.CACHE_INVALIDATION_FAILED)

        candidate = self._outcome(req, facts, status, tuple(result_codes), context)
        try:
            await persist_evidence(candidate)
        except Exception as exc:  # noqa: BLE001 — record stays quarantined; report not-success
            logger.error("Quarantine evidence persistence failed (%s); record remains QUARANTINED.",
                         type(exc).__name__)
            result_codes.append(QuarantineReason.EVIDENCE_PERSISTENCE_FAILED)
            return self._outcome(req, facts, QuarantineStatus.EVIDENCE_RECONCILIATION_REQUIRED,
                                 tuple(result_codes), context, outcome_id=candidate.outcome_id)
        return candidate

    # -- steps ----------------------------------------------------------------

    def _coerce(self, request: Any) -> QuarantineRequest:
        if isinstance(request, QuarantineRequest):
            return request
        if isinstance(request, Mapping):
            try:
                return QuarantineRequest.model_validate(dict(request))
            except PydanticValidationError:
                raise _Stop(QuarantineStatus.DENIED, QuarantineReason.REQUEST_INVALID)
        raise _Stop(QuarantineStatus.DENIED, QuarantineReason.REQUEST_INVALID)

    def _authorize(self, context: Optional[TenantContext], facts: Dict[str, Any]) -> None:
        if not isinstance(context, TenantContext) or context.is_active is not True \
                or not _nonblank(context.tenant_id) or not _nonblank(context.user_id):
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.CONTEXT_INVALID)
        rbac = evaluate_role_access(context, QUARANTINE_ROLES)
        if not rbac.allowed:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.ACTOR_NOT_AUTHORIZED)
        facts["actor_role"] = rbac.role

    def _load(self, context: TenantContext, req: QuarantineRequest, facts: Dict[str, Any]):
        try:
            record = self._repo.get_record(req.record_id, context.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.REPOSITORY_UNAVAILABLE) from exc
        if record is None or getattr(record, "tenant_id", None) != context.tenant_id:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.RECORD_NOT_FOUND)
        try:
            effective = self._trust.effective_state(context.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.TRUST_DECISION_STORE_UNAVAILABLE) from exc
        if effective is None:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.CURRENT_STATE_UNKNOWN)
        version = getattr(record, "current_version", None)
        facts["record_version"] = version
        facts["previous_state"] = effective
        facts["version_checksum"] = self._current_checksum(context.tenant_id, req.record_id, version)
        return record, effective

    async def _aload(self, context: TenantContext, req: QuarantineRequest, facts: Dict[str, Any]):
        try:
            record = await _maybe_await(self._repo.get_record(req.record_id, context.tenant_id))
        except Exception as exc:  # noqa: BLE001
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.REPOSITORY_UNAVAILABLE) from exc
        if record is None or getattr(record, "tenant_id", None) != context.tenant_id:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.RECORD_NOT_FOUND)
        try:
            if _needs_async_trust(self._trust) and hasattr(self._trust, "aeffective_state"):
                effective = await self._trust.aeffective_state(context.tenant_id, req.record_id)
            else:
                effective = self._trust.effective_state(context.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.TRUST_DECISION_STORE_UNAVAILABLE) from exc
        if effective is None:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.CURRENT_STATE_UNKNOWN)
        version = getattr(record, "current_version", None)
        facts["record_version"] = version
        facts["previous_state"] = effective
        facts["version_checksum"] = self._current_checksum(context.tenant_id, req.record_id, version)
        return record, effective

    def _current_checksum(self, tenant_id: str, record_id: str, version: Any) -> Optional[str]:
        """Checksum of the current version as recorded (evidence digest; never content)."""
        try:
            ver = self._repo.get_version(record_id, version, tenant_id) if type(version) is int else None
        except Exception:  # noqa: BLE001
            return None
        return getattr(ver, "checksum", None) if ver is not None else None

    def _rule_for(self, effective: str, req: QuarantineRequest):
        if effective == TrustState.REJECTED.value:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.REJECTED_IS_TERMINAL)
        rule = TRANSITION_MATRIX.get((TrustOperation.QUARANTINE, TrustState(effective)))
        if rule is None:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.TRANSITION_NOT_ALLOWED)
        if rule.requires_incident and not req.incident_id:
            raise _Stop(QuarantineStatus.DENIED, QuarantineReason.INCIDENT_REQUIRED)
        return rule

    def _trust_request(self, req: QuarantineRequest, record, effective: str, facts: Dict[str, Any]) -> Dict[str, Any]:
        refs = [r for r in req.evidence_refs if isinstance(r, str) and r.strip()]
        if req.incident_id:
            refs.append(f"incident:{req.incident_id}")
        if not refs:
            # Honest label: no external evidence supplied; the authenticated analyst's
            # classified attestation is the basis for containment (Doc 05 §6.2 one-click).
            refs.append(f"attestation:{req.reason_code.value}")
        refs = list(dict.fromkeys(refs))
        facts["evidence_refs"] = tuple(refs)
        return {
            "record_id": req.record_id,
            "operation": TrustOperation.QUARANTINE.value,
            "target_state": TrustState.QUARANTINED.value,
            "expected_state": effective,
            "expected_version": record.current_version,
            "reason": f"[{req.reason_code.value}] {req.reason.strip()}",
            "evidence": {"evidence_refs": refs, "incident_id": req.incident_id},
        }

    def _is_stale(self, decision: TrustDecision) -> bool:
        return bool({"STALE_STATE", "STALE_VERSION"} & set(decision.reason_codes))

    def _stop_for_denied_trust_decision(self, decision: TrustDecision) -> _Stop:
        codes = set(decision.reason_codes)
        if {"STALE_STATE", "STALE_VERSION"} & codes:
            return _Stop(QuarantineStatus.FAILED, QuarantineReason.CONCURRENT_MODIFICATION)
        if "DECISION_STORE_UNAVAILABLE" in codes:
            return _Stop(QuarantineStatus.FAILED, QuarantineReason.TRUST_DECISION_STORE_UNAVAILABLE)
        if "REPOSITORY_UNAVAILABLE" in codes:
            return _Stop(QuarantineStatus.FAILED, QuarantineReason.REPOSITORY_UNAVAILABLE)
        if "RECORD_NOT_FOUND" in codes:
            return _Stop(QuarantineStatus.DENIED, QuarantineReason.RECORD_NOT_FOUND)
        if codes & {"ACTOR_NOT_AUTHORIZED", "ACTOR_INVALID", "ACTOR_TYPE_NOT_PERMITTED", "ACTOR_MISSING"}:
            return _Stop(QuarantineStatus.DENIED, QuarantineReason.ACTOR_NOT_AUTHORIZED)
        if "TRANSITION_NOT_ALLOWED" in codes:
            return _Stop(QuarantineStatus.DENIED, QuarantineReason.TRANSITION_NOT_ALLOWED)
        if "INCIDENT_REQUIRED" in codes:
            return _Stop(QuarantineStatus.DENIED, QuarantineReason.INCIDENT_REQUIRED)
        return _Stop(QuarantineStatus.FAILED, QuarantineReason.TRUST_TRANSITION_FAILED)

    def _reconcile_stored_state(self, context, req, record, facts) -> bool:
        """History says QUARANTINED but stored state is less restrictive (out-of-band
        write, e.g. M3 update or a rollback): restore QUARANTINED. Restrictive only."""
        stored = getattr(record, "trust_state", None)
        stored = stored.value if isinstance(stored, TrustState) else stored
        if stored == TrustState.QUARANTINED.value:
            return False
        try:
            fixed = record.model_copy(update={"trust_state": TrustState.QUARANTINED.value, "updated_at": self._clock()})
            self._repo.update_record(fixed)
        except Exception as exc:  # noqa: BLE001
            raise _Stop(QuarantineStatus.FAILED, QuarantineReason.REPOSITORY_UNAVAILABLE) from exc
        logger.warning("Quarantine reconciliation: stored state %s restored to QUARANTINED for record %s.",
                       stored, req.record_id)
        facts["reconciled_stored_state"] = True
        return True

    # -- helpers --------------------------------------------------------------

    def _outcome(self, req, facts, status, codes, context, *, success: Optional[bool] = None,
                 dry_run: bool = False, outcome_id: Optional[str] = None) -> QuarantineOutcome:
        ok = status in SUCCESS_STATUSES if success is None else success
        resulting = facts.get("resulting_state")
        if resulting is None:
            resulting = facts.get("previous_state") if not dry_run else TrustState.QUARANTINED.value
        tenant_ok = isinstance(context, TenantContext) and _nonblank(getattr(context, "tenant_id", None))
        return QuarantineOutcome(
            outcome_id=outcome_id or str(uuid.uuid4()),
            success=ok,
            status=status,
            reason_codes=tuple(c.value for c in codes),
            tenant_id=context.tenant_id if tenant_ok else None,
            record_id=getattr(req, "record_id", None) if req is not None else None,
            record_version=facts.get("record_version"),
            version_checksum=facts.get("version_checksum"),
            previous_state=facts.get("previous_state"),
            resulting_state=resulting if facts.get("previous_state") is not None or dry_run else None,
            actor_id=context.user_id if tenant_ok and _nonblank(getattr(context, "user_id", None)) else None,
            actor_role=facts.get("actor_role"),
            reason_code=req.reason_code.value if isinstance(req, QuarantineRequest) else None,
            reason=req.reason.strip() if isinstance(req, QuarantineRequest) else None,
            analyst_notes=req.analyst_notes if isinstance(req, QuarantineRequest) else None,
            incident_id=req.incident_id if isinstance(req, QuarantineRequest) else None,
            evidence_refs=tuple(facts.get("evidence_refs", ())),
            trust_decision_id=facts.get("trust_decision_id"),
            transition_id=facts.get("transition_id"),
            policy_version=QUARANTINE_POLICY_VERSION,
            trust_policy_version=TRUST_POLICY_VERSION,
            timestamp=self._clock(),
            trace_id=req.trace_id if isinstance(req, QuarantineRequest) else None,
            reconciled_stored_state=bool(facts.get("reconciled_stored_state", False)),
            retries=int(facts.get("retries", 0)),
        )

    def _log(self, outcome: QuarantineOutcome) -> None:
        # Never log reason text, analyst notes or memory content.
        logger.info(
            "Quarantine outcome %s: status=%s tenant=%s record=%s %s->%s codes=%s actor=%s trust_decision=%s",
            outcome.outcome_id, outcome.status.value, outcome.tenant_id, outcome.record_id,
            outcome.previous_state, outcome.resulting_state, ",".join(outcome.reason_codes),
            outcome.actor_id, outcome.trust_decision_id,
        )


def raise_for_outcome(outcome: QuarantineOutcome) -> QuarantineOutcome:
    """Return a successful outcome; otherwise raise the matching M1 error (allowlisted messages)."""
    if outcome.success:
        return outcome
    codes = set(outcome.reason_codes)
    if outcome.status in (QuarantineStatus.EVIDENCE_RECONCILIATION_REQUIRED,
                          QuarantineStatus.CACHE_RECONCILIATION_REQUIRED) or outcome.status is QuarantineStatus.FAILED:
        raise SecurityDependencyError("Quarantine could not be completed and recorded.")
    if codes & {QuarantineReason.ACTOR_NOT_AUTHORIZED.value, QuarantineReason.CONTEXT_INVALID.value}:
        raise ForbiddenError("Quarantine not authorized.")
    if QuarantineReason.RECORD_NOT_FOUND.value in codes:
        raise NotFoundError("Memory record not found.")
    if QuarantineReason.REQUEST_INVALID.value in codes:
        raise ValidationError("Invalid quarantine request.")
    raise AMSCException(message="Quarantine transition not permitted.", code="CONFLICT", status_code=409)


# =============================================================================
# 4. Forensic access (separate, authorized, audited, non-actionable)
# =============================================================================

FORENSIC_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)
MIN_FORENSIC_REASON = 5
MAX_FORENSIC_REASON = 500


@dataclass(frozen=True)
class ForensicView:
    """Forensic read result. ``actionable`` is always False: never agent context or action evidence."""

    record: Any
    versions: Tuple[Any, ...]
    provenance: Tuple[Any, ...]
    trust_history: Tuple[TrustDecision, ...]
    audit_event: Mapping[str, Any]
    actionable: bool = False


PersistAudit = Callable[[Mapping[str, Any]], Awaitable[Any]]


class ForensicAccess:
    """Authorized forensic inspection of non-trusted memory.

    Order: authorize -> resolve record in tenant -> persist audit event -> read.
    If the audit event cannot be persisted, no content is read or returned.
    """

    def __init__(
        self,
        trust: TrustEvaluator,
        repository: MemoryRepository,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(trust, TrustEvaluator):
            raise TypeError("ForensicAccess requires the Day 3 TrustEvaluator.")
        self._trust = trust
        self._repo = repository
        self._clock = clock

    async def read(
        self,
        context: Optional[TenantContext],
        record_id: str,
        reason: str,
        *,
        persist_audit: PersistAudit,
        incident_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ForensicView:
        if not isinstance(context, TenantContext) or context.is_active is not True \
                or not _nonblank(context.tenant_id) or not _nonblank(context.user_id):
            raise ForbiddenError("Forensic access requires a verified tenant context.")
        rbac = evaluate_role_access(context, FORENSIC_ROLES)
        if not rbac.allowed:
            raise ForbiddenError("Forensic access not authorized.")
        try:
            actor = user_actor(context.user_id)   # OD-9 audit identity, from trusted context only
        except ValueError as exc:
            raise ForbiddenError("Forensic access requires a verified tenant context.") from exc
        if type(record_id) is not str or not _SAFE_ID.fullmatch(record_id):
            raise ValidationError("Invalid record identifier.")
        if type(reason) is not str or not (MIN_FORENSIC_REASON <= len(reason.strip()) <= MAX_FORENSIC_REASON):
            raise ValidationError("A forensic investigation reason is required.")
        if incident_id is not None and (type(incident_id) is not str or not _SAFE_ID.fullmatch(incident_id)):
            raise ValidationError("Invalid incident identifier.")
        if persist_audit is None or not callable(persist_audit):
            raise SecurityDependencyError("Forensic audit persistence is not configured.")

        try:
            record = self._repo.get_record(record_id, context.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise SecurityDependencyError("Memory repository unavailable.") from exc
        if record is None or getattr(record, "tenant_id", None) != context.tenant_id:
            raise NotFoundError("Memory record not found.")

        state = getattr(record, "trust_state", None)
        event = {
            "id": f"aud-{uuid.uuid4().hex[:12]}",
            "tenant_id": context.tenant_id,
            "actor_id": actor,
            "event_type": "FORENSIC_MEMORY_ACCESSED",
            "resource_id": record_id,
            "action": "FORENSIC_READ",
            "outcome": "SUCCESS",
            "trace_id": trace_id,
            "details_json": {
                "reason": reason.strip(),
                "incident_id": incident_id,
                "actor_role": rbac.role,
                "trust_state_at_access": state.value if isinstance(state, TrustState) else state,
                "record_version": getattr(record, "current_version", None),
                "policy_version": QUARANTINE_POLICY_VERSION,
            },
            "occurred_at": self._clock().isoformat(),
        }
        try:
            await persist_audit(event)
        except Exception as exc:  # noqa: BLE001 — no audit, no access
            logger.error("Forensic audit persistence failed (%s); access refused.", type(exc).__name__)
            raise SecurityDependencyError("Forensic access could not be audited.") from exc

        try:
            rec, versions, provenance = get_memory_detail(
                tenant_id=context.tenant_id, record_id=record_id, for_forensic=True, repository=self._repo,
            )
            if _needs_async_trust(self._trust) and hasattr(self._trust, "ahistory"):
                history = await self._trust.ahistory(UserActor(context), record_id)
            else:
                history = self._trust.history(UserActor(context), record_id)
        except (NotFoundError, AMSCException):
            raise
        except Exception as exc:  # noqa: BLE001
            raise SecurityDependencyError("Forensic read failed.") from exc
        logger.info("Forensic access: tenant=%s record=%s actor=%s audit=%s",
                    context.tenant_id, record_id, context.user_id, event["id"])
        return ForensicView(record=rec, versions=tuple(versions), provenance=tuple(provenance),
                            trust_history=tuple(history), audit_event=event, actionable=False)


# =============================================================================
# 5. Compatibility surface for M1's Day 5 branch (fails closed until migrated)
# =============================================================================

@dataclass(frozen=True)
class QuarantineTransitionResult:
    record_id: str
    tenant_id: str
    previous_state: str
    new_state: str
    quarantined_by: str
    reason: str
    timestamp: datetime


@runtime_checkable
class QuarantineServiceProtocol(Protocol):
    def evaluate_quarantine_eligibility(self, record: Any, actor_role: str) -> Tuple[bool, Optional[str]]: ...

    def execute_quarantine_transition(
        self, record: Any, reason: str, actor_id: str, analyst_notes: Optional[str] = None
    ) -> QuarantineTransitionResult: ...


class M4QuarantineService:
    """Name-compatible with ``feat/m1-day5-incident-quarantine``.

    ``execute_quarantine_transition`` receives only a bare ``actor_id`` string and
    mutates the record in place, so it cannot be a security boundary. It FAILS CLOSED
    (HTTP 503) and directs callers to ``QuarantineWorkflow.quarantine``.
    """

    def evaluate_quarantine_eligibility(self, record: Any, actor_role: str) -> Tuple[bool, Optional[str]]:
        if actor_role not in (Role.SECURITY_ANALYST.value, Role.TENANT_ADMIN.value):
            return False, "Role is not authorized to quarantine memory records."
        state = getattr(record, "trust_state", None)
        state = state.value if isinstance(state, TrustState) else state
        if state == TrustState.QUARANTINED.value:
            return True, None
        if type(state) is not str or state not in {s.value for s in TrustState}:
            return False, "Record trust state is unknown."
        if (TrustOperation.QUARANTINE, TrustState(state)) not in TRANSITION_MATRIX:
            return False, "Quarantine is not a permitted transition from the record's current state."
        return True, None

    def execute_quarantine_transition(self, record: Any, reason: str, actor_id: str,
                                      analyst_notes: Optional[str] = None) -> QuarantineTransitionResult:
        logger.error("Legacy quarantine path invoked; refusing (use QuarantineWorkflow.quarantine).")
        raise SecurityDependencyError(
            "Legacy quarantine transition is disabled; use backend.app.security.quarantine.QuarantineWorkflow."
        )


_default_quarantine_service: Optional[QuarantineServiceProtocol] = None


def get_default_quarantine_service() -> QuarantineServiceProtocol:
    global _default_quarantine_service
    if _default_quarantine_service is None:
        _default_quarantine_service = M4QuarantineService()
    return _default_quarantine_service


def set_default_quarantine_service(service: Optional[QuarantineServiceProtocol]) -> None:
    global _default_quarantine_service
    _default_quarantine_service = service


# =============================================================================
# 6. Utilities
# =============================================================================

def _nonblank(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _safe_req(request: Any) -> Optional[QuarantineRequest]:
    return request if isinstance(request, QuarantineRequest) else None
