"""Deterministic memory trust state machine and trust evaluator.

Module: backend.app.security.trust
Owner: M4 — Security Engine & Incident Response Lead

Implements the M4 Day 3 deliverable from ``docs/06-TEAM-IMPLEMENTATION-PLAN.md``
("Implement trust state machine (UNVERIFIED, TRUSTED, SUSPICIOUS, QUARANTINED)";
exit criterion: state transitions obey valid transition rules), following
TRD §15.3 and ``docs/security-design/policy-evaluation-matrix.md`` §7-§8.

Key properties (details in ``docs/security-design/trust-state-machine.md``):

* **Explicit matrix, default deny.** Every transition is an (operation, from_state)
  entry in ``TRANSITION_MATRIX``. Anything not listed is denied.
* **Promotion only through validation.** ``TRUSTED`` is reachable only from
  ``UNVERIFIED`` via ``VALIDATE``. That requires an authorised human actor, a
  current-version assessment and evidence for all eight trust dimensions.
  Integrity, version currency, provenance and lineage are recomputed here from
  M3's repository; the caller's word is not accepted for them.
* **Monotone automation.** System processes may only make a record *more*
  restricted. Every operation that relaxes restriction requires an authenticated
  analyst/admin ``TenantContext`` checked by the Day 2 RBAC evaluator.
* **Recovery never trusts.** ``RECOVERY_RESTORE`` yields ``UNVERIFIED`` only.
* **Tenant-scoped.** The tenant comes from the actor (server-side context), never
  from the request. Records outside the tenant are reported as not found.
* **Stale-safe.** Requests carry ``expected_state`` / ``expected_version``; the
  validation assessment is bound to the current version's checksum.
* **History-aware.** Each decision (applied or denied) is appended to a
  ``TrustDecisionStore``. Out-of-band state changes that contradict the history
  (e.g. M3 ``update_memory`` turning QUARANTINED into UNVERIFIED) are detected,
  the more restrictive state is enforced, and relaxing operations are denied.
* **Fail closed.** ``evaluate``/``apply`` never raise. Any repository, store or
  internal error produces a DENIED decision.
* **Deterministic.** No LLM or ML output can allow a transition. Model signals are
  evidence only and can only block promotion.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory import MemoryRepository, ProvenanceRelationType, TrustState, sha256_hex
from backend.app.security.authorization import Role, evaluate_role_access
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.trust")

TRUST_POLICY_VERSION = "amsc-trust-policy/1.0.0"

# Lineage traversal budgets. One shared visited set and global counters (avoids GAP-005).
MAX_LINEAGE_DEPTH = 5  # TRD §22 / M3 MAX_PROVENANCE_DEPTH
MAX_LINEAGE_NODES = 50
MAX_LINEAGE_EDGES = 200

MAX_REASON_LENGTH = 2000
MAX_EVIDENCE_REFS = 50

ANALYST_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)


# =============================================================================
# 1. Vocabulary
# =============================================================================

class TrustOperation(str, Enum):
    """Named trust operations. Each operation has a single, fixed resulting state."""

    VALIDATE = "VALIDATE"                      # T-02  UNVERIFIED -> TRUSTED
    FLAG_SUSPICIOUS = "FLAG_SUSPICIOUS"        # T-03/T-06  -> SUSPICIOUS
    QUARANTINE = "QUARANTINE"                  # T-04/T-07/T-10/T-16 -> QUARANTINED
    REJECT = "REJECT"                          # T-05/T-12/T-13/T-16 -> REJECTED
    INVALIDATE = "INVALIDATE"                  # T-08  TRUSTED -> UNVERIFIED
    SUPERSEDE = "SUPERSEDE"                    # T-09  TRUSTED -> SUPERSEDED
    CLEAR_SUSPICION = "CLEAR_SUSPICION"        # T-11  SUSPICIOUS -> UNVERIFIED
    RELEASE_QUARANTINE = "RELEASE_QUARANTINE"  # T-14  QUARANTINED -> UNVERIFIED
    RECOVERY_RESTORE = "RECOVERY_RESTORE"      # T-17  -> UNVERIFIED (never TRUSTED)


class ActorType(str, Enum):
    USER = "USER"
    SYSTEM_DETECTOR = "SYSTEM_DETECTOR"      # injection/anomaly detectors, drift monitor
    SYSTEM_INTEGRITY = "SYSTEM_INTEGRITY"    # checksum / MAC verification
    SYSTEM_UPDATE = "SYSTEM_UPDATE"          # content-update invalidation


class TrustDimension(str, Enum):
    """Distinct trust dimensions (Doc 07 §3.2). Never collapsed into one score."""

    SOURCE_IDENTITY = "SOURCE_IDENTITY"
    SOURCE_AUTHORITY = "SOURCE_AUTHORITY"
    INTEGRITY = "INTEGRITY"
    FRESHNESS = "FRESHNESS"
    SENSITIVITY = "SENSITIVITY"
    POLICY_SCOPE = "POLICY_SCOPE"
    CONTRADICTION = "CONTRADICTION"
    LINEAGE = "LINEAGE"


class DimensionStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SignalSeverity(str, Enum):
    INFO = "INFO"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TrustReason(str, Enum):
    """Machine-readable reason codes (logged and stored; never contain content)."""

    TRANSITION_APPLIED = "TRANSITION_APPLIED"
    TRANSITION_PERMITTED = "TRANSITION_PERMITTED"  # evaluate() dry-run
    REQUEST_INVALID = "REQUEST_INVALID"
    TARGET_STATE_MISMATCH = "TARGET_STATE_MISMATCH"
    TRANSITION_NOT_ALLOWED = "TRANSITION_NOT_ALLOWED"
    CURRENT_STATE_UNKNOWN = "CURRENT_STATE_UNKNOWN"
    ACTOR_MISSING = "ACTOR_MISSING"
    ACTOR_INVALID = "ACTOR_INVALID"
    ACTOR_TYPE_NOT_PERMITTED = "ACTOR_TYPE_NOT_PERMITTED"
    ACTOR_NOT_AUTHORIZED = "ACTOR_NOT_AUTHORIZED"
    SEPARATION_OF_DUTIES = "SEPARATION_OF_DUTIES"
    QUARANTINE_ORIGIN_UNKNOWN = "QUARANTINE_ORIGIN_UNKNOWN"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    STALE_STATE = "STALE_STATE"
    STALE_VERSION = "STALE_VERSION"
    STATE_HISTORY_MISMATCH = "STATE_HISTORY_MISMATCH"
    REASON_MISSING = "REASON_MISSING"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    INCIDENT_REQUIRED = "INCIDENT_REQUIRED"
    VALIDATION_EVIDENCE_MISSING = "VALIDATION_EVIDENCE_MISSING"
    ASSESSMENT_VERSION_MISMATCH = "ASSESSMENT_VERSION_MISMATCH"
    ASSESSMENT_CHECKSUM_MISMATCH = "ASSESSMENT_CHECKSUM_MISMATCH"
    DIMENSION_FAILED = "DIMENSION_FAILED"
    DIMENSION_UNAVAILABLE = "DIMENSION_UNAVAILABLE"
    DIMENSION_NOT_APPLICABLE_FORBIDDEN = "DIMENSION_NOT_APPLICABLE_FORBIDDEN"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    INTEGRITY_UNVERIFIABLE = "INTEGRITY_UNVERIFIABLE"
    PROVENANCE_MISSING = "PROVENANCE_MISSING"
    SOURCE_INVALID = "SOURCE_INVALID"
    LINEAGE_TAINTED = "LINEAGE_TAINTED"
    LINEAGE_UNVERIFIED = "LINEAGE_UNVERIFIED"
    LINEAGE_SUPERSEDED = "LINEAGE_SUPERSEDED"
    LINEAGE_INCOMPLETE = "LINEAGE_INCOMPLETE"
    UNRESOLVED_HIGH_SIGNAL = "UNRESOLVED_HIGH_SIGNAL"
    SUCCESSOR_INVALID = "SUCCESSOR_INVALID"
    SUPERSESSION_EDGE_MISSING = "SUPERSESSION_EDGE_MISSING"
    RECOVERY_EVIDENCE_MISSING = "RECOVERY_EVIDENCE_MISSING"
    REPOSITORY_UNAVAILABLE = "REPOSITORY_UNAVAILABLE"
    DECISION_STORE_UNAVAILABLE = "DECISION_STORE_UNAVAILABLE"
    EVALUATION_ERROR = "EVALUATION_ERROR"


# Restriction rank, used only to resolve conflicts between the stored state and the
# decision history (most restrictive wins). SUPERSEDED is ranked above UNVERIFIED
# because it can never justify use as current memory.
_RESTRICTION_RANK: Dict[str, int] = {
    TrustState.TRUSTED.value: 0,
    TrustState.UNVERIFIED.value: 1,
    TrustState.SUPERSEDED.value: 2,
    TrustState.SUSPICIOUS.value: 3,
    TrustState.QUARANTINED.value: 4,
    TrustState.REJECTED.value: 5,
}
_KNOWN_STATES: FrozenSet[str] = frozenset(_RESTRICTION_RANK)


# =============================================================================
# 2. Transition matrix
# =============================================================================

@dataclass(frozen=True)
class TransitionRule:
    transition_id: str
    operation: TrustOperation
    from_state: TrustState
    to_state: TrustState
    actor_types: FrozenSet[ActorType]
    user_roles: Tuple[Role, ...]
    relaxes_restriction: bool
    requires_evidence_refs: bool = False
    requires_incident: bool = False


def _rule(tid, op, src, dst, actors, relaxes, refs=False, incident=False) -> TransitionRule:
    return TransitionRule(
        transition_id=tid,
        operation=op,
        from_state=src,
        to_state=dst,
        actor_types=frozenset(actors),
        user_roles=ANALYST_ROLES if ActorType.USER in actors else (),
        relaxes_restriction=relaxes,
        requires_evidence_refs=refs,
        requires_incident=incident,
    )


_U, _T, _S, _Q, _R, _X = (
    TrustState.UNVERIFIED, TrustState.TRUSTED, TrustState.SUSPICIOUS,
    TrustState.QUARANTINED, TrustState.REJECTED, TrustState.SUPERSEDED,
)
_USER = ActorType.USER
_DET, _INT, _UPD = ActorType.SYSTEM_DETECTOR, ActorType.SYSTEM_INTEGRITY, ActorType.SYSTEM_UPDATE
_OP = TrustOperation

_RULES: Tuple[TransitionRule, ...] = (
    _rule("T-02", _OP.VALIDATE, _U, _T, {_USER}, relaxes=True),
    _rule("T-03", _OP.FLAG_SUSPICIOUS, _U, _S, {_USER, _DET}, relaxes=False, refs=True),
    _rule("T-04", _OP.QUARANTINE, _U, _Q, {_USER, _INT}, relaxes=False, refs=True),
    _rule("T-05", _OP.REJECT, _U, _R, {_USER}, relaxes=False, refs=True, incident=True),
    _rule("T-06", _OP.FLAG_SUSPICIOUS, _T, _S, {_USER, _DET}, relaxes=False, refs=True),
    _rule("T-07", _OP.QUARANTINE, _T, _Q, {_USER, _INT}, relaxes=False, refs=True),
    _rule("T-08", _OP.INVALIDATE, _T, _U, {_USER, _UPD}, relaxes=False),
    _rule("T-09", _OP.SUPERSEDE, _T, _X, {_USER}, relaxes=False),
    _rule("T-10", _OP.QUARANTINE, _S, _Q, {_USER, _INT}, relaxes=False, refs=True),
    _rule("T-11", _OP.CLEAR_SUSPICION, _S, _U, {_USER}, relaxes=True, refs=True),
    _rule("T-12", _OP.REJECT, _S, _R, {_USER}, relaxes=False, refs=True, incident=True),
    _rule("T-13", _OP.REJECT, _Q, _R, {_USER}, relaxes=False, refs=True, incident=True),
    _rule("T-14", _OP.RELEASE_QUARANTINE, _Q, _U, {_USER}, relaxes=True, refs=True, incident=True),
    _rule("T-16a", _OP.QUARANTINE, _X, _Q, {_USER}, relaxes=False, refs=True, incident=True),
    _rule("T-16b", _OP.REJECT, _X, _R, {_USER}, relaxes=False, refs=True, incident=True),
    _rule("T-17a", _OP.RECOVERY_RESTORE, _Q, _U, {_USER}, relaxes=True),
    _rule("T-17b", _OP.RECOVERY_RESTORE, _S, _U, {_USER}, relaxes=True),
    _rule("T-17c", _OP.RECOVERY_RESTORE, _T, _U, {_USER}, relaxes=False),
    _rule("T-17d", _OP.RECOVERY_RESTORE, _X, _U, {_USER}, relaxes=True),
)

#: (operation, from_state) -> rule. Anything absent is denied. REJECTED has no exits.
TRANSITION_MATRIX: Mapping[Tuple[TrustOperation, TrustState], TransitionRule] = {
    (r.operation, r.from_state): r for r in _RULES
}

#: Each operation's fixed resulting state.
OPERATION_TARGET: Mapping[TrustOperation, TrustState] = {
    _OP.VALIDATE: _T,
    _OP.FLAG_SUSPICIOUS: _S,
    _OP.QUARANTINE: _Q,
    _OP.REJECT: _R,
    _OP.INVALIDATE: _U,
    _OP.SUPERSEDE: _X,
    _OP.CLEAR_SUSPICION: _U,
    _OP.RELEASE_QUARANTINE: _U,
    _OP.RECOVERY_RESTORE: _U,
}

#: Dimensions the evaluator verifies itself from authoritative state. Caller claims are cross-checked.
COMPUTED_DIMENSIONS: FrozenSet[TrustDimension] = frozenset(
    {TrustDimension.INTEGRITY, TrustDimension.LINEAGE, TrustDimension.SOURCE_IDENTITY}
)
#: Dimensions where an explicit, analyst-attested NOT_APPLICABLE is accepted in policy v1,
#: because no schema attribute exists yet (Day 1 D-08). Every other dimension must PASS.
NOT_APPLICABLE_PERMITTED: FrozenSet[TrustDimension] = frozenset(
    {TrustDimension.SENSITIVITY, TrustDimension.POLICY_SCOPE}
)


# =============================================================================
# 3. Request and evidence (strict; no tenant or actor fields accepted)
# =============================================================================

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class DimensionAssessment(_Strict):
    status: DimensionStatus
    evidence_ref: Optional[str] = Field(default=None, max_length=256)
    note: Optional[str] = Field(default=None, max_length=500)


class TrustSignal(_Strict):
    """Detector / model output. Evidence only: can block promotion, never allow it."""

    source: str = Field(min_length=1, max_length=128)
    model_version: Optional[str] = Field(default=None, max_length=64)
    label: str = Field(min_length=1, max_length=64)
    severity: SignalSeverity
    score: Optional[float] = None  # recorded, never used for the decision
    resolved: bool = False


class TrustValidationEvidence(_Strict):
    """Assessment submitted for VALIDATE, bound to one exact version and checksum."""

    assessed_version: int = Field(ge=1)
    assessed_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    dimensions: Dict[TrustDimension, DimensionAssessment]


class TrustEvidence(_Strict):
    evidence_refs: Tuple[str, ...] = Field(default=(), max_length=MAX_EVIDENCE_REFS)
    incident_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    validation: Optional[TrustValidationEvidence] = None
    successor_record_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    recovery_plan_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    checkpoint_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    signals: Tuple[TrustSignal, ...] = ()


class TrustTransitionRequest(_Strict):
    """A request to change one record's trust state.

    Deliberately has no ``tenant_id`` or actor fields: those come only from the
    server-side actor. ``extra="forbid"`` rejects attempts to supply them.
    """

    record_id: str = Field(min_length=1, max_length=128)
    operation: TrustOperation
    target_state: TrustState
    expected_state: TrustState
    expected_version: int = Field(ge=1)
    reason: str = Field(max_length=MAX_REASON_LENGTH)
    evidence: TrustEvidence = TrustEvidence()


# =============================================================================
# 4. Actors (server-side only)
# =============================================================================

@dataclass(frozen=True)
class UserActor:
    """A human operator. ``context`` must be M1's verified ``TenantContext``."""

    context: TenantContext


@dataclass(frozen=True)
class SystemActor:
    """An in-process security process bound to one tenant by server code.

    System actors can only perform restricting operations (see matrix), so a forged
    system actor can at worst restrict a record, never promote or release it.
    """

    tenant_id: str
    actor_type: ActorType
    process_ref: str


TrustActor = Union[UserActor, SystemActor]


# =============================================================================
# 5. Decision record and append-only store
# =============================================================================

@dataclass(frozen=True)
class TrustDecision:
    """Immutable, explainable record of one trust evaluation (applied or denied)."""

    decision_id: str
    allowed: bool
    applied: bool
    decision: str                       # "APPLIED" | "PERMITTED" | "DENIED"
    reason_codes: Tuple[str, ...]
    reason: str                         # operator-supplied justification (not logged)
    record_id: str
    tenant_id: Optional[str]
    operation: Optional[str]
    transition_id: Optional[str]
    current_state: Optional[str]        # effective state evaluated
    stored_state: Optional[str]         # state found on the record
    target_state: Optional[str]
    resulting_state: Optional[str]
    record_version: Optional[int]
    version_checksum: Optional[str]
    actor_type: Optional[str]
    actor_id: Optional[str]
    actor_role: Optional[str]
    incident_id: Optional[str]
    evidence_summary: Mapping[str, object]
    policy_version: str
    timestamp: datetime
    history_available: bool = False


@dataclass(frozen=True)
class ActionMemoryAssessment:
    """Action-time eligibility of one memory reference (consumed by the policy engine).

    Contains identifiers, states, version and checksum only — never memory content.
    """

    record_id: str
    found: bool
    eligible: bool
    reason_codes: Tuple[str, ...]
    stored_state: Optional[str] = None
    effective_state: Optional[str] = None
    version: Optional[int] = None
    checksum: Optional[str] = None
    agent_id: Optional[str] = None
    trust_decision_id: Optional[str] = None
    ancestors: Mapping[str, str] = field(default_factory=dict)


# Environments in which the in-memory trust store / memory repository may be used (M4-F6).
NON_DURABLE_ALLOWED_ENVIRONMENTS: FrozenSet[str] = frozenset({"development", "test"})


class TrustDecisionStore(Protocol):
    """Append-only, tenant-scoped decision history (durable implementation: M6)."""

    is_persistent: bool

    def append(self, decision: TrustDecision) -> None:
        ...

    def list_for_record(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        ...


async def _maybe_await(value: object) -> object:
    if inspect.isawaitable(value):
        return await value
    return value


class InMemoryTrustDecisionStore:
    """Development/test store. Append-only; refused in production by ``TrustEvaluator``."""

    is_persistent: bool = False

    def __init__(self) -> None:
        self._by_record: Dict[Tuple[str, str], List[TrustDecision]] = {}

    def append(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            raise ValueError("Trust decisions must be tenant-scoped.")
        self._by_record.setdefault((decision.tenant_id, decision.record_id), []).append(decision)

    def list_for_record(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        return tuple(self._by_record.get((tenant_id, record_id), ()))


# =============================================================================
# 6. Evaluator
# =============================================================================

class _Deny(Exception):
    """Internal control flow: carries deny reason codes."""

    def __init__(self, *codes: TrustReason, summary: Optional[Mapping[str, object]] = None):
        super().__init__(",".join(c.value for c in codes))
        self.codes = codes
        self.summary = dict(summary or {})


@dataclass
class _Ctx:
    """Mutable working state for one evaluation (never shared between calls)."""

    tenant_id: Optional[str] = None
    actor_type: Optional[str] = None
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    stored_state: Optional[str] = None
    effective_state: Optional[str] = None
    version: Optional[int] = None
    checksum: Optional[str] = None
    rule: Optional[TransitionRule] = None
    history_available: bool = False
    drift: bool = False
    summary: Dict[str, object] = field(default_factory=dict)


class TrustEvaluator:
    """Evaluates and applies memory trust transitions.

    ``evaluate`` is a side-effect-free dry run. ``apply`` evaluates, updates the
    record through M3's repository and appends the decision to the store.
    Neither method raises; use ``raise_for_decision`` to map denials to M1 errors.
    """

    def __init__(
        self,
        repository: MemoryRepository,
        store: TrustDecisionStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        app_env: Optional[str] = None,
    ) -> None:
        env = app_env
        if env is None:
            try:
                from backend.app.core.config import get_settings

                env = get_settings().APP_ENV
            except Exception:  # noqa: BLE001 — unknown environment is treated as production
                env = "production"
        # M4-F6: only an explicit non-production environment may use non-durable stores.
        # Anything else (production, staging, an unknown or misspelled value) requires them.
        normalized_env = env.strip().lower() if isinstance(env, str) else ""
        if normalized_env not in NON_DURABLE_ALLOWED_ENVIRONMENTS:
            if not getattr(store, "is_persistent", False):
                raise RuntimeError("A persistent trust decision store (M6) is required in production.")
            if getattr(repository, "is_in_memory", True) or not getattr(repository, "is_persistent", False):
                raise RuntimeError("A persistent memory repository (M6) is required in production.")
        self._repo = repository
        self._store = store
        self._clock = clock
        # Per-(tenant, record) locks: the re-read + write in _apply is atomic within this process
        # (finding M4-F5). Cross-process atomicity needs a repository compare-and-set (M3/M6 contract).
        self._locks: Dict[Tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._async_locks: Dict[Tuple[str, str], asyncio.Lock] = {}

    async def _astore_append(self, decision: TrustDecision) -> None:
        if hasattr(self._store, "aappend"):
            await self._store.aappend(decision)
        else:
            self._store.append(decision)

    async def _astore_list(self, tenant_id: str, record_id: str) -> Sequence[TrustDecision]:
        if hasattr(self._store, "alist_for_record"):
            return await self._store.alist_for_record(tenant_id, record_id)
        return self._store.list_for_record(tenant_id, record_id)

    def _async_record_lock(self, tenant_id: str, record_id: str) -> asyncio.Lock:
        with self._locks_guard:
            return self._async_locks.setdefault((tenant_id, record_id), asyncio.Lock())

    # -- public API -----------------------------------------------------------

    @property
    def repository(self) -> MemoryRepository:
        """The memory repository this evaluator reads and writes (read-only property)."""
        return self._repo

    def evaluate(self, request: object, actor: Optional[TrustActor]) -> TrustDecision:
        return self._run(request, actor, apply=False)

    def apply(self, request: object, actor: Optional[TrustActor]) -> TrustDecision:
        return self._run(request, actor, apply=True)

    def history(self, actor: TrustActor, record_id: str) -> Tuple[TrustDecision, ...]:
        """Tenant-scoped decision history for a record (forensic inspection)."""
        tenant_id = self._actor_tenant(actor)
        if tenant_id is None:
            raise ForbiddenError("Trust history requires a verified tenant context.")
        return tuple(self._store.list_for_record(tenant_id, record_id))

    def effective_state(self, tenant_id: str, record_id: str) -> Optional[str]:
        """Most restrictive of stored state and decision history; None if unknown.

        Raises on repository/store failure so callers fail closed.
        """
        record = self._repo.get_record(record_id, tenant_id)
        if record is None or not record or getattr(record, "tenant_id", None) != tenant_id:
            return None
        stored = _state_value(record.trust_state)
        if stored is None:
            return None
        effective, _, _ = self._reconcile(stored, record.current_version, tenant_id, record_id)
        return effective

    def assess_for_action(
        self,
        tenant_id: str,
        record_id: str,
        pinned_version: Optional[int] = None,
    ) -> "ActionMemoryAssessment":
        """Decide whether a memory reference may justify a protected action *now*.

        Used by the Day 4 policy engine (``backend.app.security.policy``) so that the
        trust evaluator stays the single authority for memory trust. A reference is
        eligible only if ALL hold (Day 1 design §7.3, POL-MREF/MTS/MINT/MFRS/MLIN):

        * the record exists in ``tenant_id``;
        * the pinned version (if given) is the current version;
        * the effective state (stored state reconciled with decision history) is TRUSTED;
        * every stored version's checksum recomputes;
        * an applied M4 TRUSTED decision exists for this exact version and checksum
          (records promoted outside M4, e.g. via M3's unguarded helper, are NOT eligible);
        * every ancestor is TRUSTED and lineage traversal completes within budget.

        Raises on repository/store failure so callers fail closed.
        """
        record = self._repo.get_record(record_id, tenant_id)
        if record is None or not record or getattr(record, "tenant_id", None) != tenant_id:
            return ActionMemoryAssessment(record_id=record_id, found=False, eligible=False,
                                          reason_codes=("MEMORY_REFERENCE_NOT_FOUND",))
        stored = _state_value(getattr(record, "trust_state", None))
        version = getattr(record, "current_version", None)
        if stored is None or type(version) is not int or version < 1:
            return ActionMemoryAssessment(record_id=record_id, found=True, eligible=False,
                                          reason_codes=("MEMORY_STATE_UNKNOWN",))

        codes: List[str] = []
        effective, drift, _ = self._reconcile(stored, version, tenant_id, record_id)
        if drift:
            codes.append("MEMORY_STATE_HISTORY_MISMATCH")
        if pinned_version is not None and pinned_version != version:
            codes.append("MEMORY_VERSION_STALE")
        if effective != TrustState.TRUSTED.value:
            codes.append(f"MEMORY_{effective}")

        # Integrity of every stored version; current version must exist exactly once.
        versions = self._repo.get_versions(record_id, tenant_id)
        current = [v for v in versions if getattr(v, "version", None) == version]
        checksum: Optional[str] = None
        if len(current) != 1:
            codes.append("MEMORY_INTEGRITY_UNVERIFIABLE")
        else:
            checksum = current[0].checksum
            if any(sha256_hex(v.content) != v.checksum for v in versions):
                codes.append("MEMORY_INTEGRITY_VIOLATION")

        # Version-bound trust evidence from M4's own decision history.
        trusted = [
            d for d in self._store.list_for_record(tenant_id, record_id)
            if d.applied and d.resulting_state == TrustState.TRUSTED.value
        ]
        evidence = trusted[-1] if trusted else None
        if (
            evidence is None
            or evidence.record_version != version
            or checksum is None
            or evidence.version_checksum != checksum
        ):
            codes.append("MEMORY_TRUST_EVIDENCE_MISSING")

        lineage_ctx = _Ctx(tenant_id=tenant_id)
        lineage_codes, lineage_summary = self._verify_lineage(record_id, lineage_ctx)
        codes.extend(f"MEMORY_{c.value}" for c in lineage_codes)

        return ActionMemoryAssessment(
            record_id=record_id,
            found=True,
            eligible=not codes,
            reason_codes=tuple(_dedupe_str(codes)),
            stored_state=stored,
            effective_state=effective,
            version=version,
            checksum=checksum,
            agent_id=getattr(record, "agent_id", None),
            trust_decision_id=(evidence.decision_id if evidence else None),
            ancestors=dict(lineage_summary.get("ancestors", {})),
        )

    # -- core -----------------------------------------------------------------

    def _run(self, request: object, actor: Optional[TrustActor], *, apply: bool) -> TrustDecision:
        ctx = _Ctx()
        req: Optional[TrustTransitionRequest] = None
        try:
            req = self._coerce_request(request)
            self._resolve_actor(actor, ctx)
            self._check_target(req)  # operation/target consistency before any I/O
            record = self._load_record(req, ctx)
            self._check_state_and_history(req, record, ctx)
            rule = self._rule_for_state(req, ctx)
            ctx.rule = rule
            self._authorize_actor(rule, actor, ctx)
            self._check_reason_and_evidence(req, rule)
            self._check_operation_specific(req, rule, record, ctx)
            if not apply:
                decision = self._decision(req, ctx, allowed=True, applied=False,
                                          codes=(TrustReason.TRANSITION_PERMITTED,))
                self._log(decision)
                return decision
            decision = self._apply(req, record, ctx)
            if decision.applied:
                self._log(decision)
                return decision
        except _Deny as deny:
            ctx.summary.update(deny.summary)
            decision = self._decision(req, ctx, allowed=False, applied=False, codes=deny.codes,
                                      raw_record_id=_raw_record_id(request))
        except Exception:  # noqa: BLE001 — fail closed
            logger.exception("Trust evaluation error; transition denied (fail closed).")
            decision = self._decision(req, ctx, allowed=False, applied=False,
                                      codes=(TrustReason.EVALUATION_ERROR,),
                                      raw_record_id=_raw_record_id(request))
        if apply:
            self._record_denial(decision)
        self._log(decision)
        return decision

    def _coerce_request(self, request: object) -> TrustTransitionRequest:
        if isinstance(request, TrustTransitionRequest):
            return request
        if isinstance(request, Mapping):
            try:
                return TrustTransitionRequest.model_validate(dict(request))
            except PydanticValidationError as exc:
                raise _Deny(TrustReason.REQUEST_INVALID,
                            summary={"invalid_fields": sorted({".".join(map(str, e["loc"])) for e in exc.errors()})})
        raise _Deny(TrustReason.REQUEST_INVALID)

    def _resolve_actor(self, actor: Optional[TrustActor], ctx: _Ctx) -> None:
        if actor is None:
            raise _Deny(TrustReason.ACTOR_MISSING)
        if isinstance(actor, UserActor):
            context = actor.context
            if not isinstance(context, TenantContext):
                raise _Deny(TrustReason.ACTOR_INVALID)
            if context.is_active is not True or not _nonblank(context.tenant_id) or not _nonblank(context.user_id):
                raise _Deny(TrustReason.ACTOR_INVALID)
            ctx.tenant_id = context.tenant_id
            ctx.actor_type = ActorType.USER.value
            ctx.actor_id = context.user_id
            ctx.actor_role = context.role if type(context.role) is str else None
            return
        if isinstance(actor, SystemActor):
            if (
                type(actor.actor_type) is not ActorType
                or actor.actor_type is ActorType.USER
                or not _nonblank(actor.tenant_id)
                or not _nonblank(actor.process_ref)
            ):
                raise _Deny(TrustReason.ACTOR_INVALID)
            ctx.tenant_id = actor.tenant_id
            ctx.actor_type = actor.actor_type.value
            ctx.actor_id = actor.process_ref
            return
        raise _Deny(TrustReason.ACTOR_INVALID)

    def _check_target(self, req: TrustTransitionRequest) -> None:
        expected_target = OPERATION_TARGET.get(req.operation)
        if expected_target is None or req.target_state is not expected_target:
            raise _Deny(TrustReason.TARGET_STATE_MISMATCH)

    def _load_record(self, req: TrustTransitionRequest, ctx: _Ctx):
        try:
            record = self._repo.get_record(req.record_id, ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        # Cross-tenant and nonexistent records are indistinguishable to the caller.
        if record is None or not record or getattr(record, "tenant_id", None) != ctx.tenant_id:
            raise _Deny(TrustReason.RECORD_NOT_FOUND)
        return record

    def _check_state_and_history(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> None:
        stored = _state_value(getattr(record, "trust_state", None))
        if stored is None:
            raise _Deny(TrustReason.CURRENT_STATE_UNKNOWN)
        version = getattr(record, "current_version", None)
        if type(version) is not int or version < 1:
            raise _Deny(TrustReason.CURRENT_STATE_UNKNOWN)
        ctx.stored_state = stored
        ctx.version = version

        try:
            effective, drift, history_available = self._reconcile(stored, version, ctx.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.DECISION_STORE_UNAVAILABLE) from exc
        ctx.effective_state = effective
        ctx.history_available = history_available
        if drift:
            ctx.summary["state_history_mismatch"] = {"stored": stored, "history": effective}

        if req.expected_state.value != effective:
            codes = [TrustReason.STALE_STATE]
            if drift:
                codes.append(TrustReason.STATE_HISTORY_MISMATCH)
            raise _Deny(*codes)
        if req.expected_version != version:
            raise _Deny(TrustReason.STALE_VERSION)
        ctx.drift = drift

    def _rule_for_state(self, req: TrustTransitionRequest, ctx: _Ctx) -> TransitionRule:
        rule = TRANSITION_MATRIX.get((req.operation, TrustState(ctx.effective_state)))
        if rule is None:
            raise _Deny(TrustReason.TRANSITION_NOT_ALLOWED)
        if rule.relaxes_restriction and ctx.drift:
            raise _Deny(TrustReason.STATE_HISTORY_MISMATCH)
        return rule

    def _authorize_actor(self, rule: TransitionRule, actor: TrustActor, ctx: _Ctx) -> None:
        actor_type = ActorType(ctx.actor_type)
        if actor_type not in rule.actor_types:
            raise _Deny(TrustReason.ACTOR_TYPE_NOT_PERMITTED)
        if actor_type is ActorType.USER:
            rbac = evaluate_role_access(actor.context, rule.user_roles)  # type: ignore[union-attr]
            if not rbac.allowed:
                raise _Deny(TrustReason.ACTOR_NOT_AUTHORIZED, summary={"rbac_reason": rbac.reason.value})
            ctx.actor_role = rbac.role

    def _check_reason_and_evidence(self, req: TrustTransitionRequest, rule: TransitionRule) -> None:
        if not req.reason or not req.reason.strip():
            raise _Deny(TrustReason.REASON_MISSING)
        refs = [r for r in req.evidence.evidence_refs if isinstance(r, str) and r.strip()]
        if rule.requires_evidence_refs and not refs:
            raise _Deny(TrustReason.EVIDENCE_MISSING)
        if rule.requires_incident and not (req.evidence.incident_id and req.evidence.incident_id.strip()):
            raise _Deny(TrustReason.INCIDENT_REQUIRED)

    def _check_operation_specific(self, req: TrustTransitionRequest, rule: TransitionRule, record, ctx: _Ctx) -> None:
        op = rule.operation
        if op is TrustOperation.VALIDATE:
            self._check_validation(req, record, ctx)
        elif op is TrustOperation.SUPERSEDE:
            self._check_supersession(req, ctx)
        elif op is TrustOperation.RELEASE_QUARANTINE:
            self._check_release_separation(req, ctx)
        elif op is TrustOperation.RECOVERY_RESTORE:
            if not (req.evidence.recovery_plan_id and req.evidence.checkpoint_id):
                raise _Deny(TrustReason.RECOVERY_EVIDENCE_MISSING)

    # -- VALIDATE (T-02) ------------------------------------------------------

    def _check_validation(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> None:
        validation = req.evidence.validation
        if validation is None:
            raise _Deny(TrustReason.VALIDATION_EVIDENCE_MISSING)

        codes: List[TrustReason] = []
        dims: Dict[str, str] = {}

        # Bind assessment to the exact current version.
        if validation.assessed_version != ctx.version:
            raise _Deny(TrustReason.ASSESSMENT_VERSION_MISMATCH)

        # Caller-attested dimensions: every dimension must be present and PASS
        # (NOT_APPLICABLE only where policy v1 permits it).
        for dim in TrustDimension:
            assessment = validation.dimensions.get(dim)
            if assessment is None or assessment.status is DimensionStatus.UNAVAILABLE:
                codes.append(TrustReason.DIMENSION_UNAVAILABLE)
                dims[dim.value] = "UNAVAILABLE"
                continue
            if assessment.status is DimensionStatus.FAIL:
                codes.append(TrustReason.DIMENSION_FAILED)
                dims[dim.value] = "FAIL"
                continue
            if assessment.status is DimensionStatus.NOT_APPLICABLE:
                if dim not in NOT_APPLICABLE_PERMITTED or not (assessment.note and assessment.note.strip()):
                    codes.append(TrustReason.DIMENSION_NOT_APPLICABLE_FORBIDDEN)
                    dims[dim.value] = "NOT_APPLICABLE_FORBIDDEN"
                    continue
                dims[dim.value] = "NOT_APPLICABLE"
                continue
            dims[dim.value] = "PASS(attested)"

        # Computed dimensions override attestations (never trust the caller's word).
        integrity_codes = self._verify_integrity(req, validation, ctx)
        dims[TrustDimension.INTEGRITY.value] = "PASS(verified)" if not integrity_codes else "FAIL(verified)"
        codes.extend(integrity_codes)

        source_codes = self._verify_source(record, ctx)
        dims[TrustDimension.SOURCE_IDENTITY.value] = "PASS(verified)" if not source_codes else "FAIL(verified)"
        codes.extend(source_codes)

        lineage_codes, lineage_summary = self._verify_lineage(req.record_id, ctx)
        dims[TrustDimension.LINEAGE.value] = "PASS(verified)" if not lineage_codes else "FAIL(verified)"
        codes.extend(lineage_codes)

        if not getattr(record, "source_id", None) and not lineage_summary.get("ancestors"):
            codes.append(TrustReason.PROVENANCE_MISSING)

        if any(s.severity is SignalSeverity.HIGH and not s.resolved for s in req.evidence.signals):
            codes.append(TrustReason.UNRESOLVED_HIGH_SIGNAL)

        ctx.summary["dimensions"] = dims
        ctx.summary["lineage"] = lineage_summary
        if req.evidence.signals:
            ctx.summary["signals"] = [
                {"source": s.source, "label": s.label, "severity": s.severity.value,
                 "model_version": s.model_version, "resolved": s.resolved}
                for s in req.evidence.signals
            ]
        if codes:
            raise _Deny(*_dedupe(codes))

    def _verify_integrity(self, req, validation: TrustValidationEvidence, ctx: _Ctx) -> List[TrustReason]:
        try:
            versions = self._repo.get_versions(req.record_id, ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        current = [v for v in versions if getattr(v, "version", None) == ctx.version]
        if len(current) != 1:
            return [TrustReason.INTEGRITY_UNVERIFIABLE]
        codes: List[TrustReason] = []
        for ver in versions:
            try:
                if sha256_hex(ver.content) != ver.checksum:
                    codes.append(TrustReason.INTEGRITY_FAILED)
                    break
            except Exception:  # noqa: BLE001
                return [TrustReason.INTEGRITY_UNVERIFIABLE]
        ctx.checksum = current[0].checksum
        if validation.assessed_checksum != current[0].checksum:
            codes.append(TrustReason.ASSESSMENT_CHECKSUM_MISMATCH)
        return codes

    def _verify_source(self, record, ctx: _Ctx) -> List[TrustReason]:
        source_id = getattr(record, "source_id", None)
        if not source_id:
            return []  # provenance via lineage is checked separately
        try:
            source = self._repo.get_source(source_id, ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        if source is None or getattr(source, "tenant_id", None) != ctx.tenant_id or getattr(source, "status", None) != "ACTIVE":
            return [TrustReason.SOURCE_INVALID]
        return []

    def _verify_lineage(self, record_id: str, ctx: _Ctx) -> Tuple[List[TrustReason], Dict[str, object]]:
        """Bounded upstream traversal with one shared visited set and global budgets."""
        lineage_relations = {ProvenanceRelationType.DERIVED_FROM.value, ProvenanceRelationType.TRANSFORMED_INTO.value}
        visited = {record_id}
        frontier: List[Tuple[str, int]] = [(record_id, 0)]
        ancestors: Dict[str, str] = {}
        edges_seen = 0
        codes: List[TrustReason] = []
        try:
            while frontier:
                current, depth = frontier.pop(0)
                edges = self._repo.get_edges_for_record(current, ctx.tenant_id)
                for edge in edges:
                    relation = _state_like(getattr(edge, "relation_type", None))
                    if getattr(edge, "to_record_id", None) != current or relation not in lineage_relations:
                        continue
                    edges_seen += 1
                    if edges_seen > MAX_LINEAGE_EDGES:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    if getattr(edge, "tenant_id", None) != ctx.tenant_id:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_id = edge.from_record_id
                    if parent_id in visited:
                        continue  # shared descendant or cycle; already evaluated or queued
                    if depth + 1 > MAX_LINEAGE_DEPTH or len(visited) >= MAX_LINEAGE_NODES:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    visited.add(parent_id)
                    parent = self._repo.get_record(parent_id, ctx.tenant_id)
                    if parent is None or not parent or getattr(parent, "tenant_id", None) != ctx.tenant_id:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_stored = _state_value(parent.trust_state)
                    if parent_stored is None:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_effective, _, _ = self._reconcile(parent_stored, parent.current_version, ctx.tenant_id, parent_id)
                    ancestors[parent_id] = parent_effective
                    if parent_effective in (TrustState.SUSPICIOUS.value, TrustState.QUARANTINED.value, TrustState.REJECTED.value):
                        codes.append(TrustReason.LINEAGE_TAINTED)
                    elif parent_effective == TrustState.UNVERIFIED.value:
                        codes.append(TrustReason.LINEAGE_UNVERIFIED)
                    elif parent_effective == TrustState.SUPERSEDED.value:
                        codes.append(TrustReason.LINEAGE_SUPERSEDED)
                    frontier.append((parent_id, depth + 1))
        except _Deny:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        return _dedupe(codes), {"ancestors": ancestors, "complete": True}

    # -- SUPERSEDE / RELEASE --------------------------------------------------

    def _check_supersession(self, req: TrustTransitionRequest, ctx: _Ctx) -> None:
        successor_id = req.evidence.successor_record_id
        if not successor_id or successor_id == req.record_id:
            raise _Deny(TrustReason.SUCCESSOR_INVALID)
        try:
            successor = self._repo.get_record(successor_id, ctx.tenant_id)
            if successor is None or not successor or getattr(successor, "tenant_id", None) != ctx.tenant_id:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            succ_state = _state_value(successor.trust_state)
            if succ_state is None:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            succ_effective, _, _ = self._reconcile(succ_state, successor.current_version, ctx.tenant_id, successor_id)
            if succ_effective != TrustState.TRUSTED.value:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            edges = self._repo.get_edges_for_record(req.record_id, ctx.tenant_id)
        except _Deny:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        has_edge = any(
            getattr(e, "from_record_id", None) == successor_id
            and getattr(e, "to_record_id", None) == req.record_id
            and _state_like(getattr(e, "relation_type", None)) == ProvenanceRelationType.SUPERSEDES.value
            and getattr(e, "tenant_id", None) == ctx.tenant_id
            for e in edges
        )
        if not has_edge:
            raise _Deny(TrustReason.SUPERSESSION_EDGE_MISSING)
        ctx.summary["successor_record_id"] = successor_id

    def _check_release_separation(self, req: TrustTransitionRequest, ctx: _Ctx) -> None:
        try:
            history = self._store.list_for_record(ctx.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.DECISION_STORE_UNAVAILABLE) from exc
        quarantines = [d for d in history if d.applied and d.resulting_state == TrustState.QUARANTINED.value]
        is_admin = ctx.actor_role == Role.TENANT_ADMIN.value
        if not quarantines:
            if not is_admin:
                raise _Deny(TrustReason.QUARANTINE_ORIGIN_UNKNOWN)
            return
        if quarantines[-1].actor_id == ctx.actor_id and not is_admin:
            raise _Deny(TrustReason.SEPARATION_OF_DUTIES)

    # -- history reconciliation ----------------------------------------------

    def _reconcile(self, stored: str, version: int, tenant_id: str, record_id: str) -> Tuple[str, bool, bool]:
        """Return (effective_state, drift_detected, history_available).

        The only out-of-band change accepted as legitimate is GAP-002 invalidation:
        history says TRUSTED, record says UNVERIFIED at a newer version.
        """
        applied = [d for d in self._store.list_for_record(tenant_id, record_id) if d.applied]
        if not applied:
            return stored, False, False
        last = applied[-1]
        history_state = last.resulting_state
        if history_state not in _KNOWN_STATES:
            return stored, True, True
        if history_state == stored:
            return stored, False, True
        if (
            history_state == TrustState.TRUSTED.value
            and stored == TrustState.UNVERIFIED.value
            and last.record_version is not None
            and version > last.record_version
        ):
            return stored, False, True
        effective = history_state if _RESTRICTION_RANK[history_state] > _RESTRICTION_RANK[stored] else stored
        return effective, True, True

    # -- apply ----------------------------------------------------------------

    def _record_lock(self, tenant_id: str, record_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault((tenant_id, record_id), threading.Lock())

    def _apply(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> TrustDecision:
        with self._record_lock(ctx.tenant_id or "", req.record_id):
            return self._apply_locked(req, record, ctx)

    def _apply_locked(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> TrustDecision:
        rule = ctx.rule
        assert rule is not None
        now = self._clock()
        # M4-F5: the decision was evaluated against ``record``; re-read immediately before the
        # write and refuse if the state or version moved meanwhile (a concurrent quarantine, a
        # new version, another transition). Writing the stale copy would silently undo them.
        try:
            fresh = self._repo.get_record(req.record_id, ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Trust transition not applied: repository re-read failed (%s).", type(exc).__name__)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.REPOSITORY_UNAVAILABLE,))
        if fresh is None or getattr(fresh, "tenant_id", None) != ctx.tenant_id:
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.RECORD_NOT_FOUND,))
        if _state_value(fresh.trust_state) != _state_value(record.trust_state):
            logger.warning("Trust transition refused: record %s state changed during evaluation.", req.record_id)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.STALE_STATE,))
        if fresh.current_version != record.current_version:
            logger.warning("Trust transition refused: record %s version changed during evaluation.", req.record_id)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.STALE_VERSION,))
        previous = fresh
        try:
            updated = fresh.model_copy(update={"trust_state": rule.to_state.value, "updated_at": now})
            self._repo.update_record(updated)
        except Exception as exc:  # noqa: BLE001
            raise_codes = (TrustReason.REPOSITORY_UNAVAILABLE,)
            logger.error("Trust transition not applied: repository update failed (%s).", type(exc).__name__)
            return self._decision(req, ctx, allowed=False, applied=False, codes=raise_codes)

        decision = self._decision(req, ctx, allowed=True, applied=True, codes=(TrustReason.TRANSITION_APPLIED,))
        try:
            self._store.append(decision)
        except Exception as exc:  # noqa: BLE001
            # Evidence could not be recorded: undo the state change (fail closed).
            logger.error("Trust decision store append failed (%s); reverting transition.", type(exc).__name__)
            try:
                current = self._repo.get_record(req.record_id, ctx.tenant_id)
                if current is None or _state_value(current.trust_state) != rule.to_state.value                         or current.current_version != previous.current_version:
                    # Someone else wrote meanwhile: never overwrite their change with our snapshot.
                    raise RuntimeError("record changed after the transition; revert skipped")
                self._repo.update_record(previous)
            except Exception:  # noqa: BLE001
                logger.critical(
                    "Trust transition revert FAILED for record %s; manual reconciliation required.", req.record_id
                )
            return self._decision(req, ctx, allowed=False, applied=False,
                                  codes=(TrustReason.DECISION_STORE_UNAVAILABLE,))
        return decision

    def _record_denial(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            return  # unscoped denials (no verified actor) are logged only
        try:
            self._store.append(decision)
        except Exception as exc:  # noqa: BLE001 — denial stands regardless
            logger.error("Could not persist denied trust decision (%s).", type(exc).__name__)

    # -- async durable API ----------------------------------------------------

    async def ahistory(self, actor: TrustActor, record_id: str) -> Tuple[TrustDecision, ...]:
        """Async tenant-scoped decision history for a record."""
        tenant_id = self._actor_tenant(actor)
        if tenant_id is None:
            raise ForbiddenError("Trust history requires a verified tenant context.")
        return tuple(await self._astore_list(tenant_id, record_id))

    async def aeffective_state(self, tenant_id: str, record_id: str) -> Optional[str]:
        """Async most restrictive of stored state and durable decision history."""
        record = await _maybe_await(self._repo.get_record(record_id, tenant_id))
        if record is None or not record or getattr(record, "tenant_id", None) != tenant_id:
            return None
        stored = _state_value(record.trust_state)
        if stored is None:
            return None
        effective, _, _ = await self._areconcile(stored, record.current_version, tenant_id, record_id)
        return effective

    async def aassess_for_action(
        self,
        tenant_id: str,
        record_id: str,
        pinned_version: Optional[int] = None,
    ) -> "ActionMemoryAssessment":
        """Async version of ``assess_for_action`` using durable decision history."""
        record = await _maybe_await(self._repo.get_record(record_id, tenant_id))
        if record is None or not record or getattr(record, "tenant_id", None) != tenant_id:
            return ActionMemoryAssessment(
                record_id=record_id, found=False, eligible=False,
                reason_codes=("MEMORY_REFERENCE_NOT_FOUND",),
            )
        stored = _state_value(getattr(record, "trust_state", None))
        version = getattr(record, "current_version", None)
        if stored is None or type(version) is not int or version < 1:
            return ActionMemoryAssessment(
                record_id=record_id, found=True, eligible=False,
                reason_codes=("MEMORY_STATE_UNKNOWN",),
            )

        codes: List[str] = []
        effective, drift, _ = await self._areconcile(stored, version, tenant_id, record_id)
        if drift:
            codes.append("MEMORY_STATE_HISTORY_MISMATCH")
        if pinned_version is not None and pinned_version != version:
            codes.append("MEMORY_VERSION_STALE")
        if effective != TrustState.TRUSTED.value:
            codes.append(f"MEMORY_{effective}")

        versions = await _maybe_await(self._repo.get_versions(record_id, tenant_id))
        current = [v for v in versions if getattr(v, "version", None) == version]
        checksum: Optional[str] = None
        if len(current) != 1:
            codes.append("MEMORY_INTEGRITY_UNVERIFIABLE")
        else:
            checksum = current[0].checksum
            if any(sha256_hex(v.content) != v.checksum for v in versions):
                codes.append("MEMORY_INTEGRITY_VIOLATION")

        history = await self._astore_list(tenant_id, record_id)
        trusted = [
            d for d in history
            if d.applied and d.resulting_state == TrustState.TRUSTED.value
        ]
        evidence = trusted[-1] if trusted else None
        if (
            evidence is None
            or evidence.record_version != version
            or checksum is None
            or evidence.version_checksum != checksum
        ):
            codes.append("MEMORY_TRUST_EVIDENCE_MISSING")

        lineage_ctx = _Ctx(tenant_id=tenant_id)
        lineage_codes, lineage_summary = await self._averify_lineage(record_id, lineage_ctx)
        codes.extend(f"MEMORY_{c.value}" for c in lineage_codes)

        return ActionMemoryAssessment(
            record_id=record_id,
            found=True,
            eligible=not codes,
            reason_codes=tuple(_dedupe_str(codes)),
            stored_state=stored,
            effective_state=effective,
            version=version,
            checksum=checksum,
            agent_id=getattr(record, "agent_id", None),
            trust_decision_id=(evidence.decision_id if evidence else None),
            ancestors=dict(lineage_summary.get("ancestors", {})),
        )

    async def aevaluate(self, request: object, actor: Optional[TrustActor]) -> TrustDecision:
        return await self._arun(request, actor, apply=False)

    async def aapply(self, request: object, actor: Optional[TrustActor]) -> TrustDecision:
        return await self._arun(request, actor, apply=True)

    async def _arun(self, request: object, actor: Optional[TrustActor], *, apply: bool) -> TrustDecision:
        ctx = _Ctx()
        req: Optional[TrustTransitionRequest] = None
        try:
            req = self._coerce_request(request)
            self._resolve_actor(actor, ctx)
            self._check_target(req)
            record = await self._aload_record(req, ctx)
            await self._acheck_state_and_history(req, record, ctx)
            rule = self._rule_for_state(req, ctx)
            ctx.rule = rule
            self._authorize_actor(rule, actor, ctx)
            self._check_reason_and_evidence(req, rule)
            await self._acheck_operation_specific(req, rule, record, ctx)
            if not apply:
                decision = self._decision(
                    req, ctx, allowed=True, applied=False,
                    codes=(TrustReason.TRANSITION_PERMITTED,),
                )
                self._log(decision)
                return decision
            decision = await self._aapply(req, record, ctx)
            if decision.applied:
                self._log(decision)
                return decision
        except _Deny as deny:
            ctx.summary.update(deny.summary)
            decision = self._decision(
                req, ctx, allowed=False, applied=False, codes=deny.codes,
                raw_record_id=_raw_record_id(request),
            )
        except Exception:  # noqa: BLE001 — fail closed
            logger.exception("Trust evaluation error; transition denied (fail closed).")
            decision = self._decision(
                req, ctx, allowed=False, applied=False,
                codes=(TrustReason.EVALUATION_ERROR,),
                raw_record_id=_raw_record_id(request),
            )
        if apply:
            await self._arecord_denial(decision)
        self._log(decision)
        return decision

    async def _aload_record(self, req: TrustTransitionRequest, ctx: _Ctx):
        try:
            record = await _maybe_await(self._repo.get_record(req.record_id, ctx.tenant_id))
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        if record is None or not record or getattr(record, "tenant_id", None) != ctx.tenant_id:
            raise _Deny(TrustReason.RECORD_NOT_FOUND)
        return record

    async def _areconcile(self, stored: str, version: int, tenant_id: str, record_id: str) -> Tuple[str, bool, bool]:
        applied = [d for d in await self._astore_list(tenant_id, record_id) if d.applied]
        if not applied:
            return stored, False, False
        last = applied[-1]
        history_state = last.resulting_state
        if history_state not in _KNOWN_STATES:
            return stored, True, True
        if history_state == stored:
            return stored, False, True
        if (
            history_state == TrustState.TRUSTED.value
            and stored == TrustState.UNVERIFIED.value
            and last.record_version is not None
            and version > last.record_version
        ):
            return stored, False, True
        effective = history_state if _RESTRICTION_RANK[history_state] > _RESTRICTION_RANK[stored] else stored
        return effective, True, True

    async def _acheck_state_and_history(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> None:
        stored = _state_value(getattr(record, "trust_state", None))
        if stored is None:
            raise _Deny(TrustReason.CURRENT_STATE_UNKNOWN)
        version = getattr(record, "current_version", None)
        if type(version) is not int or version < 1:
            raise _Deny(TrustReason.CURRENT_STATE_UNKNOWN)
        ctx.stored_state = stored
        ctx.version = version

        try:
            effective, drift, history_available = await self._areconcile(stored, version, ctx.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.DECISION_STORE_UNAVAILABLE) from exc
        ctx.effective_state = effective
        ctx.history_available = history_available
        if drift:
            ctx.summary["state_history_mismatch"] = {"stored": stored, "history": effective}

        if req.expected_state.value != effective:
            codes = [TrustReason.STALE_STATE]
            if drift:
                codes.append(TrustReason.STATE_HISTORY_MISMATCH)
            raise _Deny(*codes)
        if req.expected_version != version:
            raise _Deny(TrustReason.STALE_VERSION)
        ctx.drift = drift

    async def _acheck_operation_specific(self, req: TrustTransitionRequest, rule: TransitionRule, record, ctx: _Ctx) -> None:
        op = rule.operation
        if op is TrustOperation.VALIDATE:
            await self._acheck_validation(req, record, ctx)
        elif op is TrustOperation.SUPERSEDE:
            await self._acheck_supersession(req, ctx)
        elif op is TrustOperation.RELEASE_QUARANTINE:
            await self._acheck_release_separation(req, ctx)
        elif op is TrustOperation.RECOVERY_RESTORE:
            if not (req.evidence.recovery_plan_id and req.evidence.checkpoint_id):
                raise _Deny(TrustReason.RECOVERY_EVIDENCE_MISSING)

    async def _acheck_validation(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> None:
        validation = req.evidence.validation
        if validation is None:
            raise _Deny(TrustReason.VALIDATION_EVIDENCE_MISSING)

        codes: List[TrustReason] = []
        dims: Dict[str, str] = {}

        if validation.assessed_version != ctx.version:
            raise _Deny(TrustReason.ASSESSMENT_VERSION_MISMATCH)

        for dim in TrustDimension:
            assessment = validation.dimensions.get(dim)
            if assessment is None or assessment.status is DimensionStatus.UNAVAILABLE:
                codes.append(TrustReason.DIMENSION_UNAVAILABLE)
                dims[dim.value] = "UNAVAILABLE"
                continue
            if assessment.status is DimensionStatus.FAIL:
                codes.append(TrustReason.DIMENSION_FAILED)
                dims[dim.value] = "FAIL"
                continue
            if assessment.status is DimensionStatus.NOT_APPLICABLE:
                if dim not in NOT_APPLICABLE_PERMITTED or not (assessment.note and assessment.note.strip()):
                    codes.append(TrustReason.DIMENSION_NOT_APPLICABLE_FORBIDDEN)
                    dims[dim.value] = "NOT_APPLICABLE_FORBIDDEN"
                    continue
                dims[dim.value] = "NOT_APPLICABLE"
                continue
            dims[dim.value] = "PASS(attested)"

        integrity_codes = await self._averify_integrity(req, validation, ctx)
        dims[TrustDimension.INTEGRITY.value] = "PASS(verified)" if not integrity_codes else "FAIL(verified)"
        codes.extend(integrity_codes)

        source_codes = await self._averify_source(record, ctx)
        dims[TrustDimension.SOURCE_IDENTITY.value] = "PASS(verified)" if not source_codes else "FAIL(verified)"
        codes.extend(source_codes)

        lineage_codes, lineage_summary = await self._averify_lineage(req.record_id, ctx)
        dims[TrustDimension.LINEAGE.value] = "PASS(verified)" if not lineage_codes else "FAIL(verified)"
        codes.extend(lineage_codes)

        if not getattr(record, "source_id", None) and not lineage_summary.get("ancestors"):
            codes.append(TrustReason.PROVENANCE_MISSING)

        if any(s.severity is SignalSeverity.HIGH and not s.resolved for s in req.evidence.signals):
            codes.append(TrustReason.UNRESOLVED_HIGH_SIGNAL)

        ctx.summary["dimensions"] = dims
        ctx.summary["lineage"] = lineage_summary
        if req.evidence.signals:
            ctx.summary["signals"] = [
                {"source": s.source, "label": s.label, "severity": s.severity.value,
                 "model_version": s.model_version, "resolved": s.resolved}
                for s in req.evidence.signals
            ]
        if codes:
            raise _Deny(*_dedupe(codes))

    async def _averify_integrity(self, req, validation: TrustValidationEvidence, ctx: _Ctx) -> List[TrustReason]:
        try:
            versions = await _maybe_await(self._repo.get_versions(req.record_id, ctx.tenant_id))
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        current = [v for v in versions if getattr(v, "version", None) == ctx.version]
        if len(current) != 1:
            return [TrustReason.INTEGRITY_UNVERIFIABLE]
        codes: List[TrustReason] = []
        for ver in versions:
            try:
                if sha256_hex(ver.content) != ver.checksum:
                    codes.append(TrustReason.INTEGRITY_FAILED)
                    break
            except Exception:  # noqa: BLE001
                return [TrustReason.INTEGRITY_UNVERIFIABLE]
        ctx.checksum = current[0].checksum
        if validation.assessed_checksum != current[0].checksum:
            codes.append(TrustReason.ASSESSMENT_CHECKSUM_MISMATCH)
        return codes

    async def _averify_source(self, record, ctx: _Ctx) -> List[TrustReason]:
        source_id = getattr(record, "source_id", None)
        if not source_id:
            return []
        try:
            source = await _maybe_await(self._repo.get_source(source_id, ctx.tenant_id))
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        if source is None or getattr(source, "tenant_id", None) != ctx.tenant_id or getattr(source, "status", None) != "ACTIVE":
            return [TrustReason.SOURCE_INVALID]
        return []

    async def _averify_lineage(self, record_id: str, ctx: _Ctx) -> Tuple[List[TrustReason], Dict[str, object]]:
        lineage_relations = {ProvenanceRelationType.DERIVED_FROM.value, ProvenanceRelationType.TRANSFORMED_INTO.value}
        visited = {record_id}
        frontier: List[Tuple[str, int]] = [(record_id, 0)]
        ancestors: Dict[str, str] = {}
        edges_seen = 0
        codes: List[TrustReason] = []
        try:
            while frontier:
                current, depth = frontier.pop(0)
                edges = await _maybe_await(self._repo.get_edges_for_record(current, ctx.tenant_id))
                for edge in edges:
                    relation = _state_like(getattr(edge, "relation_type", None))
                    if getattr(edge, "to_record_id", None) != current or relation not in lineage_relations:
                        continue
                    edges_seen += 1
                    if edges_seen > MAX_LINEAGE_EDGES:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    if getattr(edge, "tenant_id", None) != ctx.tenant_id:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_id = edge.from_record_id
                    if parent_id in visited:
                        continue
                    if depth + 1 > MAX_LINEAGE_DEPTH or len(visited) >= MAX_LINEAGE_NODES:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    visited.add(parent_id)
                    parent = await _maybe_await(self._repo.get_record(parent_id, ctx.tenant_id))
                    if parent is None or not parent or getattr(parent, "tenant_id", None) != ctx.tenant_id:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_stored = _state_value(parent.trust_state)
                    if parent_stored is None:
                        return [TrustReason.LINEAGE_INCOMPLETE], {"ancestors": ancestors, "complete": False}
                    parent_effective, _, _ = await self._areconcile(parent_stored, parent.current_version, ctx.tenant_id, parent_id)
                    ancestors[parent_id] = parent_effective
                    if parent_effective in (TrustState.SUSPICIOUS.value, TrustState.QUARANTINED.value, TrustState.REJECTED.value):
                        codes.append(TrustReason.LINEAGE_TAINTED)
                    elif parent_effective == TrustState.UNVERIFIED.value:
                        codes.append(TrustReason.LINEAGE_UNVERIFIED)
                    elif parent_effective == TrustState.SUPERSEDED.value:
                        codes.append(TrustReason.LINEAGE_SUPERSEDED)
                    frontier.append((parent_id, depth + 1))
        except _Deny:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        return _dedupe(codes), {"ancestors": ancestors, "complete": True}

    async def _acheck_supersession(self, req: TrustTransitionRequest, ctx: _Ctx) -> None:
        successor_id = req.evidence.successor_record_id
        if not successor_id or successor_id == req.record_id:
            raise _Deny(TrustReason.SUCCESSOR_INVALID)
        try:
            successor = await _maybe_await(self._repo.get_record(successor_id, ctx.tenant_id))
            if successor is None or not successor or getattr(successor, "tenant_id", None) != ctx.tenant_id:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            succ_state = _state_value(successor.trust_state)
            if succ_state is None:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            succ_effective, _, _ = await self._areconcile(succ_state, successor.current_version, ctx.tenant_id, successor_id)
            if succ_effective != TrustState.TRUSTED.value:
                raise _Deny(TrustReason.SUCCESSOR_INVALID)
            edges = await _maybe_await(self._repo.get_edges_for_record(req.record_id, ctx.tenant_id))
        except _Deny:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.REPOSITORY_UNAVAILABLE) from exc
        has_edge = any(
            getattr(e, "from_record_id", None) == successor_id
            and getattr(e, "to_record_id", None) == req.record_id
            and _state_like(getattr(e, "relation_type", None)) == ProvenanceRelationType.SUPERSEDES.value
            and getattr(e, "tenant_id", None) == ctx.tenant_id
            for e in edges
        )
        if not has_edge:
            raise _Deny(TrustReason.SUPERSESSION_EDGE_MISSING)
        ctx.summary["successor_record_id"] = successor_id

    async def _acheck_release_separation(self, req: TrustTransitionRequest, ctx: _Ctx) -> None:
        try:
            history = await self._astore_list(ctx.tenant_id, req.record_id)
        except Exception as exc:  # noqa: BLE001
            raise _Deny(TrustReason.DECISION_STORE_UNAVAILABLE) from exc
        quarantines = [d for d in history if d.applied and d.resulting_state == TrustState.QUARANTINED.value]
        is_admin = ctx.actor_role == Role.TENANT_ADMIN.value
        if not quarantines:
            if not is_admin:
                raise _Deny(TrustReason.QUARANTINE_ORIGIN_UNKNOWN)
            return
        if quarantines[-1].actor_id == ctx.actor_id and not is_admin:
            raise _Deny(TrustReason.SEPARATION_OF_DUTIES)

    async def _aapply(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> TrustDecision:
        async with self._async_record_lock(ctx.tenant_id or "", req.record_id):
            return await self._aapply_locked(req, record, ctx)

    async def _aapply_locked(self, req: TrustTransitionRequest, record, ctx: _Ctx) -> TrustDecision:
        rule = ctx.rule
        assert rule is not None
        now = self._clock()
        try:
            fresh = await _maybe_await(self._repo.get_record(req.record_id, ctx.tenant_id))
        except Exception as exc:  # noqa: BLE001
            logger.error("Trust transition not applied: repository re-read failed (%s).", type(exc).__name__)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.REPOSITORY_UNAVAILABLE,))
        if fresh is None or getattr(fresh, "tenant_id", None) != ctx.tenant_id:
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.RECORD_NOT_FOUND,))
        if _state_value(fresh.trust_state) != _state_value(record.trust_state):
            logger.warning("Trust transition refused: record %s state changed during evaluation.", req.record_id)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.STALE_STATE,))
        if fresh.current_version != record.current_version:
            logger.warning("Trust transition refused: record %s version changed during evaluation.", req.record_id)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.STALE_VERSION,))
        previous = fresh
        try:
            updated = fresh.model_copy(update={"trust_state": rule.to_state.value, "updated_at": now})
            await _maybe_await(self._repo.update_record(updated))
        except Exception as exc:  # noqa: BLE001
            logger.error("Trust transition not applied: repository update failed (%s).", type(exc).__name__)
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.REPOSITORY_UNAVAILABLE,))

        decision = self._decision(req, ctx, allowed=True, applied=True, codes=(TrustReason.TRANSITION_APPLIED,))
        try:
            await self._astore_append(decision)
        except Exception as exc:  # noqa: BLE001
            logger.error("Trust decision store append failed (%s); reverting transition.", type(exc).__name__)
            try:
                current = await _maybe_await(self._repo.get_record(req.record_id, ctx.tenant_id))
                if current is None or _state_value(current.trust_state) != rule.to_state.value or current.current_version != previous.current_version:
                    raise RuntimeError("record changed after the transition; revert skipped")
                await _maybe_await(self._repo.update_record(previous))
            except Exception:  # noqa: BLE001
                logger.critical(
                    "Trust transition revert FAILED for record %s; manual reconciliation required.", req.record_id
                )
            return self._decision(req, ctx, allowed=False, applied=False, codes=(TrustReason.DECISION_STORE_UNAVAILABLE,))
        return decision

    async def _arecord_denial(self, decision: TrustDecision) -> None:
        if not decision.tenant_id:
            return
        try:
            await self._astore_append(decision)
        except Exception as exc:  # noqa: BLE001 — denial stands regardless
            logger.error("Could not persist denied trust decision (%s).", type(exc).__name__)

    # -- helpers --------------------------------------------------------------

    def _actor_tenant(self, actor: Optional[TrustActor]) -> Optional[str]:
        if isinstance(actor, UserActor) and isinstance(actor.context, TenantContext) and actor.context.is_active is True:
            return actor.context.tenant_id if _nonblank(actor.context.tenant_id) else None
        if isinstance(actor, SystemActor) and _nonblank(actor.tenant_id):
            return actor.tenant_id
        return None

    def _decision(
        self,
        req: Optional[TrustTransitionRequest],
        ctx: _Ctx,
        *,
        allowed: bool,
        applied: bool,
        codes: Sequence[TrustReason],
        raw_record_id: Optional[str] = None,
    ) -> TrustDecision:
        rule = ctx.rule
        if applied:
            label = "APPLIED"
        elif allowed:
            label = "PERMITTED"
        else:
            label = "DENIED"
        summary = dict(ctx.summary)
        if req is not None:
            summary.setdefault("evidence_refs", list(req.evidence.evidence_refs))
            for key in ("recovery_plan_id", "checkpoint_id"):
                value = getattr(req.evidence, key)
                if value:
                    summary.setdefault(key, value)
        return TrustDecision(
            decision_id=str(uuid.uuid4()),
            allowed=allowed,
            applied=applied,
            decision=label,
            reason_codes=tuple(c.value for c in codes),
            reason=(req.reason if req is not None else ""),
            record_id=(req.record_id if req is not None else (raw_record_id or "")),
            tenant_id=ctx.tenant_id,
            operation=(req.operation.value if req is not None else None),
            transition_id=(rule.transition_id if rule else None),
            current_state=ctx.effective_state,
            stored_state=ctx.stored_state,
            target_state=(req.target_state.value if req is not None else None),
            resulting_state=(rule.to_state.value if (applied and rule) else ctx.effective_state),
            record_version=ctx.version,
            version_checksum=ctx.checksum,
            actor_type=ctx.actor_type,
            actor_id=ctx.actor_id,
            actor_role=ctx.actor_role,
            incident_id=(req.evidence.incident_id if req is not None else None),
            evidence_summary=summary,
            policy_version=TRUST_POLICY_VERSION,
            timestamp=self._clock(),
            history_available=ctx.history_available,
        )

    def _log(self, decision: TrustDecision) -> None:
        # Never log reason text, memory content or evidence notes.
        logger.info(
            "Trust decision %s: decision=%s op=%s transition=%s tenant=%s record=%s %s->%s codes=%s actor=%s:%s",
            decision.decision_id, decision.decision, decision.operation, decision.transition_id,
            decision.tenant_id, decision.record_id, decision.current_state, decision.resulting_state,
            ",".join(decision.reason_codes), decision.actor_type, decision.actor_id,
        )


# =============================================================================
# 7. Mapping decisions to M1 error contracts
# =============================================================================

_DEPENDENCY_CODES = {
    TrustReason.REPOSITORY_UNAVAILABLE.value,
    TrustReason.DECISION_STORE_UNAVAILABLE.value,
}
_AUTHZ_CODES = {
    TrustReason.ACTOR_MISSING.value,
    TrustReason.ACTOR_INVALID.value,
    TrustReason.ACTOR_TYPE_NOT_PERMITTED.value,
    TrustReason.ACTOR_NOT_AUTHORIZED.value,
    TrustReason.SEPARATION_OF_DUTIES.value,
    TrustReason.QUARANTINE_ORIGIN_UNKNOWN.value,
}


def raise_for_decision(decision: TrustDecision) -> TrustDecision:
    """Return an allowed decision; otherwise raise the matching M1 exception.

    503 dependency failure > 403 authorization > 404 not found > 400 request > 409 conflict.
    Public responses use M1's allowlisted messages; reason codes stay server-side.
    """
    if decision.allowed:
        return decision
    codes = set(decision.reason_codes)
    if codes & _DEPENDENCY_CODES or TrustReason.EVALUATION_ERROR.value in codes:
        raise SecurityDependencyError("Trust evaluation could not be completed.")
    if codes & _AUTHZ_CODES:
        raise ForbiddenError("Trust transition not authorized.")
    if TrustReason.RECORD_NOT_FOUND.value in codes:
        raise NotFoundError("Memory record not found.")
    if TrustReason.REQUEST_INVALID.value in codes:
        raise ValidationError("Invalid trust transition request.")
    raise AMSCException(message="Trust transition rejected.", code="CONFLICT", status_code=409)


# =============================================================================
# 8. Small utilities
# =============================================================================

def _state_value(value: object) -> Optional[str]:
    if isinstance(value, TrustState):
        return value.value
    if type(value) is str and value in _KNOWN_STATES:
        return value
    return None


def _state_like(value: object) -> Optional[str]:
    if isinstance(value, Enum):
        return value.value  # type: ignore[return-value]
    return value if type(value) is str else None


def _nonblank(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _dedupe(codes: Sequence[TrustReason]) -> List[TrustReason]:
    seen: List[TrustReason] = []
    for c in codes:
        if c not in seen:
            seen.append(c)
    return seen


def _dedupe_str(codes: Sequence[str]) -> List[str]:
    seen: List[str] = []
    for c in codes:
        if c not in seen:
            seen.append(c)
    return seen


def _raw_record_id(request: object) -> Optional[str]:
    if isinstance(request, TrustTransitionRequest):
        return request.record_id
    if isinstance(request, Mapping):
        value = request.get("record_id")
        return value[:128] if type(value) is str else None
    return None
