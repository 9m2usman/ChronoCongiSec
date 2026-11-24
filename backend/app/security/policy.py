"""Deterministic, fail-closed security policy engine for protected tool actions.

Module: backend.app.security.policy
Owner: M4 — Security Engine & Incident Response Lead

Implements the M4 Day 4 deliverable (``docs/06-TEAM-IMPLEMENTATION-PLAN.md`` Day 4:
"Enforce fail-closed policy logic: block proposals referencing tainted memory",
``security/policy.py``). The rule matrix follows TRD §16, evaluated in order:

    Check 1  Agent status            ISOLATED            -> BLOCK  AGENT_ISOLATED
    Check 2  Tool whitelist          not assigned        -> BLOCK  TOOL_NOT_ASSIGNED
    Check 3  Operation whitelist     not allowed         -> BLOCK  OPERATION_DENIED
    Check 4  Parameter ceilings      above hard maximum  -> BLOCK  CEILING_EXCEEDED
    Check 5  Approval thresholds     above threshold     -> REQUIRES_APPROVAL
    Check 6  Memory trust            any ref ineligible  -> BLOCK  REFERENCED_UNTRUSTED_MEMORY
    ALLOW only if every mandatory check positively passed.

plus an input check and a requesting-principal role check (Day 1 POL-ENV / POL-PRN,
using the Day 2 RBAC evaluator). Memory eligibility comes exclusively from the Day 3
``TrustEvaluator.assess_for_action`` (single trust authority).

Decision algebra (Day 1 design §5): the decision starts as BLOCK; any BLOCK or
INDETERMINATE check result => BLOCK; otherwise any REVIEW result => REQUIRES_APPROVAL
(only where the tool policy permits review); ALLOW only when every mandatory check
returned PASS. All checks are always evaluated so every reason is reported; a later
check can never lift an earlier denial. Timeouts and unexpected errors => BLOCK.

``ProtectedExecutionGuard`` is the enforcement point for adapters: it invokes an
executor only for an ALLOW decision issued by this engine, after the decision has
been persisted and after a fresh pre-execution revalidation, exactly once.

No LLM, ML model or score participates in any decision.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

from backend.app.security.authorization import (
    AuthorizationPolicyError,
    Role,
    evaluate_role_access,
    normalize_allowed_roles,
)
from backend.app.security.trust import ActionMemoryAssessment, TrustEvaluator
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.policy")

POLICY_VERSION = "amsc-policy/1.0.0"
DEFAULT_TIMEOUT_SECONDS = 2.0          # Doc 03 §11: evaluation > 2000 ms => BLOCK
MAX_MEMORY_REFS = 50
MAX_PARAMETERS_BYTES = 65_536
MAX_ID_LENGTH = 128
MAX_IDEMPOTENCY_KEY_LENGTH = 255
MAX_ISSUED_GRANTS = 10_000
# Process-local execution ledger (finding M4-F1): one execution per (tenant, idempotency key)
# and per (tenant, approval id). Defense in depth only: the durable, cross-process guarantee is
# M6's UNIQUE tool_executions.proposal_id plus approval consumption (OD-6/OD-7), which the
# caller (M2) must use. Entries are kept for every dispatched execution, whatever its outcome.
MAX_EXECUTION_LEDGER = 100_000


# =============================================================================
# 1. Vocabulary (Doc 05 §3.4 / §6.1)
# =============================================================================

class PolicyOutcome(str, Enum):
    """Canonical decision values (Doc 05 ``policy_decisions.decision``)."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class PolicyResult(str, Enum):
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    ELEVATED = "ELEVATED"


class CheckOutcome(str, Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    INDETERMINATE = "INDETERMINATE"


class PolicyCheck(str, Enum):
    INPUT = "CHECK_0A_INPUT"
    PRINCIPAL = "CHECK_0B_PRINCIPAL"
    AGENT_STATUS = "CHECK_1_AGENT_STATUS"
    TOOL_WHITELIST = "CHECK_2_TOOL_WHITELIST"
    OPERATION_WHITELIST = "CHECK_3_OPERATION_WHITELIST"
    PARAMETER_CEILINGS = "CHECK_4_PARAMETER_CEILINGS"
    APPROVAL_THRESHOLD = "CHECK_5_APPROVAL_THRESHOLD"
    MEMORY_TRUST = "CHECK_6_MEMORY_TRUST"


MANDATORY_CHECKS: Tuple[PolicyCheck, ...] = tuple(PolicyCheck)


class ReasonCode(str, Enum):
    # TRD §16 / Doc 03 canonical codes
    AGENT_ISOLATED = "AGENT_ISOLATED"
    TOOL_NOT_ASSIGNED = "TOOL_NOT_ASSIGNED"
    OPERATION_DENIED = "OPERATION_DENIED"
    CEILING_EXCEEDED = "CEILING_EXCEEDED"
    REFERENCED_UNTRUSTED_MEMORY = "REFERENCED_UNTRUSTED_MEMORY"
    POLICY_EVALUATION_TIMEOUT = "POLICY_EVALUATION_TIMEOUT"
    MEMORY_TRUST_UNAVAILABLE = "MEMORY_TRUST_UNAVAILABLE"
    # Additive codes (Day 1 design §4)
    ALL_CHECKS_PASSED = "ALL_CHECKS_PASSED"
    POLICY_INPUT_INVALID = "POLICY_INPUT_INVALID"
    TENANT_CONTEXT_INVALID = "TENANT_CONTEXT_INVALID"
    PRINCIPAL_ROLE_NOT_AUTHORIZED = "PRINCIPAL_ROLE_NOT_AUTHORIZED"
    AGENT_NOT_REGISTERED = "AGENT_NOT_REGISTERED"
    AGENT_NOT_ACTIVE = "AGENT_NOT_ACTIVE"
    AGENT_DIRECTORY_UNAVAILABLE = "AGENT_DIRECTORY_UNAVAILABLE"
    TOOL_GRANT_UNAVAILABLE = "TOOL_GRANT_UNAVAILABLE"
    TOOL_NOT_REGISTERED = "TOOL_NOT_REGISTERED"
    OPERATION_WILDCARD_NOT_PERMITTED = "OPERATION_WILDCARD_NOT_PERMITTED"
    PARAMETER_INVALID = "PARAMETER_INVALID"
    PARAMETER_BELOW_MINIMUM = "PARAMETER_BELOW_MINIMUM"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    POLICY_CONSTRAINT_MISSING = "POLICY_CONSTRAINT_MISSING"
    POLICY_CONFIG_INVALID = "POLICY_CONFIG_INVALID"
    APPROVAL_THRESHOLD_EXCEEDED = "APPROVAL_THRESHOLD_EXCEEDED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_SCOPE_MISMATCH = "APPROVAL_SCOPE_MISMATCH"
    APPROVAL_ALREADY_CONSUMED = "APPROVAL_ALREADY_CONSUMED"
    APPROVAL_SELF_APPROVAL = "APPROVAL_SELF_APPROVAL"
    REVIEW_NOT_PERMITTED = "REVIEW_NOT_PERMITTED"
    MEMORY_JUSTIFICATION_REQUIRED = "MEMORY_JUSTIFICATION_REQUIRED"
    MEMORY_REFERENCE_INVALID = "MEMORY_REFERENCE_INVALID"
    MEMORY_SCOPE_VIOLATION = "MEMORY_SCOPE_VIOLATION"
    MEMORY_TRUST_EVIDENCE_INCOMPLETE = "MEMORY_TRUST_EVIDENCE_INCOMPLETE"
    MANDATORY_CONTROL_DENIED = "MANDATORY_CONTROL_DENIED"
    MANDATORY_CONTROL_UNAVAILABLE = "MANDATORY_CONTROL_UNAVAILABLE"
    RULESET_INCOMPLETE = "RULESET_INCOMPLETE"
    INTERNAL_EVALUATION_ERROR = "INTERNAL_EVALUATION_ERROR"
    # Execution guard
    DECISION_NOT_EXECUTABLE = "DECISION_NOT_EXECUTABLE"
    DECISION_NOT_ISSUED_BY_ENGINE = "DECISION_NOT_ISSUED_BY_ENGINE"
    AUDIT_PERSISTENCE_FAILED = "AUDIT_PERSISTENCE_FAILED"
    PRE_EXECUTION_REVALIDATION_FAILED = "PRE_EXECUTION_REVALIDATION_FAILED"
    EXECUTION_GRANT_ALREADY_USED = "EXECUTION_GRANT_ALREADY_USED"
    EXECUTION_ALREADY_PERFORMED = "EXECUTION_ALREADY_PERFORMED"
    ADAPTER_EXECUTION_FAILED = "ADAPTER_EXECUTION_FAILED"


# =============================================================================
# 2. Server-side inputs and ports (implemented by M1 / M3 / M6)
# =============================================================================

@dataclass(frozen=True)
class ToolGrant:
    """Server-resolved agent→tool permission (Doc 05 ``agent_tool_permissions`` + ``tool_registrations``)."""

    tool_name: str
    allowed_operations: Union[str, Sequence[str]]
    constraints: Mapping[str, Any] = field(default_factory=dict)
    tool_registered: bool = True


@dataclass(frozen=True)
class ApprovalEvidence:
    """Server-resolved human approval (Doc 05 ``approvals``; extra fields requested from M6, D-06)."""

    approval_id: str
    tenant_id: str
    status: str
    proposal_fingerprint: str
    approver_user_id: str
    approver_role: str
    expires_at: datetime
    consumed: bool = False


class AgentDirectory(Protocol):
    """Returns the agent (with ``status`` and ``tenant_id``) or None. Sync or async.

    M3's ``MemoryRepository.get_agent(agent_id, tenant_id)`` satisfies this today.
    """

    def get_agent(self, agent_id: str, tenant_id: str) -> Any: ...


class ToolGrantDirectory(Protocol):
    """Returns the ``ToolGrant`` for (tenant, agent, tool) or None. Sync or async (M6)."""

    def get_tool_grant(self, tenant_id: str, agent_id: str, tool_name: str) -> Any: ...


@dataclass(frozen=True)
class ToolPolicy:
    """Per (tool, operation) policy-as-data. Absent entry => no extra requirements."""

    mandatory_constraints: Tuple[str, ...] = ()
    requires_memory_justification: bool = False
    review_permitted: bool = True


DEFAULT_TOOL_POLICIES: Mapping[Tuple[str, str], ToolPolicy] = {
    # PRD Demo 1/2: financial transfers need a hard ceiling and trusted memory justification.
    ("sandbox_transfer", "transfer_funds"): ToolPolicy(
        mandatory_constraints=("max_amount",),
        requires_memory_justification=True,
        review_permitted=True,
    ),
}


class PolicyConfigurationError(ValueError):
    """Invalid engine configuration (raised at construction: fail fast)."""


_CONSTRAINT_KEY = re.compile(r"(max|min|approval_threshold|allowed)_([a-z][a-z0-9_]{0,62})")


@dataclass(frozen=True)
class PolicyConfig:
    proposer_roles: Tuple[Union[Role, str], ...] = (Role.AI_DEVELOPER,)
    tool_policies: Mapping[Tuple[str, str], ToolPolicy] = field(default_factory=lambda: dict(DEFAULT_TOOL_POLICIES))
    enforce_memory_agent_binding: bool = True
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def validated(self) -> "PolicyConfig":
        try:
            normalize_allowed_roles(self.proposer_roles)
        except AuthorizationPolicyError as exc:
            raise PolicyConfigurationError(f"Invalid proposer_roles: {exc}") from exc
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) \
                or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise PolicyConfigurationError("timeout_seconds must be a positive finite number.")
        for key, tp in self.tool_policies.items():
            if not (isinstance(key, tuple) and len(key) == 2 and all(isinstance(k, str) and k for k in key)):
                raise PolicyConfigurationError("tool_policies keys must be (tool_name, operation).")
            if not isinstance(tp, ToolPolicy):
                raise PolicyConfigurationError("tool_policies values must be ToolPolicy.")
            for c in tp.mandatory_constraints:
                if not isinstance(c, str) or not _CONSTRAINT_KEY.fullmatch(c):
                    raise PolicyConfigurationError(f"Unrecognized mandatory constraint key: {c!r}.")
        return self


# =============================================================================
# 3. Normalized proposal (Doc 05 §6.1 fields; M2 owns the API schema)
# =============================================================================

@dataclass(frozen=True)
class MemoryRef:
    record_id: str
    version: Optional[int] = None


@dataclass(frozen=True)
class ProposalFacts:
    action_id: str
    agent_id: str
    tool_name: str
    operation: str
    parameters: Mapping[str, Any]
    memory_refs: Tuple[MemoryRef, ...]
    idempotency_key: str
    trace_id: str


class _InputError(Exception):
    pass


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _identifier(value: Any, name: str, max_len: int = MAX_ID_LENGTH) -> str:
    if type(value) is not str or not value.strip() or len(value) > max_len \
            or value != value.strip() or any(ord(c) < 32 for c in value):
        raise _InputError(name)
    return value


def normalize_proposal(proposal: Any) -> ProposalFacts:
    """Extract and validate the Doc 05 §6.1 proposal fields from M2's model or a mapping."""
    if proposal is None:
        raise _InputError("proposal")
    params = _get(proposal, "parameters")
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise _InputError("parameters")
    try:
        encoded = json.dumps(params, sort_keys=True, separators=(",", ":"), allow_nan=False, default=_json_default)
    except (TypeError, ValueError):
        raise _InputError("parameters")
    if len(encoded.encode("utf-8")) > MAX_PARAMETERS_BYTES:
        raise _InputError("parameters")

    raw_refs = _get(proposal, "memory_refs")
    if raw_refs is None:
        raw_refs = []
    if isinstance(raw_refs, (str, bytes)) or not isinstance(raw_refs, Sequence) or len(raw_refs) > MAX_MEMORY_REFS:
        raise _InputError("memory_refs")
    refs: List[MemoryRef] = []
    for raw in raw_refs:
        if type(raw) is str:
            refs.append(MemoryRef(_identifier(raw, "memory_refs")))
            continue
        rid = _identifier(_get(raw, "record_id"), "memory_refs")
        ver = _get(raw, "version")
        if ver is not None and (type(ver) is not int or ver < 1):
            raise _InputError("memory_refs")
        refs.append(MemoryRef(rid, ver))
    if len({r.record_id for r in refs}) != len(refs):
        raise _InputError("memory_refs")

    return ProposalFacts(
        action_id=_identifier(_get(proposal, "action_id"), "action_id"),
        agent_id=_identifier(_get(proposal, "agent_id"), "agent_id"),
        tool_name=_identifier(_get(proposal, "tool_name"), "tool_name"),
        operation=_identifier(_get(proposal, "operation"), "operation"),
        parameters=dict(params),
        memory_refs=tuple(refs),
        idempotency_key=_identifier(_get(proposal, "idempotency_key"), "idempotency_key", MAX_IDEMPOTENCY_KEY_LENGTH),
        trace_id=_identifier(_get(proposal, "trace_id"), "trace_id"),
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite decimal")
        return str(value)
    raise TypeError(f"Unserializable parameter type: {type(value).__name__}")


def proposal_fingerprint(facts: ProposalFacts, tenant_id: str, principal_id: str) -> str:
    """SHA-256 over canonical JSON of the security-relevant proposal fields."""
    payload = {
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "action_id": facts.action_id,
        "agent_id": facts.agent_id,
        "tool_name": facts.tool_name,
        "operation": facts.operation,
        "parameters": facts.parameters,
        "memory_refs": [[r.record_id, r.version] for r in facts.memory_refs],
        "idempotency_key": facts.idempotency_key,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False, default=_json_default)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# =============================================================================
# 4. Decision contract
# =============================================================================

@dataclass(frozen=True)
class CheckResult:
    check: str
    outcome: str
    reason_codes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class MemoryEvidence:
    """Per-reference evidence (identifiers, states, version, checksum — never content)."""

    record_id: str
    pinned_version: Optional[int]
    version: Optional[int]
    checksum: Optional[str]
    effective_state: Optional[str]
    eligible: bool
    trust_decision_id: Optional[str]
    reason_codes: Tuple[str, ...]


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    outcome: PolicyOutcome
    policy_result: PolicyResult
    memory_trust: str
    reason_codes: Tuple[str, ...]
    reasons: Tuple[str, ...]
    checks: Tuple[CheckResult, ...]
    memory_evidence: Tuple[MemoryEvidence, ...]
    policy_version: str
    evaluated_at: datetime
    evaluation_status: str              # COMPLETE | TIMEOUT | ERROR | INPUT_INVALID
    execution_eligible: bool
    proposal_fingerprint: Optional[str]
    tenant_id: Optional[str]
    principal_id: Optional[str]
    principal_role: Optional[str]
    agent_id: Optional[str]
    action_id: Optional[str]
    tool_name: Optional[str]
    operation: Optional[str]
    idempotency_key: Optional[str]
    trace_id: Optional[str]
    approval_id: Optional[str] = None
    elapsed_ms: float = 0.0

    @property
    def initial_execution_status(self) -> str:
        """Doc 05 ``policy_decisions.execution_status`` at decision time (OD-4).

        The execution *lifecycle*, not the tool outcome and not permission to run:

        - a complete, consistent ALLOW -> ``PENDING_EXECUTION`` ("permitted and persisted;
          dispatch not yet recorded"). It never means success: only the guard, after
          persistence, pre-execution revalidation and mandatory controls, may dispatch, and
          the caller then moves it to EXECUTED / FAILED / UNKNOWN, or to NOT_EXECUTED when
          revalidation or a control blocks;
        - REQUIRES_APPROVAL -> ``PENDING_APPROVAL`` (never executes without a valid approval);
        - BLOCK, and any ALLOW that is not ``decision_is_executable`` (incomplete, timed out,
          contradictory or tampered) -> ``NOT_EXECUTED`` (fail closed).
        """
        if decision_is_executable(self):
            return "PENDING_EXECUTION"
        if self.outcome is PolicyOutcome.REQUIRES_APPROVAL and self.policy_result is PolicyResult.ELEVATED:
            return "PENDING_APPROVAL"
        return "NOT_EXECUTED"

    def to_persistence_record(self) -> Dict[str, Any]:
        """Data for M6: Doc 05 ``policy_decisions`` columns plus audit ``details_json``.

        Columns beyond Doc 05 (policy_version, reason_codes, checks, memory evidence,
        fingerprint) are requested from M6 (Day 1 D-06); until then they belong in the
        TOOL_POLICY_DECIDED audit event ``details_json``.
        """
        return {
            "id": self.decision_id,
            "tenant_id": self.tenant_id,
            "decision": self.outcome.value,
            "memory_trust": self.memory_trust,
            "policy_result": self.policy_result.value,
            "reasons_json": list(self.reasons),
            "execution_status": self.initial_execution_status,
            "details_json": {
                "policy_version": self.policy_version,
                "evaluation_status": self.evaluation_status,
                "reason_codes": list(self.reason_codes),
                "checks": [
                    {"check": c.check, "outcome": c.outcome, "reason_codes": list(c.reason_codes)} for c in self.checks
                ],
                "memory_evidence": [
                    {
                        "record_id": m.record_id, "pinned_version": m.pinned_version, "version": m.version,
                        "checksum": m.checksum, "effective_state": m.effective_state, "eligible": m.eligible,
                        "trust_decision_id": m.trust_decision_id, "reason_codes": list(m.reason_codes),
                    }
                    for m in self.memory_evidence
                ],
                "proposal_fingerprint": self.proposal_fingerprint,
                "principal_id": self.principal_id,
                "principal_role": self.principal_role,
                "agent_id": self.agent_id,
                "action_id": self.action_id,
                "tool_name": self.tool_name,
                "operation": self.operation,
                "idempotency_key": self.idempotency_key,
                "trace_id": self.trace_id,
                "approval_id": self.approval_id,
                "evaluated_at": self.evaluated_at.isoformat(),
                "elapsed_ms": round(self.elapsed_ms, 3),
            },
        }


def decision_is_executable(decision: Any) -> bool:
    """True only for a complete, internally consistent, current-policy ALLOW ``PolicyDecision``.

    Anything else — other types, BLOCK/REQUIRES_APPROVAL, timed-out or errored evaluations,
    contradictory fields (e.g. ALLOW with policy_result DENIED, a non-PASS or missing
    mandatory check, ineligible memory evidence) — is False.
    """
    if not isinstance(decision, PolicyDecision):
        return False
    checks = {c.check: c.outcome for c in decision.checks if isinstance(c, CheckResult)}
    return (
        decision.outcome is PolicyOutcome.ALLOW
        and decision.policy_result is PolicyResult.PERMITTED
        and decision.execution_eligible is True
        and decision.evaluation_status == "COMPLETE"
        and decision.policy_version == POLICY_VERSION
        and decision.reason_codes == (ReasonCode.ALL_CHECKS_PASSED.value,)
        and len(decision.checks) == len(MANDATORY_CHECKS)
        and all(checks.get(c.value) == CheckOutcome.PASS.value for c in MANDATORY_CHECKS)
        and all(isinstance(m, MemoryEvidence) and m.eligible is True for m in decision.memory_evidence)
    )


_HUMAN_REASONS: Mapping[str, str] = {
    "AGENT_ISOLATED": "Agent is isolated and cannot execute protected tools.",
    "AGENT_NOT_ACTIVE": "Agent is not active.",
    "AGENT_NOT_REGISTERED": "Agent is not registered in this tenant.",
    "TOOL_NOT_ASSIGNED": "Tool is not assigned to this agent.",
    "TOOL_NOT_REGISTERED": "Tool is not registered in this tenant.",
    "OPERATION_DENIED": "Operation is not in the agent's allowed operations for this tool.",
    "OPERATION_WILDCARD_NOT_PERMITTED": "Wildcard operation grants are not honoured for protected tools.",
    "CEILING_EXCEEDED": "A parameter exceeds its configured hard ceiling.",
    "PARAMETER_BELOW_MINIMUM": "A parameter is below its configured minimum.",
    "PARAMETER_INVALID": "A security-relevant parameter is missing or invalid.",
    "DESTINATION_NOT_ALLOWED": "A destination or resource is not in the configured allow-list.",
    "POLICY_CONSTRAINT_MISSING": "A mandatory policy constraint is not configured for this tool operation.",
    "POLICY_CONFIG_INVALID": "Tool permission constraints are invalid or unrecognized.",
    "APPROVAL_THRESHOLD_EXCEEDED": "A parameter exceeds the approval threshold; human approval is required.",
    "REVIEW_NOT_PERMITTED": "This tool operation does not permit human review; the action is blocked.",
    "REFERENCED_UNTRUSTED_MEMORY": "A referenced memory is not eligible TRUSTED memory and cannot justify this action.",
    "MEMORY_JUSTIFICATION_REQUIRED": "This tool operation requires trusted memory justification.",
    "MEMORY_TRUST_UNAVAILABLE": "Memory trust verification is unavailable; the action is blocked.",
    "PRINCIPAL_ROLE_NOT_AUTHORIZED": "The requesting principal's role may not submit protected actions.",
    "POLICY_EVALUATION_TIMEOUT": "Policy evaluation exceeded its time budget; the action is blocked.",
    "INTERNAL_EVALUATION_ERROR": "Policy evaluation failed; the action is blocked.",
    "POLICY_INPUT_INVALID": "The proposal is malformed.",
    "TENANT_CONTEXT_INVALID": "Verified tenant context is unavailable.",
    "ALL_CHECKS_PASSED": "All authorization, trust-state, and operational ceiling checks passed.",
}


# =============================================================================
# 5. Engine
# =============================================================================

_STATE_RANK = {"TRUSTED": 0, "UNVERIFIED": 1, "SUPERSEDED": 2, "SUSPICIOUS": 3, "QUARANTINED": 4, "REJECTED": 5}


@dataclass
class _Eval:
    checks: Dict[PolicyCheck, CheckResult] = field(default_factory=dict)
    memory: List[MemoryEvidence] = field(default_factory=list)
    memory_trust: str = "NOT_REFERENCED"
    principal_role: Optional[str] = None
    approval_id: Optional[str] = None

    def set(self, check: PolicyCheck, outcome: CheckOutcome, *codes: ReasonCode | str) -> None:
        values = tuple(c.value if isinstance(c, Enum) else c for c in codes)
        prev = self.checks.get(check)
        if prev is not None:  # combine: worst outcome wins, codes accumulate
            order = [CheckOutcome.PASS.value, CheckOutcome.REVIEW.value, CheckOutcome.BLOCK.value, CheckOutcome.INDETERMINATE.value]
            worst = max(prev.outcome, outcome.value, key=order.index)
            merged = tuple(dict.fromkeys(prev.reason_codes + values))
            self.checks[check] = CheckResult(check.value, worst, merged)
        else:
            self.checks[check] = CheckResult(check.value, outcome.value, values)


class PolicyEngine:
    """Deterministic policy decision point (PDP) for protected tool proposals."""

    def __init__(
        self,
        trust: TrustEvaluator,
        agents: AgentDirectory,
        tool_grants: ToolGrantDirectory,
        config: Optional[PolicyConfig] = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(trust, TrustEvaluator):
            raise PolicyConfigurationError("A Day 3 TrustEvaluator is required as the memory trust authority.")
        if agents is None or tool_grants is None:
            raise PolicyConfigurationError("Agent and tool-grant directories are required.")
        self._trust = trust
        self._agents = agents
        self._grants = tool_grants
        self._config = (config or PolicyConfig()).validated()
        self._proposer_roles = normalize_allowed_roles(self._config.proposer_roles)
        self._clock = clock
        # decision_id -> the exact issued decision (single use). Whole-object equality means a
        # copy with any altered field (dataclasses.replace) is not recognised as issued.
        self._issued: "OrderedDict[str, PolicyDecision]" = OrderedDict()
        # (tenant_id, idempotency_key) and (tenant_id, approval_id) already dispatched (M4-F1).
        self._executed_keys: "OrderedDict[Tuple[str, str], str]" = OrderedDict()
        self._consumed_approvals: "OrderedDict[Tuple[str, str], str]" = OrderedDict()

    # -- public ---------------------------------------------------------------

    async def evaluate(
        self,
        proposal: Any,
        context: Optional[TenantContext],
        *,
        approval: Optional[ApprovalEvidence] = None,
    ) -> PolicyDecision:
        """Evaluate a proposal. Never raises; every failure is a BLOCK decision."""
        return await self._evaluate(proposal, context, approval, register=True)

    @property
    def config(self) -> PolicyConfig:
        return self._config

    # -- internal -------------------------------------------------------------

    async def _evaluate(self, proposal, context, approval, *, register: bool) -> PolicyDecision:
        started = time.perf_counter()
        decision: Optional[PolicyDecision] = None
        try:
            decision = await asyncio.wait_for(
                self._evaluate_inner(proposal, context, approval, started),
                timeout=self._config.timeout_seconds,
            )
            # Synchronous ports cannot be interrupted by wait_for: enforce the budget post hoc.
            if (time.perf_counter() - started) > self._config.timeout_seconds:
                decision = self._failure(proposal, context, started, "TIMEOUT", ReasonCode.POLICY_EVALUATION_TIMEOUT)
        except asyncio.TimeoutError:
            decision = self._failure(proposal, context, started, "TIMEOUT", ReasonCode.POLICY_EVALUATION_TIMEOUT)
        except Exception:  # noqa: BLE001 — fail closed
            logger.exception("Policy evaluation error; proposal blocked (fail closed).")
            decision = self._failure(proposal, context, started, "ERROR", ReasonCode.INTERNAL_EVALUATION_ERROR)

        if register and decision_is_executable(decision):
            self._issued[decision.decision_id] = decision
            while len(self._issued) > MAX_ISSUED_GRANTS:
                self._issued.popitem(last=False)  # evicted grants can no longer execute (fail closed)
        self._log(decision)
        return decision

    async def _evaluate_inner(self, proposal, context, approval, started) -> PolicyDecision:
        ev = _Eval()

        # Check 0A — verified tenant context and well-formed proposal.
        if not _valid_context(context):
            return self._failure(proposal, context, started, "INPUT_INVALID", ReasonCode.TENANT_CONTEXT_INVALID)
        try:
            facts = normalize_proposal(proposal)
            fingerprint = proposal_fingerprint(facts, context.tenant_id, context.user_id)
        except _InputError:
            return self._failure(proposal, context, started, "INPUT_INVALID", ReasonCode.POLICY_INPUT_INVALID)
        ev.set(PolicyCheck.INPUT, CheckOutcome.PASS)
        tenant_id = context.tenant_id
        tool_policy = self._config.tool_policies.get((facts.tool_name, facts.operation), ToolPolicy())

        # Check 0B — requesting principal role (Day 2 RBAC; role from M1 membership).
        rbac = evaluate_role_access(context, self._proposer_roles)
        ev.principal_role = rbac.role
        if rbac.allowed:
            ev.set(PolicyCheck.PRINCIPAL, CheckOutcome.PASS)
        else:
            ev.set(PolicyCheck.PRINCIPAL, CheckOutcome.BLOCK, ReasonCode.PRINCIPAL_ROLE_NOT_AUTHORIZED)

        # Check 1 — agent status.
        await self._check_agent(ev, facts, tenant_id)

        # Check 2 / 3 — tool and operation whitelists.
        grant = await self._check_tool_and_operation(ev, facts, tenant_id)

        # Check 4 / 5 — parameter ceilings and approval thresholds.
        self._check_parameters(ev, facts, grant, tool_policy, approval, fingerprint, context)

        # Check 6 — memory trust (Day 3 trust evaluator is the authority).
        self._check_memory(ev, facts, tenant_id, tool_policy)

        return self._conclude(ev, facts, context, fingerprint, tool_policy, started)

    async def _check_agent(self, ev: _Eval, facts: ProposalFacts, tenant_id: str) -> None:
        try:
            agent = await _maybe_await(self._agents.get_agent(facts.agent_id, tenant_id))
        except Exception:  # noqa: BLE001
            ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.INDETERMINATE, ReasonCode.AGENT_DIRECTORY_UNAVAILABLE)
            return
        if agent is None or _get(agent, "tenant_id") != tenant_id:
            ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.BLOCK, ReasonCode.AGENT_NOT_REGISTERED)
            return
        status = _get(agent, "status")
        if status == "ACTIVE":
            ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.PASS)
        elif status == "ISOLATED":
            ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.BLOCK, ReasonCode.AGENT_ISOLATED)
        else:  # DEPRECATED, unknown, missing, malformed
            ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.BLOCK, ReasonCode.AGENT_NOT_ACTIVE)

        if hasattr(self._agents, "get_profile"):
            try:
                prof = await _maybe_await(self._agents.get_profile(facts.agent_id, tenant_id))
                if prof is not None:
                    p_stat = prof.get("status")
                    if p_stat in ("ISOLATED", "SUSPENDED", "REVOKED"):
                        ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.BLOCK, ReasonCode.AGENT_ISOLATED)
                    elif p_stat != "ACTIVE":
                        ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.BLOCK, ReasonCode.AGENT_NOT_ACTIVE)
            except Exception:
                ev.set(PolicyCheck.AGENT_STATUS, CheckOutcome.INDETERMINATE, ReasonCode.AGENT_DIRECTORY_UNAVAILABLE)

    async def _check_tool_and_operation(self, ev: _Eval, facts: ProposalFacts, tenant_id: str) -> Optional[ToolGrant]:
        try:
            grant = await _maybe_await(self._grants.get_tool_grant(tenant_id, facts.agent_id, facts.tool_name))
        except Exception:  # noqa: BLE001
            ev.set(PolicyCheck.TOOL_WHITELIST, CheckOutcome.INDETERMINATE, ReasonCode.TOOL_GRANT_UNAVAILABLE)
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.INDETERMINATE, ReasonCode.TOOL_GRANT_UNAVAILABLE)
            return None
        if grant is None:
            ev.set(PolicyCheck.TOOL_WHITELIST, CheckOutcome.BLOCK, ReasonCode.TOOL_NOT_ASSIGNED)
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.BLOCK, ReasonCode.OPERATION_DENIED)
            return None
        if not isinstance(grant, ToolGrant) or grant.tool_name != facts.tool_name:
            ev.set(PolicyCheck.TOOL_WHITELIST, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONFIG_INVALID)
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONFIG_INVALID)
            return None
        if grant.tool_registered is not True:
            ev.set(PolicyCheck.TOOL_WHITELIST, CheckOutcome.BLOCK, ReasonCode.TOOL_NOT_REGISTERED)
        else:
            ev.set(PolicyCheck.TOOL_WHITELIST, CheckOutcome.PASS)

        ops = _parse_operations(grant.allowed_operations)
        if ops is None:
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONFIG_INVALID)
        elif "*" in ops:
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.BLOCK,
                   ReasonCode.OPERATION_DENIED, ReasonCode.OPERATION_WILDCARD_NOT_PERMITTED)
        elif facts.operation in ops:
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.PASS)
        else:
            ev.set(PolicyCheck.OPERATION_WHITELIST, CheckOutcome.BLOCK, ReasonCode.OPERATION_DENIED)
        return grant

    def _check_parameters(self, ev, facts, grant, tool_policy, approval, fingerprint, context) -> None:
        if grant is None:
            # Without a valid grant there are no verified constraints: cannot pass.
            ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONSTRAINT_MISSING)
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONSTRAINT_MISSING)
            return
        parsed = _parse_constraints(grant.constraints)
        if parsed is None:
            ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONFIG_INVALID)
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.INDETERMINATE, ReasonCode.POLICY_CONFIG_INVALID)
            return
        missing = [k for k in tool_policy.mandatory_constraints if k not in parsed.keys_present]
        if missing:
            ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.BLOCK, ReasonCode.POLICY_CONSTRAINT_MISSING)

        # Check 4 — hard ceilings, minimums, allow-lists.
        ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.PASS)
        for name in sorted(parsed.numeric_params):
            value = _number(facts.parameters.get(name))
            if value is None:
                ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.BLOCK, ReasonCode.PARAMETER_INVALID)
                continue
            if name in parsed.maximum and value > parsed.maximum[name]:
                ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.BLOCK, ReasonCode.CEILING_EXCEEDED)
            if name in parsed.minimum and value < parsed.minimum[name]:
                ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.BLOCK, ReasonCode.PARAMETER_BELOW_MINIMUM)
        for name in sorted(parsed.allowed):
            value = facts.parameters.get(name)
            if type(value) is not str or value not in parsed.allowed[name]:
                ev.set(PolicyCheck.PARAMETER_CEILINGS, CheckOutcome.BLOCK, ReasonCode.DESTINATION_NOT_ALLOWED)

        # Check 5 — approval thresholds (threshold < value; hard ceiling handled above).
        needs_review = False
        for name in sorted(parsed.threshold):
            value = _number(facts.parameters.get(name))
            if value is None:
                ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.BLOCK, ReasonCode.PARAMETER_INVALID)
                continue
            if value > parsed.threshold[name]:
                needs_review = True
        if not needs_review:
            if approval is not None:
                problem = self._approval_problem(approval, fingerprint, context, facts.agent_id)
                if problem is not None:
                    ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.BLOCK, problem)
                    return
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.PASS)
            return
        if approval is None:
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.REVIEW, ReasonCode.APPROVAL_THRESHOLD_EXCEEDED)
            return
        problem = self._approval_problem(approval, fingerprint, context, facts.agent_id)
        if problem is None:
            ev.approval_id = approval.approval_id
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.PASS)
        else:
            ev.set(PolicyCheck.APPROVAL_THRESHOLD, CheckOutcome.BLOCK, problem)

    def _approval_problem(
        self,
        approval: Any,
        fingerprint: str,
        context: TenantContext,
        agent_id: Optional[str] = None,
    ) -> Optional[ReasonCode]:
        if not isinstance(approval, ApprovalEvidence):
            return ReasonCode.APPROVAL_INVALID
        if approval.tenant_id != context.tenant_id or approval.status != "APPROVED":
            return ReasonCode.APPROVAL_INVALID
        if not approval.approver_user_id:
            return ReasonCode.APPROVAL_INVALID
        if approval.consumed or (context.tenant_id, approval.approval_id) in self._consumed_approvals:
            return ReasonCode.APPROVAL_ALREADY_CONSUMED
        if approval.approver_user_id == context.user_id:
            return ReasonCode.APPROVAL_SELF_APPROVAL
        if agent_id is not None and approval.approver_user_id == agent_id:
            return ReasonCode.APPROVAL_SELF_APPROVAL
        if not isinstance(approval.expires_at, datetime) or approval.expires_at.tzinfo is None:
            return ReasonCode.APPROVAL_INVALID
        if self._clock() >= approval.expires_at:
            return ReasonCode.APPROVAL_EXPIRED
        if approval.proposal_fingerprint != fingerprint:
            return ReasonCode.APPROVAL_SCOPE_MISMATCH
        if approval.approver_role not in (Role.SECURITY_ANALYST.value, Role.TENANT_ADMIN.value):
            return ReasonCode.APPROVAL_INVALID
        return None

    def _check_memory(self, ev: _Eval, facts: ProposalFacts, tenant_id: str, tool_policy: ToolPolicy) -> None:
        if not facts.memory_refs:
            ev.memory_trust = "NOT_REFERENCED"
            if tool_policy.requires_memory_justification:
                ev.set(PolicyCheck.MEMORY_TRUST, CheckOutcome.BLOCK, ReasonCode.MEMORY_JUSTIFICATION_REQUIRED)
            else:
                ev.set(PolicyCheck.MEMORY_TRUST, CheckOutcome.PASS)
            return

        ev.set(PolicyCheck.MEMORY_TRUST, CheckOutcome.PASS)
        worst_rank, worst_label = -1, "TRUSTED"
        for ref in facts.memory_refs:
            try:
                assessment = self._trust.assess_for_action(tenant_id, ref.record_id, ref.version)
                if not isinstance(assessment, ActionMemoryAssessment) or assessment.record_id != ref.record_id:
                    raise TypeError("malformed trust assessment")
            except Exception:  # noqa: BLE001 — trust evaluator unavailable => BLOCK
                ev.memory.append(MemoryEvidence(ref.record_id, ref.version, None, None, None, False, None,
                                                (ReasonCode.MEMORY_TRUST_UNAVAILABLE.value,)))
                ev.set(PolicyCheck.MEMORY_TRUST, CheckOutcome.INDETERMINATE,
                       ReasonCode.REFERENCED_UNTRUSTED_MEMORY, ReasonCode.MEMORY_TRUST_UNAVAILABLE)
                worst_rank, worst_label = 99, "UNAVAILABLE"
                continue

            codes = list(assessment.reason_codes) if isinstance(assessment.reason_codes, tuple) else \
                [ReasonCode.MEMORY_TRUST_UNAVAILABLE.value]
            if (
                self._config.enforce_memory_agent_binding
                and assessment.agent_id is not None
                and assessment.agent_id != facts.agent_id
            ):
                codes.append(ReasonCode.MEMORY_SCOPE_VIOLATION.value)
            # Eligibility must be positively evidenced, never inferred from an absence of
            # reason codes (Day 7 hardening: a faulty or substituted trust implementation
            # returning eligible=True with missing evidence must not pass).
            if assessment.eligible is True and not codes and not _assessment_fully_evidenced(assessment):
                codes.append(ReasonCode.MEMORY_TRUST_EVIDENCE_INCOMPLETE.value)
            eligible = assessment.eligible is True and not codes
            ev.memory.append(MemoryEvidence(
                record_id=ref.record_id, pinned_version=ref.version, version=assessment.version,
                checksum=assessment.checksum, effective_state=assessment.effective_state, eligible=eligible,
                trust_decision_id=assessment.trust_decision_id, reason_codes=tuple(codes),
            ))
            if not eligible:
                ev.set(PolicyCheck.MEMORY_TRUST, CheckOutcome.BLOCK,
                       ReasonCode.REFERENCED_UNTRUSTED_MEMORY, *(codes or ["MEMORY_TRUST_EVIDENCE_MISSING"]))
            if not assessment.found:
                rank, label = 98, "NOT_FOUND"
            elif assessment.effective_state in _STATE_RANK:
                rank, label = _STATE_RANK[assessment.effective_state], assessment.effective_state
                if label == "TRUSTED" and not eligible:
                    rank, label = 1, "INELIGIBLE"
            else:
                rank, label = 97, "UNKNOWN"
            if rank > worst_rank:
                worst_rank, worst_label = rank, label
        ev.memory_trust = worst_label

    def _conclude(self, ev, facts, context, fingerprint, tool_policy, started) -> PolicyDecision:
        results = [ev.checks.get(c) for c in MANDATORY_CHECKS]
        if any(r is None for r in results):
            outcome, codes = PolicyOutcome.BLOCK, [ReasonCode.RULESET_INCOMPLETE.value]
        else:
            outcomes = {r.outcome for r in results}
            all_codes = [code for r in results for code in r.reason_codes]
            if CheckOutcome.BLOCK.value in outcomes or CheckOutcome.INDETERMINATE.value in outcomes:
                outcome = PolicyOutcome.BLOCK
                blocking = [code for r in results if r.outcome in (CheckOutcome.BLOCK.value, CheckOutcome.INDETERMINATE.value)
                            for code in r.reason_codes]
                codes = blocking or [ReasonCode.INTERNAL_EVALUATION_ERROR.value]
            elif CheckOutcome.REVIEW.value in outcomes:
                if tool_policy.review_permitted:
                    outcome, codes = PolicyOutcome.REQUIRES_APPROVAL, all_codes
                else:
                    outcome, codes = PolicyOutcome.BLOCK, all_codes + [ReasonCode.REVIEW_NOT_PERMITTED.value]
            elif outcomes == {CheckOutcome.PASS.value}:
                outcome, codes = PolicyOutcome.ALLOW, [ReasonCode.ALL_CHECKS_PASSED.value]
            else:
                outcome, codes = PolicyOutcome.BLOCK, [ReasonCode.INTERNAL_EVALUATION_ERROR.value]
        codes = list(dict.fromkeys(codes))
        return self._build(
            outcome=outcome, codes=codes, ev=ev, facts=facts, context=context,
            fingerprint=fingerprint, started=started, status="COMPLETE",
        )

    # -- construction helpers ---------------------------------------------------

    def _build(self, *, outcome, codes, ev, facts, context, fingerprint, started, status) -> PolicyDecision:
        result = {
            PolicyOutcome.ALLOW: PolicyResult.PERMITTED,
            PolicyOutcome.REQUIRES_APPROVAL: PolicyResult.ELEVATED,
        }.get(outcome, PolicyResult.DENIED)
        return PolicyDecision(
            decision_id=str(uuid.uuid4()),
            outcome=outcome,
            policy_result=result,
            memory_trust=ev.memory_trust if ev else "UNAVAILABLE",
            reason_codes=tuple(codes),
            reasons=tuple(dict.fromkeys(_HUMAN_REASONS.get(c, c) for c in codes if c in _HUMAN_REASONS))
            or ("The proposed action was blocked by security policy.",),
            checks=tuple(ev.checks[c] for c in MANDATORY_CHECKS if ev and c in ev.checks) if ev else (),
            memory_evidence=tuple(ev.memory) if ev else (),
            policy_version=POLICY_VERSION,
            evaluated_at=self._clock(),
            evaluation_status=status,
            execution_eligible=(outcome is PolicyOutcome.ALLOW and status == "COMPLETE"),
            proposal_fingerprint=fingerprint,
            tenant_id=getattr(context, "tenant_id", None) if _valid_context(context) else None,
            principal_id=getattr(context, "user_id", None) if _valid_context(context) else None,
            principal_role=ev.principal_role if ev else None,
            agent_id=facts.agent_id if facts else None,
            action_id=facts.action_id if facts else None,
            tool_name=facts.tool_name if facts else None,
            operation=facts.operation if facts else None,
            idempotency_key=facts.idempotency_key if facts else None,
            trace_id=facts.trace_id if facts else None,
            approval_id=ev.approval_id if ev else None,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    def _failure(self, proposal, context, started, status: str, code: ReasonCode) -> PolicyDecision:
        facts = None
        try:
            facts = normalize_proposal(proposal)
        except Exception:  # noqa: BLE001
            facts = None
        fingerprint = None
        if facts is not None and _valid_context(context):
            try:
                fingerprint = proposal_fingerprint(facts, context.tenant_id, context.user_id)
            except Exception:  # noqa: BLE001
                fingerprint = None
        ev = _Eval(memory_trust="UNAVAILABLE" if code is not ReasonCode.POLICY_INPUT_INVALID else "NOT_REFERENCED")
        return self._build(outcome=PolicyOutcome.BLOCK, codes=[code.value], ev=ev, facts=facts, context=context,
                           fingerprint=fingerprint, started=started, status=status)

    def _log(self, decision: PolicyDecision) -> None:
        logger.info(
            "Policy decision %s: outcome=%s status=%s tenant=%s agent=%s tool=%s op=%s memory_trust=%s codes=%s elapsed_ms=%.2f",
            decision.decision_id, decision.outcome.value, decision.evaluation_status, decision.tenant_id,
            decision.agent_id, decision.tool_name, decision.operation, decision.memory_trust,
            ",".join(decision.reason_codes), decision.elapsed_ms,
        )

    # -- grant registry (used only by ProtectedExecutionGuard) ------------------

    def _consume_issued(self, decision: PolicyDecision) -> Optional[ReasonCode]:
        issued = self._issued.pop(decision.decision_id, None)
        if issued is None or issued != decision:
            return ReasonCode.DECISION_NOT_ISSUED_BY_ENGINE
        return None

    def _is_issued(self, decision: PolicyDecision) -> bool:
        issued = self._issued.get(decision.decision_id)
        return issued is not None and issued == decision

    def _reserve_execution(self, decision: PolicyDecision) -> Optional[ReasonCode]:
        """Atomically (no await) refuse or record this dispatch in the execution ledger.

        Fails closed when the key is missing: an executable decision always carries tenant and
        idempotency key, so a missing value means an inconsistent decision.
        """
        tenant, idem = decision.tenant_id, decision.idempotency_key
        if not (isinstance(tenant, str) and tenant and isinstance(idem, str) and idem):
            return ReasonCode.DECISION_NOT_EXECUTABLE
        key = (tenant, idem)
        approval_key = (tenant, decision.approval_id) if decision.approval_id else None
        if key in self._executed_keys:
            return ReasonCode.EXECUTION_ALREADY_PERFORMED
        if approval_key is not None and approval_key in self._consumed_approvals:
            return ReasonCode.APPROVAL_ALREADY_CONSUMED
        self._executed_keys[key] = decision.decision_id
        if approval_key is not None:
            self._consumed_approvals[approval_key] = decision.decision_id
        for ledger in (self._executed_keys, self._consumed_approvals):
            while len(ledger) > MAX_EXECUTION_LEDGER:
                ledger.popitem(last=False)
        return None


# =============================================================================
# 6. Protected execution guard (policy enforcement point for adapters)
# =============================================================================

@dataclass(frozen=True)
class ExecutionGrant:
    grant_id: str
    decision_id: str
    tenant_id: str
    agent_id: str
    tool_name: str
    operation: str
    proposal_fingerprint: str
    issued_at: datetime


@dataclass(frozen=True)
class ExecutionOutcome:
    executed: bool
    status: str                      # EXECUTED | NOT_EXECUTED | PENDING_APPROVAL | FAILED | UNKNOWN
    reason_codes: Tuple[str, ...]
    decision: Optional[PolicyDecision]
    revalidation: Optional[PolicyDecision] = None
    grant: Optional[ExecutionGrant] = None
    result: Any = None
    error_type: Optional[str] = None


Executor = Callable[[ExecutionGrant], Awaitable[Any]]
PersistDecision = Callable[[PolicyDecision], Awaitable[Any]]


@dataclass(frozen=True)
class MandatoryControl:
    """A mandatory pre-execution security control (e.g. Redis idempotency lock, replay
    check, distributed rate limit). ``check()`` must return exactly ``True`` to pass;
    False, None, any other value, or an exception => the adapter is not invoked.

    The guard owns no Redis client: controls wrap the owners' existing interfaces
    (M1/M7 ``RateLimiterProtocol``, M7 lock service).
    """

    name: str
    check: Callable[[], Awaitable[Any]]


def rate_limit_control(limiter: Any, key: str, max_requests: int, window_seconds: int,
                       name: str = "distributed_rate_limit") -> MandatoryControl:
    """Wrap M1's ``RateLimiterProtocol`` as a mandatory control (strict result validation)."""
    from backend.app.core.dependencies import RateLimitResult

    async def check() -> bool:
        result = await limiter.check_rate_limit(key, max_requests, window_seconds)
        return isinstance(result, RateLimitResult) and result.allowed is True

    return MandatoryControl(name=name, check=check)


def lock_control(acquire: Callable[[], Awaitable[Any]], name: str = "idempotency_lock") -> MandatoryControl:
    """Wrap a lock/replay acquisition (e.g. Redis ``SET key NX EX``) that returns True when acquired."""
    async def check() -> bool:
        return (await acquire()) is True

    return MandatoryControl(name=name, check=check)


def _memory_snapshot(decision: PolicyDecision) -> Tuple[Tuple[Any, ...], ...]:
    return tuple(
        (m.record_id, m.version, m.checksum, m.effective_state, m.trust_decision_id) for m in decision.memory_evidence
    )


class ProtectedExecutionGuard:
    """Calls a protected adapter only when every enforcement condition holds.

    1. ``decision`` is an executable ALLOW issued by *this* engine (not forged, not reused).
    1b. Every ``mandatory_controls`` entry returns exactly True (Redis lock / replay /
        rate limit); a denial, invalid result or exception stops here.
    2. ``persist_decision(decision)`` completes without raising and without returning
       ``False`` (decision recorded before any side effect).
    3. A fresh evaluation of the same proposal is ALLOW with the same fingerprint and the
       same memory versions, checksums, states and trust evidence (TOCTOU protection).
    4. The grant is consumed exactly once, then ``executor(grant)`` is awaited.

    Any other path — BLOCK, REQUIRES_APPROVAL, unknown objects, exceptions — returns
    without calling ``executor``.
    """

    def __init__(self, engine: PolicyEngine) -> None:
        if not isinstance(engine, PolicyEngine):
            raise PolicyConfigurationError("ProtectedExecutionGuard requires a PolicyEngine.")
        self._engine = engine

    async def execute(
        self,
        decision: Any,
        proposal: Any,
        context: Optional[TenantContext],
        *,
        persist_decision: PersistDecision,
        executor: Executor,
        approval: Optional[ApprovalEvidence] = None,
        mandatory_controls: Sequence[MandatoryControl] = (),
    ) -> ExecutionOutcome:
        try:
            return await self._execute(decision, proposal, context, persist_decision, executor, approval,
                                       mandatory_controls)
        except Exception:  # noqa: BLE001 — guard failure never executes
            logger.exception("Execution guard error; adapter not invoked (fail closed).")
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.INTERNAL_EVALUATION_ERROR.value,),
                                    decision if isinstance(decision, PolicyDecision) else None)

    async def _execute(self, decision, proposal, context, persist_decision, executor, approval,
                       mandatory_controls=()) -> ExecutionOutcome:
        if isinstance(decision, PolicyDecision) and decision.outcome is PolicyOutcome.REQUIRES_APPROVAL:
            return ExecutionOutcome(False, "PENDING_APPROVAL", decision.reason_codes, decision)
        if not decision_is_executable(decision):
            codes = decision.reason_codes if isinstance(decision, PolicyDecision) else ()
            return ExecutionOutcome(False, "NOT_EXECUTED", tuple(codes) + (ReasonCode.DECISION_NOT_EXECUTABLE.value,),
                                    decision if isinstance(decision, PolicyDecision) else None)
        if not self._engine._is_issued(decision):
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.DECISION_NOT_ISSUED_BY_ENGINE.value,), decision)

        # 1b. Mandatory pre-execution controls (Redis lock / replay / rate limit): exact True only.
        if isinstance(mandatory_controls, (str, bytes)) or not isinstance(mandatory_controls, (list, tuple)):
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.MANDATORY_CONTROL_UNAVAILABLE.value,), decision)
        for control in mandatory_controls:
            if not isinstance(control, MandatoryControl):
                return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.MANDATORY_CONTROL_UNAVAILABLE.value,), decision)
            try:
                passed = await control.check()
            except Exception as exc:  # noqa: BLE001 — unavailable control never means permission
                logger.error("Mandatory control %s unavailable (%s); adapter not invoked.", control.name,
                             type(exc).__name__)
                return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.MANDATORY_CONTROL_UNAVAILABLE.value,),
                                        decision)
            if passed is not True:
                logger.warning("Mandatory control %s did not pass; adapter not invoked.", control.name)
                return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.MANDATORY_CONTROL_DENIED.value,), decision)

        # 2. Decision must be durably recorded before any side effect.
        try:
            persisted = await persist_decision(decision)
        except Exception as exc:  # noqa: BLE001
            logger.error("Decision persistence failed (%s); adapter not invoked.", type(exc).__name__)
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.AUDIT_PERSISTENCE_FAILED.value,), decision)
        if persisted is False:
            logger.error("Decision persistence reported failure; adapter not invoked.")
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.AUDIT_PERSISTENCE_FAILED.value,), decision)

        # 3. Pre-execution revalidation against current state.
        fresh = await self._engine._evaluate(proposal, context, approval, register=False)
        if (
            not decision_is_executable(fresh)
            or fresh.proposal_fingerprint != decision.proposal_fingerprint
            or fresh.tenant_id != decision.tenant_id
            or _memory_snapshot(fresh) != _memory_snapshot(decision)
        ):
            self._engine._issued.pop(decision.decision_id, None)  # grant revoked
            codes = (ReasonCode.PRE_EXECUTION_REVALIDATION_FAILED.value,) + tuple(
                c for c in fresh.reason_codes if c != ReasonCode.ALL_CHECKS_PASSED.value)
            return ExecutionOutcome(False, "NOT_EXECUTED", codes, decision, revalidation=fresh)

        # 4. Single use.
        problem = self._engine._consume_issued(decision)
        if problem is not None:
            return ExecutionOutcome(False, "NOT_EXECUTED", (ReasonCode.EXECUTION_GRANT_ALREADY_USED.value,), decision)
        # 4b. One dispatch per idempotency key and per approval (M4-F1). Same synchronous step as
        # the grant consumption, before any await, so concurrent duplicates cannot both pass.
        replay = self._engine._reserve_execution(decision)
        if replay is not None:
            return ExecutionOutcome(False, "NOT_EXECUTED", (replay.value,), decision)

        grant = ExecutionGrant(
            grant_id=str(uuid.uuid4()), decision_id=decision.decision_id, tenant_id=decision.tenant_id or "",
            agent_id=decision.agent_id or "", tool_name=decision.tool_name or "", operation=decision.operation or "",
            proposal_fingerprint=decision.proposal_fingerprint or "", issued_at=self._engine._clock(),
        )
        try:
            result = await executor(grant)
        except (asyncio.TimeoutError, TimeoutError):
            return ExecutionOutcome(True, "UNKNOWN", (ReasonCode.ADAPTER_EXECUTION_FAILED.value,), decision,
                                    revalidation=fresh, grant=grant, error_type="TimeoutError")
        except Exception as exc:  # noqa: BLE001 — side effect may or may not have occurred
            return ExecutionOutcome(True, "FAILED", (ReasonCode.ADAPTER_EXECUTION_FAILED.value,), decision,
                                    revalidation=fresh, grant=grant, error_type=type(exc).__name__)
        return ExecutionOutcome(True, "EXECUTED", (ReasonCode.ALL_CHECKS_PASSED.value,), decision,
                                revalidation=fresh, grant=grant, result=result)


# =============================================================================
# 7. Helpers
# =============================================================================

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _assessment_fully_evidenced(a: ActionMemoryAssessment) -> bool:
    """A TRUSTED-eligible assessment must carry complete, well-formed evidence."""
    return (
        a.found is True
        and a.effective_state == "TRUSTED"
        and type(a.version) is int and a.version >= 1
        and type(a.checksum) is str and bool(_HEX64.fullmatch(a.checksum))
        and type(a.trust_decision_id) is str and bool(a.trust_decision_id.strip())
    )


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _valid_context(context: Any) -> bool:
    return (
        isinstance(context, TenantContext)
        and context.is_active is True
        and type(context.tenant_id) is str and bool(context.tenant_id.strip())
        and type(context.user_id) is str and bool(context.user_id.strip())
    )


def _parse_operations(value: Any) -> Optional[FrozenSet[str]]:
    """Parse ``allowed_operations`` (comma-separated string per Doc 05, or a sequence)."""
    if type(value) is str:
        items = [v.strip() for v in value.split(",")]
    elif isinstance(value, (list, tuple, frozenset, set)):
        items = list(value)
    else:
        return None
    if not all(type(i) is str for i in items):
        return None
    return frozenset(i for i in items if i)


@dataclass(frozen=True)
class _Constraints:
    maximum: Mapping[str, Decimal]
    minimum: Mapping[str, Decimal]
    threshold: Mapping[str, Decimal]
    allowed: Mapping[str, FrozenSet[str]]
    keys_present: FrozenSet[str]

    @property
    def numeric_params(self) -> FrozenSet[str]:
        return frozenset(self.maximum) | frozenset(self.minimum)


def _parse_constraints(constraints: Any) -> Optional[_Constraints]:
    """Parse ``constraints_json``. Unknown keys or invalid values => None (fail closed)."""
    if not isinstance(constraints, Mapping):
        return None
    maximum: Dict[str, Decimal] = {}
    minimum: Dict[str, Decimal] = {}
    threshold: Dict[str, Decimal] = {}
    allowed: Dict[str, FrozenSet[str]] = {}
    for key, raw in constraints.items():
        match = _CONSTRAINT_KEY.fullmatch(key) if type(key) is str else None
        if match is None:
            return None
        kind, param = match.group(1), match.group(2)
        if kind == "allowed":
            if not isinstance(raw, (list, tuple)) or not raw or not all(type(v) is str and v for v in raw):
                return None
            allowed[param] = frozenset(raw)
            continue
        number = _number(raw)
        if number is None or number < 0:
            return None
        {"max": maximum, "min": minimum, "approval_threshold": threshold}[kind][param] = number
    for param, limit in threshold.items():
        if param in maximum and limit >= maximum[param]:
            return None  # threshold must sit below the hard ceiling
    return _Constraints(maximum, minimum, threshold, allowed, frozenset(constraints.keys()))


def _number(value: Any) -> Optional[Decimal]:
    """Strict numeric parse: int/float/Decimal only (no bool, no strings), finite."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    try:
        number = value if isinstance(value, Decimal) else Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite():
        return None
    return number
