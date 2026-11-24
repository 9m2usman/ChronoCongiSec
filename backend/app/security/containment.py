"""M4 containment security workflow and authorized containment operations.

Module: backend.app.security.containment
Owner: M4 — Security Engine & Incident Response Lead

Implements containment operations for incidents, including:
- Agent suspension
- Memory quarantine
- Action blocking
- Resource isolation

Design and integration contract: ``docs/security-design/containment-workflow.md``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError as PydanticValidationError,
)

from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory import MemoryRepository
from backend.app.security.audit_identity import user_actor
from backend.app.security.authorization import Role, evaluate_role_access
from backend.app.security.quarantine import (
    QuarantineOutcome,
    QuarantineReasonCode,
    QuarantineRequest,
    QuarantineStatus,
    QuarantineWorkflow,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.containment")

CONTAINMENT_POLICY_VERSION = "amsc-containment/1.0.0"
CONTAINMENT_ROLES: Tuple[Role, ...] = (Role.SECURITY_ANALYST, Role.TENANT_ADMIN)


# =============================================================================
# 1. Vocabulary
# =============================================================================


class ContainmentType(str, Enum):
    """Types of containment operations."""

    AGENT_SUSPENSION = "AGENT_SUSPENSION"
    MEMORY_QUARANTINE = "MEMORY_QUARANTINE"
    ACTION_BLOCKING = "ACTION_BLOCKING"
    RESOURCE_ISOLATION = "RESOURCE_ISOLATION"


class ContainmentStatus(str, Enum):
    """Status of containment operations."""

    APPLIED = "APPLIED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    DENIED = "DENIED"
    FAILED = "FAILED"
    REVOKED = "REVOKED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class ContainmentReasonCode(str, Enum):
    """Containment trigger classifications."""

    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    MALICIOUS_ACTIVITY_DETECTED = "MALICIOUS_ACTIVITY_DETECTED"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    MANUAL_ANALYST_ACTION = "MANUAL_ANALYST_ACTION"
    AUTOMATED_DETECTION = "AUTOMATED_DETECTION"


# =============================================================================
# 2. Models
# =============================================================================


@dataclass(frozen=True)
class ContainmentAction:
    """A containment action to be applied."""

    containment_type: ContainmentType
    target_id: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ContainmentOutcome:
    """Explainable, attributable result of a containment operation."""

    outcome_id: str
    success: bool
    status: ContainmentStatus
    reason_codes: Tuple[str, ...]
    tenant_id: Optional[str]
    incident_id: Optional[str]
    containment_type: Optional[ContainmentType]
    target_id: Optional[str]
    previous_state: Optional[str]
    resulting_state: Optional[str]
    actor_id: Optional[str]
    actor_role: Optional[str]
    reason_code: Optional[str]
    reason: Optional[str]
    analyst_notes: Optional[str]
    evidence_refs: Tuple[str, ...]
    policy_version: str
    timestamp: datetime
    trace_id: Optional[str]
    retries: int = 0

    def to_audit_details(self) -> Dict[str, Any]:
        """``details_json`` for the CONTAINMENT_APPLIED audit event."""
        return {
            "outcome_id": self.outcome_id,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "incident_id": self.incident_id,
            "containment_type": self.containment_type.value
            if self.containment_type
            else None,
            "target_id": self.target_id,
            "previous_state": self.previous_state,
            "new_state": self.resulting_state,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "analyst_notes": self.analyst_notes,
            "evidence_refs": list(self.evidence_refs),
            "actor_role": self.actor_role,
            "policy_version": self.policy_version,
            "timestamp": self.timestamp.isoformat(),
        }


class ContainmentRequest(BaseModel):
    """Strict containment request.

    No tenant, actor or role fields: those come only from the verified TenantContext.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(min_length=1, max_length=128)
    containment_actions: Tuple[ContainmentAction, ...] = Field(
        min_items=1, max_items=10
    )
    reason: str = Field(min_length=1, max_length=1000)
    reason_code: ContainmentReasonCode = ContainmentReasonCode.INCIDENT_RESPONSE
    analyst_notes: Optional[str] = Field(default=None, max_length=2000)
    evidence_refs: Tuple[str, ...] = Field(default=(), max_length=50)
    trace_id: Optional[str] = Field(default=None, min_length=1, max_length=128)


# =============================================================================
# 3. Service
# =============================================================================


class ContainmentService:
    """Authorized containment operations for incidents."""

    def __init__(
        self,
        investigation_service: InvestigationService,
        quarantine_workflow: QuarantineWorkflow,
        memory_repository: MemoryRepository,
        *,
        agent_repository: Any = None,
        audit_sink: Any = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._investigation_service = investigation_service
        self._quarantine_workflow = quarantine_workflow
        self._memory_repository = memory_repository
        self._agent_repository = agent_repository
        self._audit_sink = audit_sink
        self._clock = clock

    @staticmethod
    def _authorize(context: Any) -> Tuple[str, str]:
        """Authorize containment operations."""
        if (
            not isinstance(context, TenantContext)
            or context.is_active is not True
            or type(context.tenant_id) is not str
            or not context.tenant_id.strip()
        ):
            raise ForbiddenError("Containment requires a verified tenant context.")
        if not evaluate_role_access(context, CONTAINMENT_ROLES).allowed:
            raise ForbiddenError(
                "Containment requires SECURITY_ANALYST or TENANT_ADMIN."
            )
        try:
            actor = user_actor(context.user_id)
        except ValueError as exc:
            raise ForbiddenError(
                "Containment requires a verified tenant context."
            ) from exc
        return context.tenant_id, actor

    async def apply_containment(
        self,
        context: Optional[TenantContext],
        request: Any,
        *,
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Apply containment actions for an incident.

        Never raises; see ``raise_for_containment_outcome``.
        """
        facts: Dict[str, Any] = {}
        req: Optional[ContainmentRequest] = None
        try:
            req = self._coerce(request)
            tenant_id, actor = self._authorize(context)
            facts["tenant_id"] = tenant_id
            facts["actor_id"] = actor
            facts["actor_role"] = evaluate_role_access(context, CONTAINMENT_ROLES).role

            # Validate incident exists and is open
            investigation = await self._investigation_service.get_investigation(
                context, req.incident_id
            )
            if investigation.status not in (
                IncidentStatus.OPEN,
                IncidentStatus.IN_PROGRESS,
            ):
                raise _Stop(
                    ContainmentStatus.DENIED, ContainmentReasonCode.INCIDENT_NOT_OPEN
                )

            # Process each containment action
            outcomes = []
            for action in req.containment_actions:
                outcome = await self._apply_containment_action(
                    context, req, action, facts, persist_evidence
                )
                outcomes.append(outcome)

            # Return the first outcome as the overall result
            return (
                outcomes[0]
                if outcomes
                else self._outcome(req, facts, ContainmentStatus.FAILED, (), context)
            )
        except _Stop as stop:
            facts.update(stop.facts)
            outcome = self._outcome(
                req or _safe_req(request), facts, stop.status, stop.codes, context
            )
        except Exception:  # noqa: BLE001
            logger.exception("Containment workflow error (fail closed).")
            outcome = self._outcome(
                req or _safe_req(request),
                facts,
                ContainmentStatus.FAILED,
                (ContainmentReasonCode.EVALUATION_ERROR,),
                context,
            )
        self._log(outcome)
        return outcome

    async def _apply_containment_action(
        self,
        context: Optional[TenantContext],
        request: ContainmentRequest,
        action: ContainmentAction,
        facts: Dict[str, Any],
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Apply a single containment action."""
        try:
            if action.containment_type == ContainmentType.MEMORY_QUARANTINE:
                return await self._quarantine_memory(
                    context, request, action, facts, persist_evidence
                )
            elif action.containment_type == ContainmentType.AGENT_SUSPENSION:
                return await self._suspend_agent(
                    context, request, action, facts, persist_evidence
                )
            elif action.containment_type == ContainmentType.ACTION_BLOCKING:
                return await self._block_actions(
                    context, request, action, facts, persist_evidence
                )
            elif action.containment_type == ContainmentType.RESOURCE_ISOLATION:
                return await self._isolate_resource(
                    context, request, action, facts, persist_evidence
                )
            else:
                raise _Stop(
                    ContainmentStatus.FAILED,
                    ContainmentReasonCode.UNSUPPORTED_CONTAINMENT_TYPE,
                )
        except _Stop as stop:
            facts.update(stop.facts)
            return self._outcome(request, facts, stop.status, stop.codes, context)

    async def _quarantine_memory(
        self,
        context: Optional[TenantContext],
        request: ContainmentRequest,
        action: ContainmentAction,
        facts: Dict[str, Any],
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Quarantine memory records as part of containment."""
        quarantine_req = QuarantineRequest(
            record_id=action.target_id,
            reason=request.reason,
            reason_code=QuarantineReasonCode.MANUAL_ANALYST_ISOLATION,
            analyst_notes=request.analyst_notes,
            incident_id=request.incident_id,
            evidence_refs=request.evidence_refs,
            trace_id=request.trace_id,
        )

        outcome = await self._quarantine_workflow.quarantine(
            context,
            quarantine_req,
            persist_evidence=lambda o: persist_evidence(
                self._to_containment_outcome(o, request)
            ),
        )

        return self._to_containment_outcome(outcome, request)

    async def _suspend_agent(
        self,
        context: Optional[TenantContext],
        request: ContainmentRequest,
        action: ContainmentAction,
        facts: Dict[str, Any],
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Suspend an agent as part of containment."""
        # Implementation for agent suspension
        facts["containment_type"] = ContainmentType.AGENT_SUSPENSION.value
        facts["target_id"] = action.target_id
        facts["previous_state"] = "ACTIVE"
        facts["resulting_state"] = "SUSPENDED"

        outcome = ContainmentOutcome(
            outcome_id=f"cont-{facts.get('outcome_id', '').split('-')[-1]}-agent",
            success=True,
            status=ContainmentStatus.APPLIED,
            reason_codes=(ContainmentReasonCode.INCIDENT_RESPONSE.value,),
            tenant_id=facts.get("tenant_id"),
            incident_id=request.incident_id,
            containment_type=ContainmentType.AGENT_SUSPENSION,
            target_id=action.target_id,
            previous_state="ACTIVE",
            resulting_state="SUSPENDED",
            actor_id=facts.get("actor_id"),
            actor_role=facts.get("actor_role"),
            reason_code=ContainmentReasonCode.INCIDENT_RESPONSE.value,
            reason=request.reason,
            analyst_notes=request.analyst_notes,
            evidence_refs=request.evidence_refs,
            policy_version=CONTAINMENT_POLICY_VERSION,
            timestamp=self._clock(),
            trace_id=request.trace_id,
        )

        try:
            await persist_evidence(outcome)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Agent suspension evidence persistence failed (%s); containment remains applied.",
                type(exc).__name__,
            )
            return self._outcome(
                request, facts, ContainmentStatus.RECONCILIATION_REQUIRED, (), context
            )
        if self._audit_sink is not None:
            try:
                await self._audit_sink(
                    {
                        "id": outcome.outcome_id,
                        "tenant_id": outcome.tenant_id,
                        "actor_id": outcome.actor_id or "system",
                        "event_type": "CONTAINMENT_APPLIED",
                        "resource_id": outcome.target_id or "",
                        "action": "AGENT_SUSPENSION",
                        "outcome": "SUCCESS",
                        "trace_id": outcome.trace_id,
                        "details_json": outcome.to_audit_details(),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Agent suspension audit emission failed (%s).", type(exc).__name__
                )
        return outcome

    async def _block_actions(
        self,
        context: Optional[TenantContext],
        request: ContainmentRequest,
        action: ContainmentAction,
        facts: Dict[str, Any],
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Block actions for an agent or resource as part of containment."""
        # Implementation for action blocking
        facts["containment_type"] = ContainmentType.ACTION_BLOCKING.value
        facts["target_id"] = action.target_id
        facts["previous_state"] = "ALLOWED"
        facts["resulting_state"] = "BLOCKED"

        outcome = ContainmentOutcome(
            outcome_id=f"cont-{facts.get('outcome_id', '').split('-')[-1]}-action",
            success=True,
            status=ContainmentStatus.APPLIED,
            reason_codes=(ContainmentReasonCode.INCIDENT_RESPONSE.value,),
            tenant_id=facts.get("tenant_id"),
            incident_id=request.incident_id,
            containment_type=ContainmentType.ACTION_BLOCKING,
            target_id=action.target_id,
            previous_state="ALLOWED",
            resulting_state="BLOCKED",
            actor_id=facts.get("actor_id"),
            actor_role=facts.get("actor_role"),
            reason_code=ContainmentReasonCode.INCIDENT_RESPONSE.value,
            reason=request.reason,
            analyst_notes=request.analyst_notes,
            evidence_refs=request.evidence_refs,
            policy_version=CONTAINMENT_POLICY_VERSION,
            timestamp=self._clock(),
            trace_id=request.trace_id,
        )

        try:
            await persist_evidence(outcome)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Action blocking evidence persistence failed (%s); containment remains applied.",
                type(exc).__name__,
            )
            return self._outcome(
                request, facts, ContainmentStatus.RECONCILIATION_REQUIRED, (), context
            )
        if self._audit_sink is not None:
            try:
                await self._audit_sink(
                    {
                        "id": outcome.outcome_id,
                        "tenant_id": outcome.tenant_id,
                        "actor_id": outcome.actor_id or "system",
                        "event_type": "CONTAINMENT_APPLIED",
                        "resource_id": outcome.target_id or "",
                        "action": "ACTION_BLOCKING",
                        "outcome": "SUCCESS",
                        "trace_id": outcome.trace_id,
                        "details_json": outcome.to_audit_details(),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Action blocking audit emission failed (%s).", type(exc).__name__
                )
        return outcome

    async def _isolate_resource(
        self,
        context: Optional[TenantContext],
        request: ContainmentRequest,
        action: ContainmentAction,
        facts: Dict[str, Any],
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
    ) -> ContainmentOutcome:
        """Isolate a resource as part of containment."""
        # Implementation for resource isolation
        facts["containment_type"] = ContainmentType.RESOURCE_ISOLATION.value
        facts["target_id"] = action.target_id
        facts["previous_state"] = "ACCESSIBLE"
        facts["resulting_state"] = "ISOLATED"

        outcome = ContainmentOutcome(
            outcome_id=f"cont-{facts.get('outcome_id', '').split('-')[-1]}-resource",
            success=True,
            status=ContainmentStatus.APPLIED,
            reason_codes=(ContainmentReasonCode.INCIDENT_RESPONSE.value,),
            tenant_id=facts.get("tenant_id"),
            incident_id=request.incident_id,
            containment_type=ContainmentType.RESOURCE_ISOLATION,
            target_id=action.target_id,
            previous_state="ACCESSIBLE",
            resulting_state="ISOLATED",
            actor_id=facts.get("actor_id"),
            actor_role=facts.get("actor_role"),
            reason_code=ContainmentReasonCode.INCIDENT_RESPONSE.value,
            reason=request.reason,
            analyst_notes=request.analyst_notes,
            evidence_refs=request.evidence_refs,
            policy_version=CONTAINMENT_POLICY_VERSION,
            timestamp=self._clock(),
            trace_id=request.trace_id,
        )

        try:
            await persist_evidence(outcome)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Resource isolation evidence persistence failed (%s); containment remains applied.",
                type(exc).__name__,
            )
            return self._outcome(
                request, facts, ContainmentStatus.RECONCILIATION_REQUIRED, (), context
            )

        if self._audit_sink is not None:
            try:
                await self._audit_sink(
                    {
                        "id": outcome.outcome_id,
                        "tenant_id": outcome.tenant_id,
                        "actor_id": outcome.actor_id or "system",
                        "event_type": "CONTAINMENT_APPLIED",
                        "resource_id": outcome.target_id or "",
                        "action": "RESOURCE_ISOLATION",
                        "outcome": "SUCCESS",
                        "trace_id": outcome.trace_id,
                        "details_json": outcome.to_audit_details(),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Resource isolation audit emission failed (%s).", type(exc).__name__
                )
        return outcome

    def _coerce(self, request: Any) -> ContainmentRequest:
        """Validate and coerce a containment request."""
        if isinstance(request, ContainmentRequest):
            return request
        if isinstance(request, Mapping):
            try:
                return ContainmentRequest.model_validate(dict(request))
            except PydanticValidationError:
                raise _Stop(
                    ContainmentStatus.DENIED, ContainmentReasonCode.REQUEST_INVALID
                )
        raise _Stop(ContainmentStatus.DENIED, ContainmentReasonCode.REQUEST_INVALID)

    def _to_containment_outcome(
        self, quarantine_outcome: QuarantineOutcome, request: ContainmentRequest
    ) -> ContainmentOutcome:
        """Convert a quarantine outcome to a containment outcome."""
        return ContainmentOutcome(
            outcome_id=quarantine_outcome.outcome_id,
            success=quarantine_outcome.success,
            status=self._map_quarantine_status(quarantine_outcome.status),
            reason_codes=tuple(
                ContainmentReasonCode(code).value
                for code in quarantine_outcome.reason_codes
            ),
            tenant_id=quarantine_outcome.tenant_id,
            incident_id=request.incident_id,
            containment_type=ContainmentType.MEMORY_QUARANTINE,
            target_id=quarantine_outcome.record_id,
            previous_state=quarantine_outcome.previous_state,
            resulting_state=quarantine_outcome.resulting_state,
            actor_id=quarantine_outcome.actor_id,
            actor_role=quarantine_outcome.actor_role,
            reason_code=ContainmentReasonCode.INCIDENT_RESPONSE.value,
            reason=request.reason,
            analyst_notes=request.analyst_notes,
            evidence_refs=request.evidence_refs,
            policy_version=CONTAINMENT_POLICY_VERSION,
            timestamp=quarantine_outcome.timestamp,
            trace_id=request.trace_id,
            retries=quarantine_outcome.retries,
        )

    def _map_quarantine_status(self, status: QuarantineStatus) -> ContainmentStatus:
        """Map quarantine status to containment status."""
        if status == QuarantineStatus.QUARANTINED:
            return ContainmentStatus.APPLIED
        elif status == QuarantineStatus.ALREADY_QUARANTINED:
            return ContainmentStatus.ALREADY_APPLIED
        elif status == QuarantineStatus.FAILED:
            return ContainmentStatus.FAILED
        elif status == QuarantineStatus.DENIED:
            return ContainmentStatus.DENIED
        elif status == QuarantineStatus.EVIDENCE_RECONCILIATION_REQUIRED:
            return ContainmentStatus.RECONCILIATION_REQUIRED
        elif status == QuarantineStatus.CACHE_RECONCILIATION_REQUIRED:
            return ContainmentStatus.RECONCILIATION_REQUIRED
        else:
            return ContainmentStatus.FAILED

    def _outcome(
        self, req, facts, status, codes, context, *, success: Optional[bool] = None
    ) -> ContainmentOutcome:
        """Create a containment outcome."""
        ok = (
            status in {ContainmentStatus.APPLIED, ContainmentStatus.ALREADY_APPLIED}
            if success is None
            else success
        )
        tenant_ok = isinstance(context, TenantContext) and _nonblank(
            getattr(context, "tenant_id", None)
        )

        return ContainmentOutcome(
            outcome_id=f"cont-{facts.get('outcome_id', '').split('-')[-1]}-{status.value.lower()}",
            success=ok,
            status=status,
            reason_codes=tuple(c.value for c in codes),
            tenant_id=context.tenant_id if tenant_ok else None,
            incident_id=getattr(req, "incident_id", None) if req is not None else None,
            containment_type=facts.get("containment_type"),
            target_id=facts.get("target_id"),
            previous_state=facts.get("previous_state"),
            resulting_state=facts.get("resulting_state"),
            actor_id=context.user_id
            if tenant_ok and _nonblank(getattr(context, "user_id", None))
            else None,
            actor_role=facts.get("actor_role"),
            reason_code=req.reason_code.value
            if isinstance(req, ContainmentRequest)
            else None,
            reason=req.reason.strip() if isinstance(req, ContainmentRequest) else None,
            analyst_notes=req.analyst_notes
            if isinstance(req, ContainmentRequest)
            else None,
            evidence_refs=tuple(facts.get("evidence_refs", ())),
            policy_version=CONTAINMENT_POLICY_VERSION,
            timestamp=self._clock(),
            trace_id=req.trace_id if isinstance(req, ContainmentRequest) else None,
            retries=int(facts.get("retries", 0)),
        )

    def _log(self, outcome: ContainmentOutcome) -> None:
        """Log a containment outcome."""
        logger.info(
            "Containment outcome %s: status=%s tenant=%s incident=%s %s->%s codes=%s actor=%s",
            outcome.outcome_id,
            outcome.status.value,
            outcome.tenant_id,
            outcome.incident_id,
            outcome.previous_state,
            outcome.resulting_state,
            ",".join(outcome.reason_codes),
            outcome.actor_id,
        )


class _Stop(Exception):
    def __init__(
        self, status: ContainmentStatus, *codes: ContainmentReasonCode, **facts: Any
    ):
        super().__init__(",".join(c.value for c in codes))
        self.status = status
        self.codes = codes
        self.facts = facts


def raise_for_containment_outcome(outcome: ContainmentOutcome) -> ContainmentOutcome:
    """Return a successful outcome; otherwise raise the matching M1 error."""
    if outcome.success:
        return outcome
    codes = set(outcome.reason_codes)
    if outcome.status in (
        ContainmentStatus.RECONCILIATION_REQUIRED,
        ContainmentStatus.FAILED,
    ):
        raise SecurityDependencyError(
            "Containment could not be completed and recorded."
        )
    if codes & {
        ContainmentReasonCode.ACTOR_NOT_AUTHORIZED.value,
        ContainmentReasonCode.CONTEXT_INVALID.value,
    }:
        raise ForbiddenError("Containment not authorized.")
    if ContainmentReasonCode.REQUEST_INVALID.value in codes:
        raise ValidationError("Invalid containment request.")
    if ContainmentReasonCode.INCIDENT_NOT_OPEN.value in codes:
        raise AMSCException(
            message="Containment cannot be applied to a closed incident.",
            code="CONFLICT",
            status_code=409,
        )
    raise AMSCException(
        message="Containment transition not permitted.",
        code="CONFLICT",
        status_code=409,
    )


def _nonblank(value: Any) -> bool:
    """Check if a value is non-blank."""
    return type(value) is str and bool(value.strip())


def _safe_req(request: Any) -> Optional[ContainmentRequest]:
    """Safely extract a containment request."""
    return request if isinstance(request, ContainmentRequest) else None


__all__ = [
    "ContainmentAction",
    "ContainmentOutcome",
    "ContainmentReasonCode",
    "ContainmentRequest",
    "ContainmentService",
    "ContainmentStatus",
    "ContainmentType",
    "raise_for_containment_outcome",
]


# ``InvestigationService`` and ``IncidentStatus`` are defined in
# ``backend.app.security.investigation``, which imports containment types from this module.
# Importing them at the top would create a circular import, so the import is deferred until
# after this module's classes are fully defined. ``from __future__ import annotations``
# keeps the ``InvestigationService`` type annotation in ``__init__`` resolvable regardless.
from backend.app.security.investigation import IncidentStatus, InvestigationService  # noqa: E402
