from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import ForbiddenError, NotFoundError, SecurityDependencyError, ValidationError
from backend.app.memory import MemoryRepository
from backend.app.security.audit_identity import user_actor
from backend.app.security.authorization import SECURITY_OPERATOR_ROLES, evaluate_role_access
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.investigation")


# =============================================================================
# 1. Vocabulary
# =============================================================================

class IncidentCategory(str, Enum):
    MEMORY_POISONING = "MEMORY_POISONING"
    EXTERNAL_ACTION_ABUSE = "EXTERNAL_ACTION_ABUSE"
    AGENT_MISCONFIGURATION = "AGENT_MISCONFIGURATION"
    SYSTEM_COMPROMISE = "SYSTEM_COMPROMISE"
    OTHER = "OTHER"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CONTAINED = "CONTAINED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


# =============================================================================
# 2. Models
# =============================================================================

@dataclass(frozen=True)
class AffectedResource:
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceReference:
    evidence_type: str
    reference_id: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime
    event_type: str
    actor: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SuspectedRootCause:
    hypothesis: str
    confidence: float
    evidence: Sequence[EvidenceReference]


@dataclass(frozen=True)
class IncidentInvestigation:
    incident_id: str
    tenant_id: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    affected_agents: Tuple[str, ...]
    affected_memory_records: Tuple[str, ...]
    affected_external_resources: Tuple[AffectedResource, ...]
    evidence_references: Tuple[EvidenceReference, ...]
    timeline: Tuple[TimelineEvent, ...]
    suspected_root_causes: Tuple[SuspectedRootCause, ...]
    containment_recommendations: Tuple[str, ...]
    recovery_requirements: Tuple[str, ...]
    created_at: datetime
    updated_at: datetime
    created_by: str
    updated_by: str


# =============================================================================
# 3. Service
# =============================================================================

class InvestigationService:
    def __init__(self, memory: MemoryRepository, incident_repository: Any = None) -> None:
        self._memory = memory
        self._incident_repository = incident_repository

    @staticmethod
    def _authorize(context: Any) -> Tuple[str, str]:
        if not isinstance(context, TenantContext) or context.is_active is not True \
                or type(context.tenant_id) is not str or not context.tenant_id.strip():
            raise ForbiddenError("Investigation requires a verified tenant context.")
        if not evaluate_role_access(context, SECURITY_OPERATOR_ROLES).allowed:
            raise ForbiddenError("Investigation requires SECURITY_ANALYST or TENANT_ADMIN.")
        try:
            actor = user_actor(context.user_id)
        except ValueError as exc:
            raise ForbiddenError("Investigation requires a verified tenant context.") from exc
        return context.tenant_id, actor

    async def create_investigation(self, context: Optional[TenantContext], request: Any) -> IncidentInvestigation:
        tenant_id, actor = self._authorize(context)
        now = datetime.now(timezone.utc)
        incident_id = getattr(request, "incident_id", None) or getattr(request, "id", None) or f"inc-{now.timestamp()}"
        investigation = IncidentInvestigation(
            incident_id=incident_id,
            tenant_id=tenant_id,
            category=IncidentCategory.OTHER,
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.OPEN,
            affected_agents=tuple(getattr(request, "affected_agents", ()) or ()),
            affected_memory_records=tuple(getattr(request, "affected_memory_records", ()) or ()),
            affected_external_resources=tuple(getattr(request, "affected_external_resources", ()) or ()),
            evidence_references=tuple(getattr(request, "evidence_references", ()) or ()),
            timeline=(),
            suspected_root_causes=(),
            containment_recommendations=(),
            recovery_requirements=(),
            created_at=now,
            updated_at=now,
            created_by=actor,
            updated_by=actor,
        )
        if self._incident_repository is not None:
            try:
                from backend.app.api.incident_management import IncidentEntity, AuditEventEntity
                entity = IncidentEntity(
                    id=incident_id, tenant_id=tenant_id, title=incident_id,
                    classification="OTHER", severity="MEDIUM", status="OPEN",
                    affected_record_id=None, agent_id=None,
                    evidence_json={"affected_agents": list(investigation.affected_agents)},
                    created_at=now,
                )
                await self._incident_repository.create_incident_atomic(entity, [])
            except Exception:  # noqa: BLE001
                logger.exception("Failed to persist investigation %s", incident_id)
        return investigation

    async def update_investigation(self, context: Optional[TenantContext], incident_id: str, request: Any) -> IncidentInvestigation:
        tenant_id, actor = self._authorize(context)
        existing = await self.get_investigation(context, incident_id)
        now = datetime.now(timezone.utc)
        new_status = getattr(request, "status", existing.status)
        if isinstance(new_status, str):
            try:
                new_status = IncidentStatus(new_status)
            except ValueError:
                new_status = existing.status
        return IncidentInvestigation(
            incident_id=existing.incident_id,
            tenant_id=existing.tenant_id,
            category=existing.category,
            severity=existing.severity,
            status=new_status,
            affected_agents=existing.affected_agents,
            affected_memory_records=existing.affected_memory_records,
            affected_external_resources=existing.affected_external_resources,
            evidence_references=existing.evidence_references,
            timeline=existing.timeline,
            suspected_root_causes=existing.suspected_root_causes,
            containment_recommendations=existing.containment_recommendations,
            recovery_requirements=existing.recovery_requirements,
            created_at=existing.created_at,
            updated_at=now,
            created_by=existing.created_by,
            updated_by=actor,
        )

    async def get_investigation(self, context: Optional[TenantContext], incident_id: str) -> IncidentInvestigation:
        tenant_id, actor = self._authorize(context)
        if self._incident_repository is not None:
            try:
                result = await self._incident_repository.get_incident(tenant_id, incident_id)
                if result is not None:
                    entity, _evidence = result
                    status_map = {"OPEN": IncidentStatus.OPEN, "IN_PROGRESS": IncidentStatus.IN_PROGRESS,
                                  "CONTAINED": IncidentStatus.CONTAINED, "RECOVERED": IncidentStatus.RECOVERED,
                                  "CLOSED": IncidentStatus.CLOSED}
                    now = datetime.now(timezone.utc)
                    return IncidentInvestigation(
                        incident_id=entity.id, tenant_id=entity.tenant_id,
                        category=IncidentCategory.OTHER, severity=IncidentSeverity.MEDIUM,
                        status=status_map.get(entity.status, IncidentStatus.OPEN),
                        affected_agents=(), affected_memory_records=(),
                        affected_external_resources=(), evidence_references=(),
                        timeline=(), suspected_root_causes=(),
                        containment_recommendations=(), recovery_requirements=(),
                        created_at=entity.created_at, updated_at=now,
                        created_by=actor, updated_by=actor,
                    )
            except Exception:  # noqa: BLE001
                logger.exception("Failed to load investigation %s", incident_id)
        raise NotFoundError(f"Investigation {incident_id} not found.")

    async def correlate_events(self, tenant_id: str, security_findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        return {"tenant_id": tenant_id, "correlated": list(security_findings)}

    async def trace_information_flow(self, tenant_id: str, record_id: str) -> Dict[str, Any]:
        return {"tenant_id": tenant_id, "record_id": record_id, "flow": []}

    async def generate_containment_recommendations(self, context: Optional[TenantContext], incident_id: str) -> Tuple[ContainmentAction, ...]:
        """Generate containment recommendations based on investigation findings.

        Args:
            context: The verified tenant context (authorization is enforced here).
            incident_id: The incident ID to generate recommendations for

        Returns:
            A tuple of containment actions to apply
        """
        # Authorize and load the investigation. The context is required: recommendations
        # are a security operation and must not be generated from an unverified caller.
        tenant_id, _ = self._authorize(context)
        investigation = await self.get_investigation(context, incident_id)

        # Generate containment recommendations based on investigation findings
        recommendations = []

        # Quarantine affected memory records
        for record_id in investigation.affected_memory_records:
            recommendations.append(
                ContainmentAction(
                    containment_type=ContainmentType.MEMORY_QUARANTINE,
                    target_id=record_id,
                    details={"reason": "Memory poisoning detected"}
                )
            )

        # Suspend affected agents
        for agent_id in investigation.affected_agents:
            recommendations.append(
                ContainmentAction(
                    containment_type=ContainmentType.AGENT_SUSPENSION,
                    target_id=agent_id,
                    details={"reason": "Agent involved in suspicious activity"}
                )
            )

        # Block actions for affected agents
        for agent_id in investigation.affected_agents:
            recommendations.append(
                ContainmentAction(
                    containment_type=ContainmentType.ACTION_BLOCKING,
                    target_id=agent_id,
                    details={"reason": "Suspicious actions detected"}
                )
            )

        # Isolate affected external resources
        for resource in investigation.affected_external_resources:
            recommendations.append(
                ContainmentAction(
                    containment_type=ContainmentType.RESOURCE_ISOLATION,
                    target_id=resource.resource_id,
                    details={"resource_type": resource.resource_type}
                )
            )

        return tuple(recommendations)


__all__ = [
    "AffectedResource", "EvidenceReference", "IncidentCategory", "IncidentInvestigation",
    "IncidentSeverity", "IncidentStatus", "InvestigationService", "SuspectedRootCause",
    "TimelineEvent", "ContainmentAction", "ContainmentType", "ContainmentReasonCode",
]


# Containment types are defined in ``backend.app.security.containment``. Importing them
# at module top would create a circular import (containment imports InvestigationService
# and IncidentStatus from this module), so the import is deferred until after this
# module's own classes are fully defined. ``from __future__ import annotations`` keeps the
# annotations in ``generate_containment_recommendations`` resolvable regardless.
from backend.app.security.containment import ContainmentAction, ContainmentReasonCode, ContainmentType  # noqa: E402