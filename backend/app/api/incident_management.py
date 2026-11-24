"""Incident Management, Evidence & Quarantine API Integration.

Module: backend.app.api.incident_management
Owner: M1 — Platform Backend & API Integration Lead
Coordinated with: M4 (Security/Quarantine Engine), M6 (Database/Persistence), M3 (Memory Systems)

Canonical References:
- AMSC-DOC-002 (TRD/SRS) Section 5: Dynamic Memory Trust, Threat Quarantine & Incident Response
- AMSC-DOC-005 (Database & API Schema) Section 3.5: Incidents, Quarantines & Recovery (Tables 20-22)
- AMSC-DOC-005 Section 5.1: Route Catalog (POST /memory/{id}/quarantine, GET/POST /security/incidents)
- AMSC-DOC-005 Section 6.2: Memory Quarantine Request & Response Schema
- AMSC-DOC-006 (Team Implementation Plan) Day 5: Incident Investigation, Quarantine & Recovery Engine (G5)
- AMSC-DOC-008: GAP-018/029 (Evidence Authorization), GAP-019/030 (Quarantine Atomicity),
                 GAP-020/031 (Forensic Access Separation), GAP-021/032 (Evidence Confidentiality)
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import inspect
import json
import logging
import re
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.api.gateway import get_gateway_repository
from backend.app.api.memory import get_repository as get_memory_repository
from backend.app.core.config import Settings, get_settings
from backend.app.core.dependencies import (
    TenantContextDep,
    require_roles,
)
from backend.app.core.exceptions import (
    AMSCException,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory.models import MemoryDetailResponse, TrustState
from backend.app.memory.repository import MemoryRepository
from backend.app.memory.service import get_memory_detail
from backend.app.security.runtime import get_quarantine_workflow
from backend.app.security.quarantine import (
    raise_for_outcome,
    QuarantineServiceProtocol,
    get_default_quarantine_service,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.incident_management")

# Safe alphanumeric & hyphen identifier regex
SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")

# Maximum evidence items per incident payload
MAX_EVIDENCE_COUNT = 20
# Maximum metadata depth
MAX_METADATA_DEPTH = 5
# Maximum metadata JSON bytes (16 KB)
MAX_METADATA_BYTES = 16384

# Sensitive keys to redact recursively in evidence payloads
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|secret|token|api_key|authorization|auth_token|jwt|private_key|access_token|refresh_token|client_secret)",
    re.IGNORECASE,
)
# Sensitive values to redact even when under non-sensitive keys (Finding G / Finding H)
SENSITIVE_VALUE_PATTERNS = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9\-_\.~+/]+=*|ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----|://[^:]+:[^@]+@|(?:^|[?&;\s,])(?:token|secret|secret[_-]?key|api[_-]?key|password)=[^&\s;,]+|sk-[a-zA-Z0-9_\-]{15,}|ghp_[a-zA-Z0-9]{15,})"
)


def redact_sensitive_dict(data: Any, depth: int = 1) -> Any:
    """Recursively scrub sensitive credential keys and values, and enforce depth limits."""
    if depth > MAX_METADATA_DEPTH:
        return "[TRUNCATED_MAX_DEPTH]"

    if isinstance(data, dict):
        scrubbed: Dict[str, Any] = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = redact_sensitive_dict(v, depth + 1)
        return scrubbed
    elif isinstance(data, (list, tuple)):
        return [redact_sensitive_dict(item, depth + 1) for item in data]
    elif isinstance(data, str):
        if SENSITIVE_VALUE_PATTERNS.search(data):
            return "[REDACTED]"
        if len(data) > 2048:
            return data[:2048] + "... [TRUNCATED]"
        return data
    return data


# ============================================================================
# 1. Enums and Domain Contracts
# ============================================================================

class IncidentClassification(str, Enum):
    """Canonical classification values per AMSC-DOC-005 Table 20."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    UNTRUSTED_MEMORY_ACTION = "UNTRUSTED_MEMORY_ACTION"
    DRIFT_DIVERGENCE = "DRIFT_DIVERGENCE"
    UNAUTHORIZED_TOOL = "UNAUTHORIZED_TOOL"


class IncidentSeverity(str, Enum):
    """Canonical severity values per AMSC-DOC-005 Table 20."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentStatus(str, Enum):
    """Canonical lifecycle status values per AMSC-DOC-005 Table 20."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    QUARANTINED = "QUARANTINED"
    RESOLVED = "RESOLVED"


class EvidenceType(str, Enum):
    """Restricted evidence types per AMSC-DOC-005 Table 21."""
    MEMORY_RECORD = "MEMORY_RECORD"
    TOOL_PROPOSAL = "TOOL_PROPOSAL"
    TRACE_SPAN = "TRACE_SPAN"
    AUDIT_EVENT = "AUDIT_EVENT"


# ============================================================================
# 2. DTO Schemas (Pydantic v2)
# ============================================================================

class IncidentEvidenceItem(BaseModel):
    """Single evidence attachment item matching Table 21."""
    evidence_type: EvidenceType = Field(..., description="Allowlisted evidence category")
    resource_id: str = Field(..., min_length=1, max_length=128, description="Target resource ID")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Redacted forensic metadata")

    model_config = ConfigDict(extra="forbid")

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, v: str) -> str:
        s = v.strip()
        if not s or not SAFE_ID_REGEX.match(s):
            raise ValueError(f"Invalid resource_id format: '{v}'")
        return s

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        try:
            serialized = json.dumps(v, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("Evidence metadata must be a valid JSON-serializable object.") from exc
        if len(serialized.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError(f"Evidence metadata exceeds maximum allowable size ({MAX_METADATA_BYTES} bytes).")
        return redact_sensitive_dict(v)


class IncidentCreateRequest(BaseModel):
    """Canonical incident creation request per AMSC-DOC-005 Section 5.1."""
    title: str = Field(..., min_length=1, max_length=255, description="Incident title")
    classification: IncidentClassification = Field(..., description="Threat classification")
    severity: IncidentSeverity = Field(default=IncidentSeverity.HIGH, description="Incident severity")
    evidence: List[IncidentEvidenceItem] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_COUNT,
        description="Associated forensic evidence items",
    )
    affected_record_id: Optional[str] = Field(None, max_length=128, description="Primary tainted memory ID")
    agent_id: Optional[str] = Field(None, max_length=128, description="Associated agent ID")

    model_config = ConfigDict(extra="forbid")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Incident title cannot be empty or whitespace only.")
        if any(c in s for c in ("\x00", "\r", "\n")):
            raise ValueError("Incident title cannot contain control characters.")
        return s

    @field_validator("affected_record_id", "agent_id")
    @classmethod
    def validate_optional_ids(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip()
        if not s or not SAFE_ID_REGEX.match(s):
            raise ValueError(f"Invalid identifier format: '{v}'")
        return s


class EvidenceAttachRequest(BaseModel):
    """Request payload to append evidence items to an existing incident."""
    evidence: List[IncidentEvidenceItem] = Field(
        ...,
        min_length=1,
        max_length=MAX_EVIDENCE_COUNT,
        description="Forensic evidence items to append",
    )

    model_config = ConfigDict(extra="forbid")


class MemoryQuarantineRequest(BaseModel):
    """Canonical quarantine request per AMSC-DOC-005 Section 6.2."""
    reason: str = Field(..., min_length=1, max_length=1000, description="Security rationale for quarantine")
    analyst_notes: Optional[str] = Field(None, max_length=2000, description="Detailed analyst investigation notes")
    incident_id: Optional[str] = Field(None, max_length=64, description="Optional incident ID linking isolation")

    model_config = ConfigDict(extra="forbid")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Quarantine reason cannot be empty or whitespace only.")
        if "\x00" in s:
            raise ValueError("Quarantine reason cannot contain null bytes.")
        return s

    @field_validator("analyst_notes", "incident_id")
    @classmethod
    def validate_optional_strings(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        if "\x00" in s:
            raise ValueError("Input cannot contain null bytes.")
        return s


class MemoryQuarantineResponse(BaseModel):
    """Canonical quarantine response per AMSC-DOC-005 Section 6.2."""
    id: str = Field(..., description="Quarantined memory record ID")
    previous_state: str = Field(..., description="Memory trust state prior to quarantine")
    trust_state: str = Field(default="QUARANTINED", description="New authoritative memory trust state")
    message: str = Field(
        default="Record successfully quarantined and excluded from protected agent retrieval.",
        description="Sanitized confirmation message",
    )

    model_config = ConfigDict(extra="forbid")


class IncidentResponse(BaseModel):
    """Full incident response entity."""
    id: str
    tenant_id: str
    title: str
    classification: str
    severity: str
    status: str
    affected_record_id: Optional[str] = None
    agent_id: Optional[str] = None
    evidence_summary: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime

    model_config = ConfigDict(extra="forbid")


class IncidentSummaryResponse(BaseModel):
    """Sanitized summary for incident listings (omits raw memory/evidence payloads)."""
    id: str
    tenant_id: str
    title: str
    classification: str
    severity: str
    status: str
    affected_record_id: Optional[str] = None
    agent_id: Optional[str] = None
    evidence_count: int
    created_at: datetime

    model_config = ConfigDict(extra="forbid")


class IncidentListEnvelope(BaseModel):
    """Bounded pagination envelope for incident tickets."""
    items: List[IncidentSummaryResponse]
    limit: int
    offset: int
    has_more: bool
    total: Optional[int] = None

    model_config = ConfigDict(extra="forbid")


class SecurityAlertsSummary(BaseModel):
    """Aggregate security status metrics per Screen 04."""
    total_alerts: int
    critical_count: int
    quarantined_records_count: int
    blocked_actions_24h: int

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# 3. Domain Entities (Dataclasses for Repository Interface)
# ============================================================================

@dataclass
class IncidentEntity:
    id: str
    tenant_id: str
    title: str
    classification: str
    severity: str
    status: str
    affected_record_id: Optional[str]
    agent_id: Optional[str]
    evidence_json: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IncidentEvidenceEntity:
    id: str
    tenant_id: str
    incident_id: str
    evidence_type: str
    resource_id: str
    metadata_json: Dict[str, Any]


@dataclass
class QuarantineEntity:
    id: str
    tenant_id: str
    record_id: str
    incident_id: Optional[str]
    reason: str
    quarantined_by: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEventEntity:
    id: str
    tenant_id: str
    actor_id: str
    event_type: str
    resource_id: str
    action: str
    outcome: str
    trace_id: Optional[str]
    details_json: Dict[str, Any]
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 4. Repository Protocol & Default Storage (M6 Boundary)
# ============================================================================

@runtime_checkable
class IncidentRepositoryProtocol(Protocol):
    """Repository protocol defining M6 database persistence for Incidents & Quarantines."""

    is_persistent: bool
    is_in_memory: bool

    async def create_incident_atomic(
        self,
        incident: IncidentEntity,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        """Atomically persist incident, evidence records, and audit event."""
        ...

    async def attach_evidence_atomic(
        self,
        tenant_id: str,
        incident_id: str,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        """Atomically append evidence to an existing incident."""
        ...

    async def create_quarantine_atomic(
        self,
        quarantine: QuarantineEntity,
        audit_event: Optional[AuditEventEntity] = None,
        incident_id: Optional[str] = None,
    ) -> None:
        """Atomically persist quarantine record, link incident, and emit audit event."""
        ...

    async def record_audit_event(self, audit_event: AuditEventEntity) -> None:
        """Durable persistence for standalone audit events (e.g. forensic reads)."""
        ...

    async def get_incident(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> Optional[Tuple[IncidentEntity, List[IncidentEvidenceEntity]]]:
        """Fetch incident and attached evidence strictly scoped to tenant."""
        ...

    async def list_incidents(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> Tuple[List[Tuple[IncidentEntity, int]], bool, int]:
        """List incidents for tenant with bounded pagination, returning ((incident, ev_count), has_more, total)."""
        ...

    async def get_quarantine_for_record(
        self,
        tenant_id: str,
        record_id: str,
    ) -> Optional[QuarantineEntity]:
        """Fetch quarantine record for a specific memory record in tenant."""
        ...

    async def count_alerts_summary(self, tenant_id: str) -> SecurityAlertsSummary:
        """Aggregate summary metrics for the tenant."""
        ...

    async def check_audit_event_reference(self, event_id: str, tenant_id: str) -> str:
        """Verify existence and tenant ownership of an audit event. Returns 'OK', 'CROSS_TENANT', or 'NOT_FOUND'."""
        ...


class InMemoryIncidentRepository:
    """Thread-safe development and test incident repository.

    Strictly forbidden in production environments.
    """

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        self._incidents: Dict[str, IncidentEntity] = {}
        self._evidence: Dict[str, List[IncidentEvidenceEntity]] = {}
        self._quarantines: Dict[str, QuarantineEntity] = {}  # key: (tenant_id, record_id)
        self._audit_events: List[AuditEventEntity] = []

        # Test hooks
        self.fail_quarantine_persistence: bool = False
        self.fail_incident_persistence: bool = False

    async def create_incident_atomic(
        self,
        incident: IncidentEntity,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        if self.fail_incident_persistence:
            raise AMSCException(
                message="Simulated transaction failure during incident creation.",
                code="TRANSACTION_ROLLBACK",
                status_code=500,
            )

        self._incidents[incident.id] = deepcopy(incident)
        self._evidence[incident.id] = [deepcopy(e) for e in evidence]
        if audit_event:
            self._audit_events.append(deepcopy(audit_event))

    async def attach_evidence_atomic(
        self,
        tenant_id: str,
        incident_id: str,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        inc = self._incidents.get(incident_id)
        if not inc or inc.tenant_id != tenant_id:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        current = self._evidence.setdefault(incident_id, [])
        current.extend([deepcopy(e) for e in evidence])
        inc.evidence_json["summary"] = f"{len(current)} attached evidence item(s)"
        inc.evidence_json["total_count"] = len(current)
        if audit_event:
            self._audit_events.append(deepcopy(audit_event))

    async def record_audit_event(self, audit_event: AuditEventEntity) -> None:
        self._audit_events.append(deepcopy(audit_event))

    async def check_cross_tenant_audit_event(self, event_id: str, tenant_id: str) -> bool:
        for ev in self._audit_events:
            if ev.id == event_id and ev.tenant_id != tenant_id:
                return True
        return False

    async def check_audit_event_reference(self, event_id: str, tenant_id: str) -> str:
        """Verify existence and tenant ownership of an audit event."""
        for ev in self._audit_events:
            if ev.id == event_id:
                if ev.tenant_id != tenant_id:
                    return "CROSS_TENANT"
                return "OK"
        return "NOT_FOUND"

    async def create_quarantine_atomic(
        self,
        quarantine: QuarantineEntity,
        audit_event: Optional[AuditEventEntity] = None,
        incident_id: Optional[str] = None,
    ) -> None:
        if self.fail_quarantine_persistence:
            raise AMSCException(
                message="Simulated database failure during quarantine transaction.",
                code="TRANSACTION_ROLLBACK",
                status_code=500,
            )

        key = f"{quarantine.tenant_id}:{quarantine.record_id}"
        self._quarantines[key] = deepcopy(quarantine)

        if incident_id and incident_id in self._incidents:
            inc = self._incidents[incident_id]
            if inc.tenant_id == quarantine.tenant_id:
                inc.status = "QUARANTINED"
                inc.affected_record_id = quarantine.record_id

        if audit_event:
            self._audit_events.append(deepcopy(audit_event))

    async def get_incident(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> Optional[Tuple[IncidentEntity, List[IncidentEvidenceEntity]]]:
        inc = self._incidents.get(incident_id)
        if not inc or inc.tenant_id != tenant_id:
            return None
        evs = self._evidence.get(incident_id, [])
        return (deepcopy(inc), [deepcopy(e) for e in evs])

    async def list_incidents(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> Tuple[List[Tuple[IncidentEntity, int]], bool, int]:
        matched = [
            i for i in self._incidents.values()
            if i.tenant_id == tenant_id
            and (status is None or i.status == status)
            and (severity is None or i.severity == severity)
            and (classification is None or i.classification == classification)
        ]
        # Sort deterministic: created_at desc, id asc
        matched.sort(key=lambda x: (x.created_at, x.id), reverse=True)
        total = len(matched)
        page = matched[offset : offset + limit]
        has_more = (offset + limit) < total

        results = []
        for inc in page:
            ev_count = len(self._evidence.get(inc.id, []))
            results.append((deepcopy(inc), ev_count))
        return results, has_more, total

    async def get_quarantine_for_record(
        self,
        tenant_id: str,
        record_id: str,
    ) -> Optional[QuarantineEntity]:
        key = f"{tenant_id}:{record_id}"
        q = self._quarantines.get(key)
        return deepcopy(q) if q else None

    async def count_alerts_summary(self, tenant_id: str) -> SecurityAlertsSummary:
        total_alerts = sum(
            1 for i in self._incidents.values()
            if i.tenant_id == tenant_id and i.status in ("OPEN", "INVESTIGATING", "QUARANTINED")
        )
        critical_count = sum(
            1 for i in self._incidents.values()
            if i.tenant_id == tenant_id and i.severity == "CRITICAL" and i.status != "RESOLVED"
        )
        quarantined_count = sum(
            1 for q in self._quarantines.values()
            if q.tenant_id == tenant_id
        )
        return SecurityAlertsSummary(
            total_alerts=total_alerts,
            critical_count=critical_count,
            quarantined_records_count=quarantined_count,
            blocked_actions_24h=0,
        )


class SqlAlchemyIncidentRepository:
    """Production database repository using async PostgreSQL sessions."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create_incident_atomic(
        self,
        incident: IncidentEntity,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import IncidentEvidence as DbIncidentEvidence

        async with self.session_factory() as session:
            async with session.begin():
                db_inc = DbIncident(
                    id=incident.id,
                    tenant_id=incident.tenant_id,
                    title=incident.title,
                    classification=incident.classification,
                    severity=incident.severity,
                    status=incident.status,
                    affected_record_id=incident.affected_record_id,
                    agent_id=incident.agent_id,
                    evidence_json=incident.evidence_json,
                    created_at=incident.created_at,
                )
                session.add(db_inc)

                for ev in evidence:
                    db_ev = DbIncidentEvidence(
                        id=ev.id,
                        tenant_id=ev.tenant_id,
                        incident_id=ev.incident_id,
                        evidence_type=ev.evidence_type,
                        resource_id=ev.resource_id,
                        metadata_json=ev.metadata_json,
                    )
                    session.add(db_ev)

                if audit_event:
                    db_audit = DbAuditEvent(
                        id=audit_event.id,
                        tenant_id=audit_event.tenant_id,
                        actor_id=audit_event.actor_id,
                        event_type=audit_event.event_type,
                        resource_id=audit_event.resource_id,
                        action=audit_event.action,
                        outcome=audit_event.outcome,
                        trace_id=audit_event.trace_id,
                        details_json=audit_event.details_json,
                        occurred_at=audit_event.occurred_at,
                    )
                    session.add(db_audit)

    async def attach_evidence_atomic(
        self,
        tenant_id: str,
        incident_id: str,
        evidence: List[IncidentEvidenceEntity],
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import IncidentEvidence as DbIncidentEvidence

        async with self.session_factory() as session:
            async with session.begin():
                # Verify tenant ownership
                stmt = select(DbIncident).where(
                    DbIncident.id == incident_id,
                    DbIncident.tenant_id == tenant_id,
                )
                existing = (await session.execute(stmt)).scalar_one_or_none()
                if not existing:
                    raise NotFoundError(f"Incident '{incident_id}' not found.")

                for ev in evidence:
                    db_ev = DbIncidentEvidence(
                        id=ev.id,
                        tenant_id=ev.tenant_id,
                        incident_id=ev.incident_id,
                        evidence_type=ev.evidence_type,
                        resource_id=ev.resource_id,
                        metadata_json=ev.metadata_json,
                    )
                    session.add(db_ev)

                # Keep incident evidence summary updated in database
                ev_count_stmt = select(func.count(DbIncidentEvidence.id)).where(
                    DbIncidentEvidence.incident_id == incident_id,
                    DbIncidentEvidence.tenant_id == tenant_id,
                )
                curr_count = (await session.execute(ev_count_stmt)).scalar() or 0
                new_total = curr_count + len(evidence)
                existing_ev = dict(existing.evidence_json or {})
                existing_ev["summary"] = f"{new_total} attached evidence item(s)"
                existing_ev["total_count"] = new_total
                existing.evidence_json = existing_ev

                if audit_event:
                    db_audit = DbAuditEvent(
                        id=audit_event.id,
                        tenant_id=audit_event.tenant_id,
                        actor_id=audit_event.actor_id,
                        event_type=audit_event.event_type,
                        resource_id=audit_event.resource_id,
                        action=audit_event.action,
                        outcome=audit_event.outcome,
                        trace_id=audit_event.trace_id,
                        details_json=audit_event.details_json,
                        occurred_at=audit_event.occurred_at,
                    )
                    session.add(db_audit)

    async def record_audit_event(self, audit_event: AuditEventEntity) -> None:
        """Durable standalone audit persistence in production PostgreSQL."""
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent

        async with self.session_factory() as session:
            async with session.begin():
                db_audit = DbAuditEvent(
                    id=audit_event.id,
                    tenant_id=audit_event.tenant_id,
                    actor_id=audit_event.actor_id,
                    event_type=audit_event.event_type,
                    resource_id=audit_event.resource_id,
                    action=audit_event.action,
                    outcome=audit_event.outcome,
                    trace_id=audit_event.trace_id,
                    details_json=audit_event.details_json,
                    occurred_at=audit_event.occurred_at,
                )
                session.add(db_audit)

    async def check_cross_tenant_audit_event(self, event_id: str, tenant_id: str) -> bool:
        """Verify whether an audit event ID exists belonging to another tenant."""
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent

        async with self.session_factory() as session:
            stmt = select(DbAuditEvent.tenant_id).where(DbAuditEvent.id == event_id)
            owner_tenant = (await session.execute(stmt)).scalar_one_or_none()
            if owner_tenant and owner_tenant != tenant_id:
                return True
            return False

    async def check_audit_event_reference(self, event_id: str, tenant_id: str) -> str:
        """Verify existence and tenant ownership of an audit event."""
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent

        async with self.session_factory() as session:
            stmt = select(DbAuditEvent.tenant_id).where(DbAuditEvent.id == event_id)
            owner_tenant = (await session.execute(stmt)).scalar_one_or_none()
            if owner_tenant is None:
                return "NOT_FOUND"
            if owner_tenant != tenant_id:
                return "CROSS_TENANT"
            return "OK"

    async def create_quarantine_atomic(
        self,
        quarantine: QuarantineEntity,
        audit_event: Optional[AuditEventEntity] = None,
        incident_id: Optional[str] = None,
    ) -> None:
        from backend.app.database.models.memory import MemoryRecord as DbMemoryRecord
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import Quarantine as DbQuarantine

        async with self.session_factory() as session:
            async with session.begin():
                # 1. Update memory record trust state
                await session.execute(
                    update(DbMemoryRecord)
                    .where(
                        DbMemoryRecord.id == quarantine.record_id,
                        DbMemoryRecord.tenant_id == quarantine.tenant_id,
                    )
                    .values(
                        trust_state="QUARANTINED",
                        updated_at=datetime.now(timezone.utc),
                    )
                )

                # 2. Insert quarantine row
                db_q = DbQuarantine(
                    id=quarantine.id,
                    tenant_id=quarantine.tenant_id,
                    record_id=quarantine.record_id,
                    incident_id=quarantine.incident_id,
                    reason=quarantine.reason,
                    quarantined_by=quarantine.quarantined_by,
                    created_at=quarantine.created_at,
                )
                session.add(db_q)

                # 3. Update incident state if provided
                if incident_id:
                    await session.execute(
                        update(DbIncident)
                        .where(
                            DbIncident.id == incident_id,
                            DbIncident.tenant_id == quarantine.tenant_id,
                        )
                        .values(status="QUARANTINED", affected_record_id=quarantine.record_id)
                    )

                # 4. Audit event
                if audit_event:
                    db_audit = DbAuditEvent(
                        id=audit_event.id,
                        tenant_id=audit_event.tenant_id,
                        actor_id=audit_event.actor_id,
                        event_type=audit_event.event_type,
                        resource_id=audit_event.resource_id,
                        action=audit_event.action,
                        outcome=audit_event.outcome,
                        trace_id=audit_event.trace_id,
                        details_json=audit_event.details_json,
                        occurred_at=audit_event.occurred_at,
                    )
                    session.add(db_audit)

    async def get_incident(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> Optional[Tuple[IncidentEntity, List[IncidentEvidenceEntity]]]:
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import IncidentEvidence as DbIncidentEvidence

        async with self.session_factory() as session:
            stmt = select(DbIncident).where(
                DbIncident.id == incident_id,
                DbIncident.tenant_id == tenant_id,
            )
            db_inc = (await session.execute(stmt)).scalar_one_or_none()
            if not db_inc:
                return None

            ev_stmt = select(DbIncidentEvidence).where(
                DbIncidentEvidence.incident_id == incident_id,
                DbIncidentEvidence.tenant_id == tenant_id,
            )
            db_evs = (await session.execute(ev_stmt)).scalars().all()

            inc_ent = IncidentEntity(
                id=db_inc.id,
                tenant_id=db_inc.tenant_id,
                title=db_inc.title,
                classification=db_inc.classification,
                severity=db_inc.severity,
                status=db_inc.status,
                affected_record_id=db_inc.affected_record_id,
                agent_id=db_inc.agent_id,
                evidence_json=dict(db_inc.evidence_json),
                created_at=db_inc.created_at,
            )
            ev_ents = [
                IncidentEvidenceEntity(
                    id=e.id,
                    tenant_id=e.tenant_id,
                    incident_id=e.incident_id,
                    evidence_type=e.evidence_type,
                    resource_id=e.resource_id,
                    metadata_json=dict(e.metadata_json),
                )
                for e in db_evs
            ]
            return (inc_ent, ev_ents)

    async def list_incidents(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> Tuple[List[Tuple[IncidentEntity, int]], bool, int]:
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import IncidentEvidence as DbIncidentEvidence

        async with self.session_factory() as session:
            count_stmt = select(func.count(DbIncident.id)).where(DbIncident.tenant_id == tenant_id)
            if status:
                count_stmt = count_stmt.where(DbIncident.status == status)
            if severity:
                count_stmt = count_stmt.where(DbIncident.severity == severity)
            if classification:
                count_stmt = count_stmt.where(DbIncident.classification == classification)
            total = (await session.execute(count_stmt)).scalar() or 0

            stmt = select(DbIncident).where(DbIncident.tenant_id == tenant_id)
            if status:
                stmt = stmt.where(DbIncident.status == status)
            if severity:
                stmt = stmt.where(DbIncident.severity == severity)
            if classification:
                stmt = stmt.where(DbIncident.classification == classification)
            stmt = stmt.order_by(DbIncident.created_at.desc(), DbIncident.id.asc()).limit(limit).offset(offset)

            rows = (await session.execute(stmt)).scalars().all()
            has_more = (offset + limit) < total

            results = []
            for r in rows:
                ev_count_stmt = select(func.count(DbIncidentEvidence.id)).where(
                    DbIncidentEvidence.incident_id == r.id,
                    DbIncidentEvidence.tenant_id == tenant_id,
                )
                ev_count = (await session.execute(ev_count_stmt)).scalar() or 0
                ent = IncidentEntity(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    title=r.title,
                    classification=r.classification,
                    severity=r.severity,
                    status=r.status,
                    affected_record_id=r.affected_record_id,
                    agent_id=r.agent_id,
                    evidence_json=dict(r.evidence_json),
                    created_at=r.created_at,
                )
                results.append((ent, ev_count))
            return results, has_more, total

    async def get_quarantine_for_record(
        self,
        tenant_id: str,
        record_id: str,
    ) -> Optional[QuarantineEntity]:
        from backend.app.database.models.recovery import Quarantine as DbQuarantine

        async with self.session_factory() as session:
            stmt = (
                select(DbQuarantine)
                .where(
                    DbQuarantine.record_id == record_id,
                    DbQuarantine.tenant_id == tenant_id,
                )
                .order_by(DbQuarantine.created_at.desc())
                .limit(1)
            )
            db_q = (await session.execute(stmt)).scalars().first()
            if not db_q:
                return None
            return QuarantineEntity(
                id=db_q.id,
                tenant_id=db_q.tenant_id,
                record_id=db_q.record_id,
                incident_id=db_q.incident_id,
                reason=db_q.reason,
                quarantined_by=db_q.quarantined_by,
                created_at=db_q.created_at,
            )

    async def count_alerts_summary(self, tenant_id: str) -> SecurityAlertsSummary:
        from backend.app.database.models.recovery import Incident as DbIncident
        from backend.app.database.models.recovery import Quarantine as DbQuarantine

        async with self.session_factory() as session:
            total_stmt = select(func.count(DbIncident.id)).where(
                DbIncident.tenant_id == tenant_id,
                DbIncident.status.in_(["OPEN", "INVESTIGATING", "QUARANTINED"]),
            )
            total_alerts = (await session.execute(total_stmt)).scalar() or 0

            crit_stmt = select(func.count(DbIncident.id)).where(
                DbIncident.tenant_id == tenant_id,
                DbIncident.severity == "CRITICAL",
                DbIncident.status != "RESOLVED",
            )
            crit_count = (await session.execute(crit_stmt)).scalar() or 0

            q_stmt = select(func.count(func.distinct(DbQuarantine.record_id))).where(
                DbQuarantine.tenant_id == tenant_id,
            )
            q_count = (await session.execute(q_stmt)).scalar() or 0

            return SecurityAlertsSummary(
                total_alerts=total_alerts,
                critical_count=crit_count,
                quarantined_records_count=q_count,
                blocked_actions_24h=0,
            )


_default_incident_repository: Optional[IncidentRepositoryProtocol] = None


def get_default_incident_repository(settings: Optional[Settings] = None) -> IncidentRepositoryProtocol:
    global _default_incident_repository
    cfg = settings or get_settings()
    if cfg.APP_ENV == "production":
        raise RuntimeError("Security violation: InMemoryIncidentRepository cannot be used in production.")
    if _default_incident_repository is None:
        _default_incident_repository = InMemoryIncidentRepository()
    return _default_incident_repository


def set_default_incident_repository(repo: Optional[IncidentRepositoryProtocol]) -> None:
    global _default_incident_repository
    _default_incident_repository = repo


async def get_incident_repository(request: Request) -> IncidentRepositoryProtocol:
    repo = getattr(request.app.state, "incident_repo", None)
    if repo is not None:
        return repo
    settings: Settings = getattr(request.app.state, "settings", None) or get_settings()
    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Database incident repository is not configured.")
    return get_default_incident_repository(settings)


IncidentRepoDep = IncidentRepositoryProtocol


def validate_identifier(val: str, field_name: str = "identifier") -> str:
    """Validate resource identifier against SAFE_ID_REGEX and non-empty bounds."""
    s = val.strip()
    if not s or not SAFE_ID_REGEX.match(s):
        raise ValidationError(f"Invalid {field_name} format: '{val}'")
    return s


# ============================================================================
# 5. Evidence Reference Authorization Validator (GAP-018 / GAP-029)
# ============================================================================

async def validate_evidence_references(
    evidence_items: List[IncidentEvidenceItem],
    tenant_id: str,
    request: Request,
    user_branch: Optional[str] = None,
) -> None:
    """Strictly authorize every referenced resource against tenant ownership and branch scope.

    Enforces GAP-018 / GAP-029 & Section 8.2:
    1. Check evidence type against allowlist.
    2. Format validation.
    3. Memory references verified in MemoryRepository within tenant scope.
    4. Tool proposals verified in GatewayRepository within tenant scope.
    5. Rejects arbitrary cross-tenant or unauthorized branch resource IDs.
    """
    mem_repo: MemoryRepository = await get_memory_repository(request)
    gateway_repo = await get_gateway_repository(request)
    incident_repo = await get_incident_repository(request)

    for ev in evidence_items:
        if ev.evidence_type == EvidenceType.MEMORY_RECORD:
            rec = mem_repo.get_record(ev.resource_id, tenant_id)
            if not rec:
                raise ValidationError(
                    f"Referenced memory record '{ev.resource_id}' does not exist or does not belong to authorized tenant."
                )
        elif ev.evidence_type == EvidenceType.TOOL_PROPOSAL:
            prop = await gateway_repo.get_by_id(tenant_id, ev.resource_id)
            if not prop:
                raise ValidationError(
                    f"Referenced tool proposal '{ev.resource_id}' does not exist or does not belong to authorized tenant."
                )
            if user_branch and hasattr(prop, "agent_id") and prop.agent_id:
                agent_repo = getattr(request.app.state, "agent_repo", None)
                if agent_repo is None:
                    from backend.app.api.agents import get_default_agent_repository
                    agent_repo = get_default_agent_repository()
                agent = await agent_repo.get_agent_by_id(prop.agent_id, tenant_id)
                if agent and getattr(agent, "branch_id", None) and agent.branch_id != user_branch:
                    raise ValidationError(
                        f"Referenced tool proposal '{ev.resource_id}' belongs to an unauthorized branch."
                    )
        elif ev.evidence_type == EvidenceType.AUDIT_EVENT:
            if not SAFE_ID_REGEX.match(ev.resource_id):
                raise ValidationError(f"Invalid AUDIT_EVENT identifier format: '{ev.resource_id}'")
            if hasattr(incident_repo, "check_audit_event_reference"):
                ref_status = await incident_repo.check_audit_event_reference(ev.resource_id, tenant_id)
                if ref_status == "CROSS_TENANT":
                    raise ValidationError(
                        f"Referenced audit event '{ev.resource_id}' belongs to another tenant."
                    )
                elif ref_status == "NOT_FOUND":
                    raise ValidationError(
                        f"Referenced audit event '{ev.resource_id}' does not exist."
                    )
            elif hasattr(incident_repo, "check_cross_tenant_audit_event"):
                is_cross = await incident_repo.check_cross_tenant_audit_event(ev.resource_id, tenant_id)
                if is_cross:
                    raise ValidationError(
                        f"Referenced audit event '{ev.resource_id}' belongs to another tenant."
                    )
        elif ev.evidence_type == EvidenceType.TRACE_SPAN:
            if not SAFE_ID_REGEX.match(ev.resource_id):
                raise ValidationError(f"Invalid TRACE_SPAN identifier format: '{ev.resource_id}'")
            trace_repo = getattr(request.app.state, "trace_repo", None)
            if trace_repo is None:
                from backend.app.api.traces import get_default_trace_repository
                trace_repo = get_default_trace_repository()
            if hasattr(trace_repo, "check_span_reference"):
                span_status = await trace_repo.check_span_reference(ev.resource_id, tenant_id)
                if span_status == "CROSS_TENANT":
                    raise ValidationError(
                        f"Referenced trace span '{ev.resource_id}' belongs to another tenant."
                    )
                elif span_status == "NOT_FOUND":
                    raise ValidationError(
                        f"Referenced trace span '{ev.resource_id}' does not exist."
                    )


# ============================================================================
# 6. Routers and Endpoints
# ============================================================================

router = APIRouter(prefix="/security", tags=["security", "incidents"])
memory_quarantine_router = APIRouter(prefix="/memory", tags=["memory", "quarantine"])


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a security incident ticket",
    description="Authorized analysts create an incident with validated forensic evidence references.",
)
async def create_incident(
    payload: IncidentCreateRequest,
    request: Request,
    tenant_context: TenantContext = Depends(require_roles("SECURITY_ANALYST", "TENANT_ADMIN")),
    repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> IncidentResponse:
    """Create a new security incident with atomic evidence attachment."""
    tenant_id = tenant_context.tenant_id
    actor_id = tenant_context.user_id
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)

    # 1. Validate affected_record_id belongs to tenant if supplied
    if payload.affected_record_id:
        mem_repo = await get_memory_repository(request)
        rec = mem_repo.get_record(payload.affected_record_id, tenant_id)
        if not rec:
            raise ValidationError(
                f"Referenced memory record '{payload.affected_record_id}' does not exist or does not belong to authorized tenant."
            )

    # 2. Validate agent_id belongs to tenant and caller's branch if supplied
    if payload.agent_id:
        agent_repo = getattr(request.app.state, "agent_repo", None)
        if agent_repo is None:
            from backend.app.api.agents import get_default_agent_repository
            agent_repo = get_default_agent_repository()
        agent = await agent_repo.get_agent_by_id(payload.agent_id, tenant_id)
        if not agent:
            raise ValidationError(
                f"Referenced agent '{payload.agent_id}' does not exist or does not belong to authorized tenant."
            )
        if user_branch and getattr(agent, "branch_id", None) and agent.branch_id != user_branch:
            raise ValidationError(
                f"Referenced agent '{payload.agent_id}' does not belong to authorized branch."
            )

    # 3. Validate evidence references against tenant ownership and branch scope
    await validate_evidence_references(payload.evidence, tenant_id, request, user_branch=user_branch)

    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Evidence entities
    evidence_entities: List[IncidentEvidenceEntity] = []
    for ev in payload.evidence:
        ev_id = f"ev-{uuid.uuid4().hex[:12]}"
        evidence_entities.append(
            IncidentEvidenceEntity(
                id=ev_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                evidence_type=ev.evidence_type.value,
                resource_id=ev.resource_id,
                metadata_json=ev.metadata,
            )
        )

    evidence_summary = (
        f"{len(evidence_entities)} attached evidence item(s): "
        + ", ".join({e.evidence_type for e in evidence_entities})
        if evidence_entities
        else "No initial evidence attached."
    )

    incident_entity = IncidentEntity(
        id=incident_id,
        tenant_id=tenant_id,
        title=payload.title,
        classification=payload.classification.value,
        severity=payload.severity.value,
        status=IncidentStatus.OPEN.value,
        affected_record_id=payload.affected_record_id,
        agent_id=payload.agent_id,
        evidence_json={"summary": evidence_summary, "initial_count": len(evidence_entities)},
        created_at=now,
    )

    audit_event = AuditEventEntity(
        id=f"aud-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        actor_id=actor_id,
        event_type="INCIDENT_CREATED",
        resource_id=incident_id,
        action="CREATE_INCIDENT",
        outcome="SUCCESS",
        trace_id=getattr(request.state, "trace_id", None),
        details_json={
            "title": payload.title,
            "classification": payload.classification.value,
            "severity": payload.severity.value,
            "evidence_count": len(evidence_entities),
            "affected_record_id": payload.affected_record_id,
            **({"branch_id": user_branch} if user_branch else {}),
        },
        occurred_at=now,
    )

    # Atomic write
    await repo.create_incident_atomic(incident_entity, evidence_entities, audit_event)

    return IncidentResponse(
        id=incident_entity.id,
        tenant_id=incident_entity.tenant_id,
        title=incident_entity.title,
        classification=incident_entity.classification,
        severity=incident_entity.severity,
        status=incident_entity.status,
        affected_record_id=incident_entity.affected_record_id,
        agent_id=incident_entity.agent_id,
        evidence_summary=evidence_summary,
        evidence=[
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "resource_id": e.resource_id,
                "metadata": e.metadata_json,
            }
            for e in evidence_entities
        ],
        created_at=incident_entity.created_at,
    )


@router.get(
    "/incidents",
    response_model=IncidentListEnvelope,
    status_code=status.HTTP_200_OK,
    summary="List security incidents for tenant",
    description="Return bounded paginated list of security incidents strictly scoped to caller's tenant.",
)
async def list_incidents(
    tenant_context: TenantContextDep,
    status_filter: Optional[IncidentStatus] = Query(None, alias="status", description="Filter by status (OPEN, INVESTIGATING, QUARANTINED, RESOLVED)"),
    severity_filter: Optional[IncidentSeverity] = Query(None, alias="severity", description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    classification_filter: Optional[IncidentClassification] = Query(None, alias="classification", description="Filter by classification"),
    limit: int = Query(50, ge=1, le=100, description="Requested page limit (1-100, default 50)"),
    offset: int = Query(0, ge=0, description="Page offset (>= 0)"),
    repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> IncidentListEnvelope:
    """List security incidents with bounded pagination and safe sanitized summaries."""
    items_with_count, has_more, total = await repo.list_incidents(
        tenant_id=tenant_context.tenant_id,
        limit=limit,
        offset=offset,
        status=status_filter.value if status_filter else None,
        severity=severity_filter.value if severity_filter else None,
        classification=classification_filter.value if classification_filter else None,
    )

    summary_items = [
        IncidentSummaryResponse(
            id=inc.id,
            tenant_id=inc.tenant_id,
            title=inc.title,
            classification=inc.classification,
            severity=inc.severity,
            status=inc.status,
            affected_record_id=inc.affected_record_id,
            agent_id=inc.agent_id,
            evidence_count=ev_count,
            created_at=inc.created_at,
        )
        for inc, ev_count in items_with_count
    ]

    return IncidentListEnvelope(
        items=summary_items,
        limit=limit,
        offset=offset,
        has_more=has_more,
        total=total,
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get incident detail & attached evidence",
    description="Retrieve incident details and full forensic evidence items strictly scoped to tenant.",
)
async def get_incident_detail(
    incident_id: str,
    tenant_context: TenantContextDep,
    repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> IncidentResponse:
    """Fetch incident detail and its associated evidence."""
    clean_incident_id = validate_identifier(incident_id, "incident_id")
    res = await repo.get_incident(tenant_context.tenant_id, clean_incident_id)
    if not res:
        raise NotFoundError(f"Incident '{clean_incident_id}' not found.")

    incident, evidence = res
    evidence_summary = incident.evidence_json.get("summary") or f"{len(evidence)} evidence item(s)"

    return IncidentResponse(
        id=incident.id,
        tenant_id=incident.tenant_id,
        title=incident.title,
        classification=incident.classification,
        severity=incident.severity,
        status=incident.status,
        affected_record_id=incident.affected_record_id,
        agent_id=incident.agent_id,
        evidence_summary=evidence_summary,
        evidence=[
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "resource_id": e.resource_id,
                "metadata": e.metadata_json,
            }
            for e in evidence
        ],
        created_at=incident.created_at,
    )


@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Attach evidence to an existing incident",
    description="Append verified forensic evidence items to an existing incident ticket.",
)
async def attach_incident_evidence(
    incident_id: str,
    payload: EvidenceAttachRequest,
    request: Request,
    tenant_context: TenantContext = Depends(require_roles("SECURITY_ANALYST", "TENANT_ADMIN")),
    repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> IncidentResponse:
    """Append validated evidence to an existing incident."""
    clean_incident_id = validate_identifier(incident_id, "incident_id")
    tenant_id = tenant_context.tenant_id
    actor_id = tenant_context.user_id
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)

    # Verify incident exists and belongs to tenant
    res = await repo.get_incident(tenant_id, clean_incident_id)
    if not res:
        raise NotFoundError(f"Incident '{clean_incident_id}' not found.")
    incident, existing_evidence = res

    # Validate evidence references
    await validate_evidence_references(payload.evidence, tenant_id, request, user_branch=user_branch)

    new_entities: List[IncidentEvidenceEntity] = []
    for ev in payload.evidence:
        ev_id = f"ev-{uuid.uuid4().hex[:12]}"
        new_entities.append(
            IncidentEvidenceEntity(
                id=ev_id,
                tenant_id=tenant_id,
                incident_id=clean_incident_id,
                evidence_type=ev.evidence_type.value,
                resource_id=ev.resource_id,
                metadata_json=ev.metadata,
            )
        )

    now = datetime.now(timezone.utc)
    audit_event = AuditEventEntity(
        id=f"aud-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        actor_id=actor_id,
        event_type="EVIDENCE_ATTACHED",
        resource_id=clean_incident_id,
        action="ATTACH_EVIDENCE",
        outcome="SUCCESS",
        trace_id=getattr(request.state, "trace_id", None),
        details_json={
            "appended_count": len(new_entities),
            "evidence_types": [e.evidence_type for e in new_entities],
            **({"branch_id": user_branch} if user_branch else {}),
        },
        occurred_at=now,
    )

    await repo.attach_evidence_atomic(tenant_id, clean_incident_id, new_entities, audit_event)

    all_evidence = existing_evidence + new_entities
    summary = f"{len(all_evidence)} attached evidence item(s)"

    return IncidentResponse(
        id=incident.id,
        tenant_id=incident.tenant_id,
        title=incident.title,
        classification=incident.classification,
        severity=incident.severity,
        status=incident.status,
        affected_record_id=incident.affected_record_id,
        agent_id=incident.agent_id,
        evidence_summary=summary,
        evidence=[
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "resource_id": e.resource_id,
                "metadata": e.metadata_json,
            }
            for e in all_evidence
        ],
        created_at=incident.created_at,
    )


@router.get(
    "/alerts",
    response_model=SecurityAlertsSummary,
    status_code=status.HTTP_200_OK,
    summary="Aggregate security alerts and quarantine counts",
    description="Provides real-time aggregate counts for Security Center Screen 04.",
)
async def get_security_alerts(
    tenant_context: TenantContextDep,
    repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> SecurityAlertsSummary:
    """Aggregate open alerts and quarantine statistics strictly for tenant."""
    return await repo.count_alerts_summary(tenant_context.tenant_id)


@router.get(
    "/memory/{record_id}",
    response_model=MemoryDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Forensic memory inspection (Audited)",
    description="Authorized analysts inspect quarantined or suspicious memory records under explicit audit logging.",
)
async def forensic_inspect_memory(
    record_id: str,
    request: Request,
    reason: str = Query(..., min_length=5, max_length=500, description="Investigation rationale for forensic inspection"),
    tenant_context: TenantContext = Depends(require_roles("SECURITY_ANALYST", "TENANT_ADMIN")),
    mem_repo: MemoryRepository = Depends(get_memory_repository),
    incident_repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> MemoryDetailResponse:
    """Forensic memory access with mandatory audit trail and zero trust-state alteration."""
    clean_record_id = validate_identifier(record_id, "record_id")
    tenant_id = tenant_context.tenant_id
    actor_id = tenant_context.user_id
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)

    # Emit audit event for forensic inspection
    now = datetime.now(timezone.utc)
    audit_event = AuditEventEntity(
        id=f"aud-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        actor_id=actor_id,
        event_type="FORENSIC_MEMORY_ACCESSED",
        resource_id=clean_record_id,
        action="FORENSIC_READ",
        outcome="SUCCESS",
        trace_id=getattr(request.state, "trace_id", None),
        details_json={
            "reason": reason.strip(),
            **({"branch_id": user_branch} if user_branch else {}),
        },
        occurred_at=now,
    )

    # Use M3 get_memory_detail with forensic=True and allow_quarantined=True
    record, versions, provenance = get_memory_detail(
        tenant_id=tenant_id,
        record_id=clean_record_id,
        for_forensic=True,
        allow_quarantined=True,
        repository=mem_repo,
    )

    # Durably persist audit event in incident repository
    await incident_repo.record_audit_event(audit_event)

    return MemoryDetailResponse(
        record=record,
        versions=versions,
        provenance=provenance,
    )


# ============================================================================
# 7. Quarantine Endpoint (Canonical & Security Route Alias)
# ============================================================================

async def _execute_quarantine_flow(
    record_id: str,
    payload: MemoryQuarantineRequest,
    request: Request,
    tenant_context: TenantContext,
    mem_repo: MemoryRepository,
    incident_repo: IncidentRepositoryProtocol,
    quarantine_service: QuarantineServiceProtocol,
) -> MemoryQuarantineResponse:
    """Quarantine flow shared by /memory and /security routes.

    API request -> TenantContext -> M4 QuarantineWorkflow -> M4 TrustEvaluator (matrix, ledger,
    race-safe write) -> durable evidence (quarantine row + audit event, atomic) -> M3 retrieval
    exclusion. There is no fallback: if M4 cannot complete or record the quarantine, the request
    fails (never reported as success). ``quarantine_service`` is kept for signature compatibility
    and only supplies the legacy eligibility pre-check message for unauthorized roles.
    """
    clean_record_id = validate_identifier(record_id, "record_id")
    tenant_id = tenant_context.tenant_id
    actor_id = tenant_context.user_id
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)

    # 1. Record must exist in the caller's tenant (cross-tenant == not found).
    record = mem_repo.get_record(clean_record_id, tenant_id)
    if inspect.isawaitable(record):
        record = await record
    if not record:
        raise NotFoundError(f"Memory record '{clean_record_id}' not found.")

    # 2. Optional incident link must belong to the tenant and be open.
    clean_inc_id: Optional[str] = None
    if payload.incident_id:
        clean_inc_id = validate_identifier(payload.incident_id, "incident_id")
        res = await incident_repo.get_incident(tenant_id, clean_inc_id)
        if not res:
            raise ValidationError(
                f"Incident '{payload.incident_id}' does not exist or does not belong to authorized tenant."
            )
        inc_entity, _ = res
        if inc_entity.status == IncidentStatus.RESOLVED.value:
            raise ValidationError(
                f"Cannot link quarantine to incident '{clean_inc_id}' because it is already RESOLVED."
            )

    # 3. Durable evidence, written by the workflow AFTER the trust transition is applied.
    #    If it fails, the record stays QUARANTINED (fail toward restriction) and the request fails.
    async def persist_evidence(outcome: Any) -> None:
        now = datetime.now(timezone.utc)
        quarantine_entity = QuarantineEntity(
            id=f"quar-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            record_id=clean_record_id,
            incident_id=clean_inc_id,
            reason=payload.reason,
            quarantined_by=actor_id,
            created_at=now,
        )
        audit_event = AuditEventEntity(
            id=f"aud-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            actor_id=actor_id,
            event_type="MEMORY_QUARANTINED",
            resource_id=clean_record_id,
            action="QUARANTINE_RECORD",
            outcome="SUCCESS",
            trace_id=getattr(request.state, "trace_id", None),
            details_json={
                "reason": payload.reason,
                "analyst_notes": payload.analyst_notes,
                "incident_id": clean_inc_id,
                "previous_state": outcome.previous_state,
                "new_state": "QUARANTINED",
                "trust_decision_id": outcome.trust_decision_id,
                "transition_id": outcome.transition_id,
                "record_version": outcome.record_version,
                "policy_version": outcome.policy_version,
                **({"branch_id": user_branch} if user_branch else {}),
            },
            occurred_at=now,
        )
        await incident_repo.create_quarantine_atomic(
            quarantine=quarantine_entity,
            audit_event=audit_event,
            incident_id=clean_inc_id,
        )

    # 4. Authoritative M4 workflow (role check, matrix, ledger, post-conditions).
    workflow = get_quarantine_workflow(request.app.state, mem_repo)
    quarantine_request: Dict[str, Any] = {"record_id": clean_record_id, "reason": payload.reason}
    if payload.analyst_notes:
        quarantine_request["analyst_notes"] = payload.analyst_notes
    if clean_inc_id:
        quarantine_request["incident_id"] = clean_inc_id
    outcome = await workflow.quarantine(tenant_context, quarantine_request, persist_evidence=persist_evidence)
    if not outcome.success:
        logger.error(
            "Quarantine not completed",
            extra={
                "event_id": "SEC-QUARANTINE-NOT-COMPLETED",
                "status": outcome.status.value,
                "reason_codes": list(outcome.reason_codes),
                "record_id": clean_record_id,
                "tenant_id": tenant_id,
            },
        )
    raise_for_outcome(outcome)

    previous_state = outcome.previous_state or TrustState.QUARANTINED.value
    return MemoryQuarantineResponse(
        id=clean_record_id,
        previous_state=previous_state,
        trust_state=TrustState.QUARANTINED.value,
        message="Record successfully quarantined and excluded from protected agent retrieval.",
    )


@memory_quarantine_router.post(
    "/{record_id}/quarantine",
    response_model=MemoryQuarantineResponse,
    status_code=status.HTTP_200_OK,
    summary="Quarantine memory record (Canonical Route)",
    description="Authoritative M4 quarantine isolation matching AMSC-DOC-005 Section 5.1 & 6.2.",
)
async def canonical_quarantine_memory(
    record_id: str,
    payload: MemoryQuarantineRequest,
    request: Request,
    tenant_context: TenantContext = Depends(require_roles("SECURITY_ANALYST", "TENANT_ADMIN")),
    mem_repo: MemoryRepository = Depends(get_memory_repository),
    incident_repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> MemoryQuarantineResponse:
    """Canonical quarantine endpoint at /api/v1/memory/{record_id}/quarantine."""
    quarantine_service = getattr(request.app.state, "quarantine_service", None) or get_default_quarantine_service()
    return await _execute_quarantine_flow(
        record_id=record_id,
        payload=payload,
        request=request,
        tenant_context=tenant_context,
        mem_repo=mem_repo,
        incident_repo=incident_repo,
        quarantine_service=quarantine_service,
    )


@router.post(
    "/memory/{record_id}/quarantine",
    response_model=MemoryQuarantineResponse,
    status_code=status.HTTP_200_OK,
    summary="Quarantine memory record (Security Center Alias)",
    description="Security workstation route alias mapping to authoritative M4 quarantine isolation.",
)
async def security_alias_quarantine_memory(
    record_id: str,
    payload: MemoryQuarantineRequest,
    request: Request,
    tenant_context: TenantContext = Depends(require_roles("SECURITY_ANALYST", "TENANT_ADMIN")),
    mem_repo: MemoryRepository = Depends(get_memory_repository),
    incident_repo: IncidentRepositoryProtocol = Depends(get_incident_repository),
) -> MemoryQuarantineResponse:
    """Security center workstation alias at /api/v1/security/memory/{record_id}/quarantine."""
    quarantine_service = getattr(request.app.state, "quarantine_service", None) or get_default_quarantine_service()
    return await _execute_quarantine_flow(
        record_id=record_id,
        payload=payload,
        request=request,
        tenant_context=tenant_context,
        mem_repo=mem_repo,
        incident_repo=incident_repo,
        quarantine_service=quarantine_service,
    )
