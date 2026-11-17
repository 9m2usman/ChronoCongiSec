"""Protected Tool Gateway API & Fail-Closed Enforcement.

Module: backend.app.api.gateway
Owner: M1 — Platform Backend & API Integration Lead

Canonical References:
- AMSC-DOC-002 (TRD/SRS) Section 5: Security Architecture & Complete Mediation
- AMSC-DOC-005 (Database & API Schema) Section 3.4: Tool Proposals, Decisions & Executions
- AMSC-DOC-005 Section 5.1: Route Catalog (POST /gateway/actions/propose, GET /gateway/actions/{id})
- AMSC-DOC-005 Section 6.1: Canonical Action Proposal & Policy Decision JSON Schemas
- AMSC-DOC-006 (Team Implementation Plan) Day 4: Protected Tool Gateway (Exit Gate G4)
- AMSC-DOC-007 (Research & Engineering Standards): Complete Mediation, Fail-Closed, Replay Resistance
- AMSC-DOC-008: GAPs 001-004, 006, 010, 015, 018-028 (Security Gap Register)
"""

import asyncio
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import math
import re
import time
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.config import Settings, get_settings
from backend.app.core.dependencies import (
    CurrentUserDep,
    RateLimiterDep,
    SettingsDep,
    TenantContextDep,
    get_tenant_context,
    require_roles,
)
from backend.app.core.exceptions import (
    AMSCException,
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.memory.hashing import sha256_hex
from backend.app.memory.models import TrustState
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.gateway")

# Strict ID validation regex
SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")

# Maximum parameters payload serialization length (64 KB)
MAX_PARAMETERS_JSON_BYTES = 65536
# Maximum parameter nesting depth
MAX_PARAMETERS_DEPTH = 5
# Maximum memory references per proposal
MAX_MEMORY_REFS_COUNT = 50


# ============================================================================
# 1. Enums and Canonical Status Types
# ============================================================================

class GatewayDecision(str, Enum):
    """Deterministic policy outcomes per AMSC-DOC-005 Table 17."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"  # Also known as REQUIRES_APPROVAL


class MemoryTrustDecision(str, Enum):
    """Memory trust classification per AMSC-DOC-005 Table 17."""
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"
    UNVERIFIED = "UNVERIFIED"
    NOT_REFERENCED = "NOT_REFERENCED"


class PolicyResult(str, Enum):
    """Policy authorization result per AMSC-DOC-005 Table 17."""
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    ELEVATED = "ELEVATED"


class ExecutionStatus(str, Enum):
    """Tool execution state per AMSC-DOC-005 Table 17 & 19."""
    EXECUTED = "EXECUTED"
    NOT_EXECUTED = "NOT_EXECUTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    PENDING_EXECUTION = "PENDING_EXECUTION"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


# ============================================================================
# 2. DTOs and Validation Models (Pydantic v2)
# ============================================================================

def _validate_finite_and_depth(val: Any, current_depth: int = 1) -> None:
    """Recursively enforce parameter depth and numeric finiteness."""
    if current_depth > MAX_PARAMETERS_DEPTH:
        raise ValueError(
            f"Parameter nesting depth ({current_depth}) exceeds maximum allowable depth ({MAX_PARAMETERS_DEPTH})."
        )
    if isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError("Numeric parameters must be finite (NaN and Infinity are forbidden).")
    elif isinstance(val, dict):
        for k, v in val.items():
            if not isinstance(k, str) or len(k) > 128:
                raise ValueError("Parameter keys must be strings with length <= 128.")
            _validate_finite_and_depth(v, current_depth + 1)
    elif isinstance(val, (list, tuple)):
        if len(val) > 200:
            raise ValueError("Parameter list sizes must not exceed 200 elements.")
        for item in val:
            _validate_finite_and_depth(item, current_depth + 1)


class ActionProposalRequest(BaseModel):
    """Canonical Tool Action Proposal Request per AMSC-DOC-005 Section 6.1."""

    action_id: str = Field(..., min_length=1, max_length=128, description="Client action identifier")
    agent_id: str = Field(..., min_length=1, max_length=64, description="Agent UUID submitting the action")
    tool_name: str = Field(..., min_length=1, max_length=128, description="Target tool identifier")
    operation: str = Field(..., min_length=1, max_length=128, description="Target tool operation name")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool operational parameters")
    memory_refs: List[str] = Field(
        default_factory=list,
        max_length=MAX_MEMORY_REFS_COUNT,
        description="Memory record IDs backing this action",
    )
    idempotency_key: str = Field(..., min_length=1, max_length=255, description="Client idempotency key")
    trace_id: str = Field(..., min_length=1, max_length=128, description="W3C trace context identifier")

    model_config = ConfigDict(extra="forbid")

    @field_validator("action_id", "agent_id", "tool_name", "operation", "idempotency_key", "trace_id")
    @classmethod
    def validate_identifier_format(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Identifiers cannot be empty or whitespace only.")
        if any(c in s for c in ("\x00", "\r", "\n")):
            raise ValueError("Identifiers cannot contain control characters.")
        return s

    @field_validator("memory_refs")
    @classmethod
    def validate_memory_refs(cls, refs: List[str]) -> List[str]:
        cleaned: List[str] = []
        for ref in refs:
            s = ref.strip()
            if not s or not SAFE_ID_REGEX.match(s):
                raise ValueError(f"Invalid memory reference format: '{ref}'")
            cleaned.append(s)
        return cleaned

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        _validate_finite_and_depth(params, current_depth=1)
        try:
            serialized = json.dumps(params, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Parameters must be JSON-serializable: {exc}") from exc
        if len(serialized.encode("utf-8")) > MAX_PARAMETERS_JSON_BYTES:
            raise ValueError(
                f"Parameters payload size exceeds limit ({MAX_PARAMETERS_JSON_BYTES} bytes)."
            )
        return params


class ActionProposalResponse(BaseModel):
    """Canonical Action Proposal & Decision Response per AMSC-DOC-005 Section 6.1."""

    action_id: str
    proposal_id: str
    decision: str  # ALLOW, BLOCK, REVIEW
    memory_trust: str  # TRUSTED, SUSPICIOUS, QUARANTINED, NOT_REFERENCED, UNVERIFIED
    policy_result: str  # PERMITTED, DENIED, ELEVATED
    reasons: List[str] = Field(default_factory=list)
    execution_status: str  # EXECUTED, NOT_EXECUTED, PENDING_APPROVAL, PENDING_EXECUTION, FAILED, UNKNOWN
    result: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="forbid")


class ProposalDetailResponse(BaseModel):
    """Detailed inspection response for GET /gateway/actions/{id}."""

    proposal_id: str
    tenant_id: str
    agent_id: str
    action_id: str
    tool_name: str
    operation: str
    parameters: Dict[str, Any]
    memory_refs: List[str]
    idempotency_key: str
    trace_id: str
    decision: str
    memory_trust: str
    policy_result: str
    reasons: List[str]
    execution_status: str
    execution_result: Optional[Dict[str, Any]] = None
    created_at: str

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# 3. Payload Fingerprinting & Secret Redaction
# ============================================================================

SECRET_FIELD_PATTERN = re.compile(
    r"(?i)(password|secret|token|auth|credential|api_key|access_key|private_key|card_number|cvv|pin|bearer)"
)


def compute_payload_fingerprint(
    agent_id: str,
    action_id: str,
    tool_name: str,
    operation: str,
    parameters: Dict[str, Any],
    memory_refs: List[str],
) -> str:
    """Compute deterministic cryptographic SHA-256 fingerprint of proposal payload.

    Canonicalizes fields and JSON representation so whitespace and key ordering
    do not produce spurious mismatches.
    """
    sorted_memory_refs = sorted(memory_refs)
    canonical_repr = {
        "action_id": action_id,
        "agent_id": agent_id,
        "memory_refs": sorted_memory_refs,
        "operation": operation,
        "parameters": parameters,
        "tool_name": tool_name,
    }
    encoded = json.dumps(canonical_repr, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def redact_sensitive_payload(data: Any) -> Any:
    """Recursively redact sensitive tokens, passwords, and secrets from parameters for audit logs."""
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if SECRET_FIELD_PATTERN.search(k):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_payload(v)
        return redacted
    elif isinstance(data, (list, tuple)):
        return [redact_sensitive_payload(item) for item in data]
    return data


# ============================================================================
# 4. Domain Entities (M6 Relational Alignment)
# ============================================================================

@dataclass
class ToolProposalEntity:
    id: str
    tenant_id: str
    agent_id: str
    action_id: str
    tool_name: str
    operation: str
    parameters_json: Dict[str, Any]
    memory_refs_json: List[str]
    idempotency_key: str
    trace_id: str
    payload_fingerprint: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_fingerprint(self) -> str:
        """Derive deterministic fingerprint from canonical proposal fields."""
        if self.payload_fingerprint:
            return self.payload_fingerprint
        return compute_payload_fingerprint(
            agent_id=self.agent_id,
            action_id=self.action_id,
            tool_name=self.tool_name,
            operation=self.operation,
            parameters=self.parameters_json,
            memory_refs=self.memory_refs_json,
        )


@dataclass
class PolicyDecisionEntity:
    id: str
    tenant_id: str
    proposal_id: str
    decision: str
    memory_trust: str
    policy_result: str
    reasons_json: List[str]
    incident_id: Optional[str] = None
    execution_status: str = "NOT_EXECUTED"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ToolExecutionEntity:
    id: str
    tenant_id: str
    proposal_id: str
    decision_id: str
    status: str
    status_code: int
    result_payload_json: Dict[str, Any]
    duration_ms: int
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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
# 5. Gateway Repository Protocol, In-Memory & SQLAlchemy Implementations
# ============================================================================

@runtime_checkable
class GatewayRepositoryProtocol(Protocol):
    """Repository boundary for M6 Gateway persistence."""

    is_persistent: bool
    is_in_memory: bool

    async def save_proposal_atomic(
        self,
        proposal: ToolProposalEntity,
        decision: PolicyDecisionEntity,
        execution: Optional[ToolExecutionEntity] = None,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        """Atomically persist proposal, decision, and optional audit event."""
        ...

    async def record_execution_outcome(
        self,
        tenant_id: str,
        proposal_id: str,
        decision_id: str,
        execution: ToolExecutionEntity,
        execution_status: str,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        """Update decision execution_status and record ToolExecution outcome atomically."""
        ...

    async def get_by_idempotency_key(
        self,
        tenant_id: str,
        idempotency_key: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        """Fetch proposal record by tenant and idempotency key."""
        ...

    async def get_by_id(
        self,
        tenant_id: str,
        proposal_id: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        """Fetch proposal record by tenant and proposal ID."""
        ...

    async def list_proposals(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        """List proposals for tenant."""
        ...


class InMemoryGatewayRepository:
    """Thread-safe development and test gateway repository.

    Strictly forbidden in production environments.
    """

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        self._proposals: Dict[str, ToolProposalEntity] = {}
        self._decisions: Dict[str, PolicyDecisionEntity] = {}
        self._executions: Dict[str, ToolExecutionEntity] = {}
        self._idempotency_index: Dict[Tuple[str, str], str] = {}
        self._audit_events: List[AuditEventEntity] = []

        # Test hooks
        self.fail_decision_save: bool = False
        self.simulate_db_race: bool = False

    async def save_proposal_atomic(
        self,
        proposal: ToolProposalEntity,
        decision: PolicyDecisionEntity,
        execution: Optional[ToolExecutionEntity] = None,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        key = (proposal.tenant_id, proposal.idempotency_key)
        if key in self._idempotency_index:
            raise AMSCException(
                message="Duplicate idempotency key detected under unique constraint.",
                code="IDEMPOTENCY_KEY_CONFLICT",
                status_code=409,
            )

        if self.fail_decision_save:
            raise AMSCException(
                message="Simulated transaction failure during policy decision persistence.",
                code="TRANSACTION_ROLLBACK",
                status_code=500,
            )

        # Stage and commit atomically
        staged_proposal = deepcopy(proposal)
        staged_decision = deepcopy(decision)
        staged_execution = deepcopy(execution) if execution else None
        staged_audit = deepcopy(audit_event) if audit_event else None

        self._proposals[proposal.id] = staged_proposal
        self._decisions[proposal.id] = staged_decision
        if staged_execution:
            self._executions[proposal.id] = staged_execution
        self._idempotency_index[key] = proposal.id

        if staged_audit:
            self._audit_events.append(staged_audit)

    async def record_execution_outcome(
        self,
        tenant_id: str,
        proposal_id: str,
        decision_id: str,
        execution: ToolExecutionEntity,
        execution_status: str,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        if proposal_id in self._decisions:
            self._decisions[proposal_id].execution_status = execution_status
        self._executions[proposal_id] = deepcopy(execution)
        if audit_event:
            self._audit_events.append(deepcopy(audit_event))

    async def get_by_idempotency_key(
        self,
        tenant_id: str,
        idempotency_key: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        key = (tenant_id, idempotency_key)
        proposal_id = self._idempotency_index.get(key)
        if not proposal_id:
            return None
        proposal = self._proposals.get(proposal_id)
        if not proposal or proposal.tenant_id != tenant_id:
            return None
        decision = self._decisions.get(proposal_id)
        execution = self._executions.get(proposal_id)
        return (deepcopy(proposal), deepcopy(decision), deepcopy(execution) if execution else None)

    async def get_by_id(
        self,
        tenant_id: str,
        proposal_id: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        proposal = self._proposals.get(proposal_id)
        if not proposal or proposal.tenant_id != tenant_id:
            return None
        decision = self._decisions.get(proposal_id)
        execution = self._executions.get(proposal_id)
        return (deepcopy(proposal), deepcopy(decision), deepcopy(execution) if execution else None)

    async def list_proposals(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        results = []
        for prop in self._proposals.values():
            if prop.tenant_id == tenant_id:
                dec = self._decisions.get(prop.id)
                exe = self._executions.get(prop.id)
                results.append((deepcopy(prop), deepcopy(dec), deepcopy(exe) if exe else None))
        results.sort(key=lambda item: item[0].created_at, reverse=True)
        return results[offset : offset + limit]

    def get_audit_events(self, tenant_id: str) -> List[AuditEventEntity]:
        """Test helper to inspect recorded audit events for tenant."""
        return [deepcopy(e) for e in self._audit_events if e.tenant_id == tenant_id]


class SqlAlchemyGatewayRepository:
    """Production persistent gateway repository backed by PostgreSQL & SQLAlchemy (M6).

    Guarantees durable idempotency under database unique constraint (tenant_id, idempotency_key).
    """

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def save_proposal_atomic(
        self,
        proposal: ToolProposalEntity,
        decision: PolicyDecisionEntity,
        execution: Optional[ToolExecutionEntity] = None,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        from backend.app.database.models.gateway import PolicyDecision as DbPolicyDecision
        from backend.app.database.models.gateway import ToolExecution as DbToolExecution
        from backend.app.database.models.gateway import ToolProposal as DbToolProposal
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent

        async with self.session_factory() as session:
            async with session.begin():
                stmt = select(DbToolProposal).where(
                    DbToolProposal.tenant_id == proposal.tenant_id,
                    DbToolProposal.idempotency_key == proposal.idempotency_key,
                )
                existing = (await session.execute(stmt)).scalar_one_or_none()
                if existing:
                    raise AMSCException(
                        message="Duplicate idempotency key detected under unique constraint.",
                        code="IDEMPOTENCY_KEY_CONFLICT",
                        status_code=409,
                    )

                db_prop = DbToolProposal(
                    id=proposal.id,
                    tenant_id=proposal.tenant_id,
                    agent_id=proposal.agent_id,
                    action_id=proposal.action_id,
                    tool_name=proposal.tool_name,
                    operation=proposal.operation,
                    parameters_json=proposal.parameters_json,
                    memory_refs_json=proposal.memory_refs_json,
                    idempotency_key=proposal.idempotency_key,
                    trace_id=proposal.trace_id,
                )
                session.add(db_prop)

                db_dec = DbPolicyDecision(
                    id=decision.id,
                    tenant_id=decision.tenant_id,
                    proposal_id=decision.proposal_id,
                    decision=decision.decision,
                    memory_trust=decision.memory_trust,
                    policy_result=decision.policy_result,
                    reasons_json=decision.reasons_json,
                    incident_id=decision.incident_id,
                    execution_status=decision.execution_status,
                )
                session.add(db_dec)

                if execution:
                    db_exec = DbToolExecution(
                        id=execution.id,
                        tenant_id=execution.tenant_id,
                        proposal_id=execution.proposal_id,
                        decision_id=execution.decision_id,
                        status=execution.status,
                        status_code=execution.status_code,
                        result_payload_json=execution.result_payload_json,
                        duration_ms=execution.duration_ms,
                    )
                    session.add(db_exec)

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
                    )
                    session.add(db_audit)

                try:
                    await session.commit()
                except IntegrityError as exc:
                    await session.rollback()
                    raise AMSCException(
                        message="Duplicate idempotency key detected under unique constraint.",
                        code="IDEMPOTENCY_KEY_CONFLICT",
                        status_code=409,
                    ) from exc

    async def record_execution_outcome(
        self,
        tenant_id: str,
        proposal_id: str,
        decision_id: str,
        execution: ToolExecutionEntity,
        execution_status: str,
        audit_event: Optional[AuditEventEntity] = None,
    ) -> None:
        from backend.app.database.models.gateway import PolicyDecision as DbPolicyDecision
        from backend.app.database.models.gateway import ToolExecution as DbToolExecution
        from backend.app.database.models.observability import AuditEvent as DbAuditEvent

        async with self.session_factory() as session:
            async with session.begin():
                stmt_dec = (
                    update(DbPolicyDecision)
                    .where(
                        DbPolicyDecision.id == decision_id,
                        DbPolicyDecision.tenant_id == tenant_id,
                    )
                    .values(execution_status=execution_status)
                )
                await session.execute(stmt_dec)

                db_exec = DbToolExecution(
                    id=execution.id,
                    tenant_id=execution.tenant_id,
                    proposal_id=execution.proposal_id,
                    decision_id=execution.decision_id,
                    status=execution.status,
                    status_code=execution.status_code,
                    result_payload_json=execution.result_payload_json,
                    duration_ms=execution.duration_ms,
                )
                session.add(db_exec)

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
                    )
                    session.add(db_audit)

                await session.commit()

    async def get_by_idempotency_key(
        self,
        tenant_id: str,
        idempotency_key: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        from backend.app.database.models.gateway import PolicyDecision as DbPolicyDecision
        from backend.app.database.models.gateway import ToolExecution as DbToolExecution
        from backend.app.database.models.gateway import ToolProposal as DbToolProposal

        async with self.session_factory() as session:
            stmt = (
                select(DbToolProposal, DbPolicyDecision, DbToolExecution)
                .join(DbPolicyDecision, DbPolicyDecision.proposal_id == DbToolProposal.id)
                .outerjoin(DbToolExecution, DbToolExecution.proposal_id == DbToolProposal.id)
                .where(
                    DbToolProposal.tenant_id == tenant_id,
                    DbToolProposal.idempotency_key == idempotency_key,
                )
            )
            res = (await session.execute(stmt)).first()
            if not res:
                return None
            prop, dec, exe = res

            proposal_entity = ToolProposalEntity(
                id=prop.id,
                tenant_id=prop.tenant_id,
                agent_id=prop.agent_id,
                action_id=prop.action_id,
                tool_name=prop.tool_name,
                operation=prop.operation,
                parameters_json=dict(prop.parameters_json),
                memory_refs_json=list(prop.memory_refs_json),
                idempotency_key=prop.idempotency_key,
                trace_id=prop.trace_id,
                created_at=prop.created_at,
            )
            decision_entity = PolicyDecisionEntity(
                id=dec.id,
                tenant_id=dec.tenant_id,
                proposal_id=dec.proposal_id,
                decision=dec.decision,
                memory_trust=dec.memory_trust,
                policy_result=dec.policy_result,
                reasons_json=list(dec.reasons_json),
                incident_id=dec.incident_id,
                execution_status=dec.execution_status,
                created_at=dec.created_at,
            )
            execution_entity = (
                ToolExecutionEntity(
                    id=exe.id,
                    tenant_id=exe.tenant_id,
                    proposal_id=exe.proposal_id,
                    decision_id=exe.decision_id,
                    status=exe.status,
                    status_code=exe.status_code,
                    result_payload_json=dict(exe.result_payload_json),
                    duration_ms=exe.duration_ms,
                    executed_at=exe.executed_at,
                )
                if exe
                else None
            )
            return (proposal_entity, decision_entity, execution_entity)

    async def get_by_id(
        self,
        tenant_id: str,
        proposal_id: str,
    ) -> Optional[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        from backend.app.database.models.gateway import PolicyDecision as DbPolicyDecision
        from backend.app.database.models.gateway import ToolExecution as DbToolExecution
        from backend.app.database.models.gateway import ToolProposal as DbToolProposal

        async with self.session_factory() as session:
            stmt = (
                select(DbToolProposal, DbPolicyDecision, DbToolExecution)
                .join(DbPolicyDecision, DbPolicyDecision.proposal_id == DbToolProposal.id)
                .outerjoin(DbToolExecution, DbToolExecution.proposal_id == DbToolProposal.id)
                .where(
                    DbToolProposal.tenant_id == tenant_id,
                    DbToolProposal.id == proposal_id,
                )
            )
            res = (await session.execute(stmt)).first()
            if not res:
                return None
            prop, dec, exe = res

            proposal_entity = ToolProposalEntity(
                id=prop.id,
                tenant_id=prop.tenant_id,
                agent_id=prop.agent_id,
                action_id=prop.action_id,
                tool_name=prop.tool_name,
                operation=prop.operation,
                parameters_json=dict(prop.parameters_json),
                memory_refs_json=list(prop.memory_refs_json),
                idempotency_key=prop.idempotency_key,
                trace_id=prop.trace_id,
                created_at=prop.created_at,
            )
            decision_entity = PolicyDecisionEntity(
                id=dec.id,
                tenant_id=dec.tenant_id,
                proposal_id=dec.proposal_id,
                decision=dec.decision,
                memory_trust=dec.memory_trust,
                policy_result=dec.policy_result,
                reasons_json=list(dec.reasons_json),
                incident_id=dec.incident_id,
                execution_status=dec.execution_status,
                created_at=dec.created_at,
            )
            execution_entity = (
                ToolExecutionEntity(
                    id=exe.id,
                    tenant_id=exe.tenant_id,
                    proposal_id=exe.proposal_id,
                    decision_id=exe.decision_id,
                    status=exe.status,
                    status_code=exe.status_code,
                    result_payload_json=dict(exe.result_payload_json),
                    duration_ms=exe.duration_ms,
                    executed_at=exe.executed_at,
                )
                if exe
                else None
            )
            return (proposal_entity, decision_entity, execution_entity)

    async def list_proposals(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Tuple[ToolProposalEntity, PolicyDecisionEntity, Optional[ToolExecutionEntity]]]:
        from backend.app.database.models.gateway import PolicyDecision as DbPolicyDecision
        from backend.app.database.models.gateway import ToolExecution as DbToolExecution
        from backend.app.database.models.gateway import ToolProposal as DbToolProposal

        async with self.session_factory() as session:
            stmt = (
                select(DbToolProposal, DbPolicyDecision, DbToolExecution)
                .join(DbPolicyDecision, DbPolicyDecision.proposal_id == DbToolProposal.id)
                .outerjoin(DbToolExecution, DbToolExecution.proposal_id == DbToolProposal.id)
                .where(DbToolProposal.tenant_id == tenant_id)
                .order_by(DbToolProposal.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            rows = (await session.execute(stmt)).all()
            results = []
            for prop, dec, exe in rows:
                p_ent = ToolProposalEntity(
                    id=prop.id,
                    tenant_id=prop.tenant_id,
                    agent_id=prop.agent_id,
                    action_id=prop.action_id,
                    tool_name=prop.tool_name,
                    operation=prop.operation,
                    parameters_json=dict(prop.parameters_json),
                    memory_refs_json=list(prop.memory_refs_json),
                    idempotency_key=prop.idempotency_key,
                    trace_id=prop.trace_id,
                    created_at=prop.created_at,
                )
                d_ent = PolicyDecisionEntity(
                    id=dec.id,
                    tenant_id=dec.tenant_id,
                    proposal_id=dec.proposal_id,
                    decision=dec.decision,
                    memory_trust=dec.memory_trust,
                    policy_result=dec.policy_result,
                    reasons_json=list(dec.reasons_json),
                    incident_id=dec.incident_id,
                    execution_status=dec.execution_status,
                    created_at=dec.created_at,
                )
                e_ent = (
                    ToolExecutionEntity(
                        id=exe.id,
                        tenant_id=exe.tenant_id,
                        proposal_id=exe.proposal_id,
                        decision_id=exe.decision_id,
                        status=exe.status,
                        status_code=exe.status_code,
                        result_payload_json=dict(exe.result_payload_json),
                        duration_ms=exe.duration_ms,
                        executed_at=exe.executed_at,
                    )
                    if exe
                    else None
                )
                results.append((p_ent, d_ent, e_ent))
            return results


_default_gateway_repository: Optional[GatewayRepositoryProtocol] = None


def get_default_gateway_repository(settings: Optional[Settings] = None) -> GatewayRepositoryProtocol:
    global _default_gateway_repository
    cfg = settings or get_settings()
    if cfg.APP_ENV == "production":
        raise RuntimeError(
            "Security violation: InMemoryGatewayRepository cannot be used in production."
        )
    if _default_gateway_repository is None:
        _default_gateway_repository = InMemoryGatewayRepository()
    return _default_gateway_repository


def set_default_gateway_repository(repo: Optional[GatewayRepositoryProtocol]) -> None:
    global _default_gateway_repository
    _default_gateway_repository = repo


async def get_gateway_repository(request: Request) -> GatewayRepositoryProtocol:
    repo = getattr(request.app.state, "gateway_repo", None)
    if repo is not None:
        return repo
    settings: Settings = getattr(request.app.state, "settings", None) or get_settings()
    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Database gateway repository is not configured.")
    return get_default_gateway_repository(settings)


GatewayRepoDep = GatewayRepositoryProtocol


# ============================================================================
# 6. M2 Tool Adapter Boundary & Registry
# ============================================================================

@dataclass
class ToolExecutionResult:
    status: str  # SUCCESS, FAILED, TIMEOUT
    status_code: int
    result_payload: Dict[str, Any]
    duration_ms: int


@runtime_checkable
class ToolAdapterProtocol(Protocol):
    """Protocol for server-side tool execution adapter owned by M2."""

    async def execute(
        self,
        operation: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
    ) -> ToolExecutionResult:
        ...


class SandboxTransferAdapter:
    """Mock financial transfer adapter per AMSC-DOC-005 Section 6.1.

    Enforces destination allowlisting and parameter constraints.
    """

    ALLOWED_OPERATIONS = {"transfer_funds", "get_balance"}
    FORBIDDEN_DESTINATIONS = {"ACC-ATTACKER-999", "ACC-BLOCKED-000"}

    async def execute(
        self,
        operation: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
    ) -> ToolExecutionResult:
        start_time = time.perf_counter()
        if operation not in self.ALLOWED_OPERATIONS:
            return ToolExecutionResult(
                status="FAILED",
                status_code=400,
                result_payload={"error": f"Unsupported operation '{operation}' for sandbox_transfer."},
                duration_ms=int((time.perf_counter() - start_time) * 1000),
            )

        destination = str(parameters.get("destination_account", ""))
        amount = float(parameters.get("amount", 0.0))
        currency = str(parameters.get("currency", "USD"))

        # Destination boundary check
        if destination in self.FORBIDDEN_DESTINATIONS:
            return ToolExecutionResult(
                status="FAILED",
                status_code=403,
                result_payload={"error": f"Destination account '{destination}' is blacklisted."},
                duration_ms=int((time.perf_counter() - start_time) * 1000),
            )

        duration = int((time.perf_counter() - start_time) * 1000)
        return ToolExecutionResult(
            status="SUCCESS",
            status_code=200,
            result_payload={
                "transaction_id": f"tx-sbx-{uuid.uuid4().hex[:12]}",
                "destination_account": destination,
                "amount": amount,
                "currency": currency,
                "status": "SETTLED_IN_SANDBOX",
            },
            duration_ms=duration,
        )


class ToolAdapterRegistry:
    """Registry coordinating available tool adapters for M2."""

    def __init__(self) -> None:
        self._adapters: Dict[str, ToolAdapterProtocol] = {
            "sandbox_transfer": SandboxTransferAdapter(),
        }

    def register(self, tool_name: str, adapter: ToolAdapterProtocol) -> None:
        self._adapters[tool_name] = adapter

    def get_adapter(self, tool_name: str) -> Optional[ToolAdapterProtocol]:
        return self._adapters.get(tool_name)

    def is_tool_registered(self, tool_name: str) -> bool:
        return tool_name in self._adapters


_default_tool_registry = ToolAdapterRegistry()


def get_default_tool_registry() -> ToolAdapterRegistry:
    return _default_tool_registry


# ============================================================================
# 7. M4 Policy Engine Boundary & Deterministic Evaluator
# ============================================================================

@dataclass
class PolicyEvaluationInput:
    tenant_id: str
    agent_id: str
    agent_status: str
    tool_name: str
    operation: str
    parameters: Dict[str, Any]
    memory_refs: List[str]
    memory_trust_state: str  # TRUSTED, SUSPICIOUS, QUARANTINED, NOT_REFERENCED, UNVERIFIED
    memory_reasons: List[str]


@dataclass
class PolicyEvaluationOutput:
    decision: GatewayDecision
    memory_trust: MemoryTrustDecision
    policy_result: PolicyResult
    reasons: List[str]


class DeterministicPolicyEvaluator:
    """Deterministic policy engine implementing AMSC-DOC-002, 005, and 006 rules.

    Rules:
    1. Fail-closed: If memory is tainted (SUSPICIOUS, QUARANTINED, UNVERIFIED, REJECTED), decision is BLOCK.
    2. Tool validation: Tool must be registered.
    3. Ceilings: For sandbox_transfer, amount > 300.00 requires dual custody / exceeds threshold -> BLOCK.
    """

    DUAL_CUSTODY_THRESHOLD_USD = 300.00
    MAX_ALLOWABLE_TRANSFER_USD = 50000.00

    def evaluate(self, inp: PolicyEvaluationInput) -> PolicyEvaluationOutput:
        reasons: List[str] = list(inp.memory_reasons)

        # 1. Memory Trust Enforcement (Absolute fail-closed rule)
        if inp.memory_trust_state in ("SUSPICIOUS", "QUARANTINED", "REJECTED"):
            return PolicyEvaluationOutput(
                decision=GatewayDecision.BLOCK,
                memory_trust=MemoryTrustDecision(inp.memory_trust_state),
                policy_result=PolicyResult.DENIED,
                reasons=reasons,
            )
        elif inp.memory_trust_state == "UNVERIFIED":
            reasons.append("Unverified memory cannot back protected tool actions.")
            return PolicyEvaluationOutput(
                decision=GatewayDecision.BLOCK,
                memory_trust=MemoryTrustDecision.UNVERIFIED,
                policy_result=PolicyResult.DENIED,
                reasons=reasons,
            )

        resolved_trust = (
            MemoryTrustDecision.NOT_REFERENCED
            if inp.memory_trust_state == "NOT_REFERENCED"
            else MemoryTrustDecision.TRUSTED
        )

        # 2. Tool-Specific Ceilings & Rules
        if inp.tool_name == "sandbox_transfer" and inp.operation == "transfer_funds":
            amount = float(inp.parameters.get("amount", 0.0))
            if amount < 0:
                reasons.append("Negative transfer amounts are forbidden.")
                return PolicyEvaluationOutput(
                    decision=GatewayDecision.BLOCK,
                    memory_trust=resolved_trust,
                    policy_result=PolicyResult.DENIED,
                    reasons=reasons,
                )
            if amount > self.MAX_ALLOWABLE_TRANSFER_USD:
                reasons.append(
                    f"Action amount (${amount:.2f}) exceeds absolute ceiling (${self.MAX_ALLOWABLE_TRANSFER_USD:.2f})."
                )
                return PolicyEvaluationOutput(
                    decision=GatewayDecision.BLOCK,
                    memory_trust=resolved_trust,
                    policy_result=PolicyResult.DENIED,
                    reasons=reasons,
                )
            if amount > self.DUAL_CUSTODY_THRESHOLD_USD:
                reasons.append(
                    f"Action amount (${amount:.2f}) exceeds dual-custody threshold (${self.DUAL_CUSTODY_THRESHOLD_USD:.2f})."
                )
                return PolicyEvaluationOutput(
                    decision=GatewayDecision.BLOCK,
                    memory_trust=resolved_trust,
                    policy_result=PolicyResult.DENIED,
                    reasons=reasons,
                )

        # 3. All checks passed
        return PolicyEvaluationOutput(
            decision=GatewayDecision.ALLOW,
            memory_trust=resolved_trust,
            policy_result=PolicyResult.PERMITTED,
            reasons=["All authorization, trust-state, and operational ceiling checks passed."],
        )


_default_policy_evaluator = DeterministicPolicyEvaluator()


def get_default_policy_evaluator() -> DeterministicPolicyEvaluator:
    return _default_policy_evaluator


# ============================================================================
# 8. Gateway Router Endpoints
# ============================================================================

router = APIRouter(prefix="/gateway", tags=["Gateway"])

# Roles strictly forbidden from submitting mutating tool action proposals
UNAUTHORIZED_PROPOSAL_ROLES = frozenset({"AUDITOR", "READ_ONLY", "GUEST"})


@router.post(
    "/actions/propose",
    response_model=ActionProposalResponse,
    status_code=status.HTTP_200_OK,
    summary="Propose Tool Action & Evaluate Security Policy",
    description=(
        "Core Protected Tool Gateway ingress. Enforces tenant boundaries, agent authentication, "
        "memory trust provenance, cryptographic checksum verification, deterministic policy ceilings, "
        "durable idempotency, and fail-closed blocking before tool execution."
    ),
    responses={
        200: {"description": "Action proposal evaluated successfully (decision may be ALLOW, BLOCK, or REVIEW)"},
        400: {"description": "Malformed request or parameter ceiling violation"},
        401: {"description": "Missing or invalid bearer token"},
        403: {"description": "Agent not active, cross-tenant agent access, or unauthorized caller role"},
        404: {"description": "Agent not found in authenticated tenant"},
        409: {"description": "Idempotency key reused with mismatched request payload or proposal currently executing"},
        422: {"description": "Validation error or invalid parameter types"},
        500: {"description": "Internal error or memory integrity violation"},
        503: {"description": "Mandatory security dependency unavailable"},
    },
)
async def propose_tool_action(
    request: Request,
    body: ActionProposalRequest,
    context: TenantContextDep,
    rate_limiter: RateLimiterDep,
) -> ActionProposalResponse:
    tenant_id = context.tenant_id

    # 1. Caller Role & Authorization Verification (Least Privilege / Part 6)
    if context.role in UNAUTHORIZED_PROPOSAL_ROLES:
        logger.warning(
            "Proposal rejected: caller '%s' with role '%s' cannot propose actions for agent '%s'.",
            context.user_id,
            context.role,
            body.agent_id,
        )
        raise ForbiddenError(f"Role '{context.role}' lacks permission to submit tool action proposals.")

    # 2. Rate Limiting Check (M7 Redis / In-Memory Boundary)
    rate_key = f"gw:propose:{tenant_id}:{body.agent_id}"
    rl_result = await rate_limiter.check_rate_limit(rate_key, max_requests=100, window_seconds=60)
    if not rl_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for tool action proposals.",
            headers={"Retry-After": str(rl_result.retry_after or 60)},
        )

    # 3. Agent Identity & Confused-Deputy Verification (M1 Day 3 Agent Registry)
    agent_repo = getattr(request.app.state, "agent_repo", None)
    if agent_repo is None:
        raise SecurityDependencyError("Agent repository service unavailable.")

    agent = await agent_repo.get_agent_by_id(body.agent_id, tenant_id)
    if agent is None:
        logger.warning(
            "Confused-deputy attempt or invalid agent: agent '%s' not found in tenant '%s'.",
            body.agent_id,
            tenant_id,
        )
        raise NotFoundError(f"Agent '{body.agent_id}' not found in the authenticated tenant.")

    if agent.status != "ACTIVE":
        logger.warning(
            "Action proposal rejected: agent '%s' is in status '%s'.",
            body.agent_id,
            agent.status,
        )
        raise ForbiddenError(
            f"Agent '{body.agent_id}' is in status '{agent.status}' and cannot propose tool actions."
        )

    # 4. Durable Idempotency Resolution (M6 Database Boundary)
    gateway_repo = await get_gateway_repository(request)

    payload_fingerprint = compute_payload_fingerprint(
        agent_id=body.agent_id,
        action_id=body.action_id,
        tool_name=body.tool_name,
        operation=body.operation,
        parameters=body.parameters,
        memory_refs=body.memory_refs,
    )

    existing_record = await gateway_repo.get_by_idempotency_key(tenant_id, body.idempotency_key)
    if existing_record is not None:
        existing_prop, existing_dec, existing_exec = existing_record
        if existing_prop.get_fingerprint() != payload_fingerprint:
            logger.warning(
                "Idempotency conflict for key '%s' in tenant '%s': payload mismatch.",
                body.idempotency_key,
                tenant_id,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key has already been used with a different request payload.",
            )

        # In-progress concurrent execution check
        if existing_dec.execution_status == ExecutionStatus.PENDING_EXECUTION.value:
            logger.info(
                "Idempotency in-progress duplicate for key '%s': execution still pending.",
                body.idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Action proposal with this idempotency key is currently executing. Please retry shortly.",
            )

        # Exact match replay: return previously persisted decision & execution without re-invoking adapter
        logger.info(
            "Idempotent replay: returning previously persisted decision for key '%s'.",
            body.idempotency_key,
        )
        return ActionProposalResponse(
            action_id=existing_prop.action_id,
            proposal_id=existing_prop.id,
            decision=existing_dec.decision,
            memory_trust=existing_dec.memory_trust,
            policy_result=existing_dec.policy_result,
            reasons=list(existing_dec.reasons_json),
            execution_status=existing_dec.execution_status,
            result=existing_exec.result_payload_json if existing_exec else None,
        )

    # 5. Memory Trust & Cryptographic Integrity Verification (M3 Memory Systems)
    memory_repo = getattr(request.app.state, "memory_repo", None)
    if memory_repo is None and body.memory_refs:
        raise SecurityDependencyError("Memory trust verification service unavailable.")

    memory_trust_state = "NOT_REFERENCED"
    memory_reasons: List[str] = []
    verified_memory_evidence: List[Dict[str, Any]] = []

    if body.memory_refs:
        all_trusted = True
        tainted_state: Optional[str] = None

        for ref_id in body.memory_refs:
            record = memory_repo.get_record(ref_id, tenant_id)
            if record is None:
                all_trusted = False
                tainted_state = "QUARANTINED"
                memory_reasons.append(
                    f"Referenced memory '{ref_id}' does not exist in the authenticated tenant."
                )
                break

            if record.agent_id is not None and record.agent_id != body.agent_id:
                all_trusted = False
                tainted_state = "QUARANTINED"
                memory_reasons.append(
                    f"Referenced memory '{ref_id}' is bound to agent '{record.agent_id}', not caller agent '{body.agent_id}'."
                )
                break

            latest_version = memory_repo.get_latest_version(ref_id, tenant_id)
            if latest_version is None:
                all_trusted = False
                tainted_state = "UNVERIFIED"
                memory_reasons.append(f"Referenced memory '{ref_id}' has no content versions.")
                break

            computed_checksum = sha256_hex(latest_version.content)
            if computed_checksum != latest_version.checksum:
                logger.error(
                    "Cryptographic checksum mismatch for memory '%s': expected %s, got %s",
                    ref_id,
                    latest_version.checksum,
                    computed_checksum,
                )
                raise AMSCException(
                    message=f"Memory integrity violation: Checksum mismatch on record '{ref_id}'.",
                    code="MEMORY_INTEGRITY_VIOLATION",
                    status_code=500,
                )

            # Record verified version & integrity evidence (SEC-GW-006)
            verified_memory_evidence.append({
                "record_id": ref_id,
                "version": latest_version.version,
                "checksum": computed_checksum,
                "trust_state": record.trust_state,
            })

            if record.trust_state != TrustState.TRUSTED.value:
                all_trusted = False
                tainted_state = record.trust_state
                memory_reasons.append(
                    f"Referenced memory '{ref_id}' is marked {record.trust_state} and cannot back protected financial tools."
                )

        if all_trusted:
            memory_trust_state = "TRUSTED"
        else:
            memory_trust_state = tainted_state or "SUSPICIOUS"

    # 6. Deterministic Policy Evaluation (M4 Security Policy Engine)
    policy_evaluator = getattr(request.app.state, "policy_evaluator", None) or get_default_policy_evaluator()
    eval_input = PolicyEvaluationInput(
        tenant_id=tenant_id,
        agent_id=body.agent_id,
        agent_status=agent.status,
        tool_name=body.tool_name,
        operation=body.operation,
        parameters=body.parameters,
        memory_refs=body.memory_refs,
        memory_trust_state=memory_trust_state,
        memory_reasons=memory_reasons,
    )

    try:
        policy_output = policy_evaluator.evaluate(eval_input)
    except Exception as exc:
        logger.exception("Policy evaluation failed closed with unexpected error: %s", exc)
        raise SecurityDependencyError("Policy evaluation failed closed.") from exc

    # 7. Check Tool Registration & Determine Initial Execution Status
    proposal_id = str(uuid.uuid4())
    decision_id = str(uuid.uuid4())
    tool_registry = getattr(request.app.state, "tool_registry", None) or get_default_tool_registry()

    execution_status = ExecutionStatus.NOT_EXECUTED.value
    adapter = None

    if policy_output.decision == GatewayDecision.ALLOW:
        adapter = tool_registry.get_adapter(body.tool_name)
        if adapter is None:
            policy_output.decision = GatewayDecision.BLOCK
            policy_output.policy_result = PolicyResult.DENIED
            policy_output.reasons.append(f"Tool '{body.tool_name}' is not registered in Gateway adapter registry.")
            execution_status = ExecutionStatus.NOT_EXECUTED.value
        else:
            # Policy allows and adapter exists: set execution_status to PENDING_EXECUTION
            execution_status = ExecutionStatus.PENDING_EXECUTION.value
    elif policy_output.decision == GatewayDecision.REVIEW:
        execution_status = ExecutionStatus.PENDING_APPROVAL.value
    else:  # BLOCK
        execution_status = ExecutionStatus.NOT_EXECUTED.value

    # 8. Durable Persistence of Proposal & Decision BEFORE Dispatch (Part 9 & Part 13)
    proposal_entity = ToolProposalEntity(
        id=proposal_id,
        tenant_id=tenant_id,
        agent_id=body.agent_id,
        action_id=body.action_id,
        tool_name=body.tool_name,
        operation=body.operation,
        parameters_json=body.parameters,
        memory_refs_json=body.memory_refs,
        idempotency_key=body.idempotency_key,
        trace_id=body.trace_id,
        payload_fingerprint=payload_fingerprint,
        created_at=datetime.now(timezone.utc),
    )

    decision_entity = PolicyDecisionEntity(
        id=decision_id,
        tenant_id=tenant_id,
        proposal_id=proposal_id,
        decision=policy_output.decision.value,
        memory_trust=policy_output.memory_trust.value,
        policy_result=policy_output.policy_result.value,
        reasons_json=policy_output.reasons,
        incident_id=None,
        execution_status=execution_status,
        created_at=datetime.now(timezone.utc),
    )

    redacted_parameters = redact_sensitive_payload(body.parameters)
    audit_entity = AuditEventEntity(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        actor_id=context.user_id,
        event_type="TOOL_POLICY_DECIDED",
        resource_id=proposal_id,
        action=f"{body.tool_name}:{body.operation}",
        outcome=policy_output.decision.value,
        trace_id=body.trace_id,
        details_json={
            "action_id": body.action_id,
            "agent_id": body.agent_id,
            "tool_name": body.tool_name,
            "operation": body.operation,
            "decision": policy_output.decision.value,
            "memory_trust": policy_output.memory_trust.value,
            "execution_status": execution_status,
            "reasons": policy_output.reasons,
            "parameters": redacted_parameters,
            "memory_refs": body.memory_refs,
            "verified_memory_versions": verified_memory_evidence,
            "payload_fingerprint": payload_fingerprint,
        },
        occurred_at=datetime.now(timezone.utc),
    )

    try:
        await gateway_repo.save_proposal_atomic(
            proposal=proposal_entity,
            decision=decision_entity,
            execution=None,  # Not executed yet!
            audit_event=audit_entity,
        )
    except HTTPException:
        raise
    except AMSCException:
        raise
    except Exception as exc:
        logger.exception("Failed to persist gateway proposal and decision atomically before dispatch: %s", exc)
        raise AMSCException(
            message="Failed to persist action proposal and security decision.",
            code="PERSISTENCE_FAILURE",
            status_code=500,
        ) from exc

    # 9. Adapter Dispatch (Only for ALLOW with PENDING_EXECUTION)
    execution_result_payload: Optional[Dict[str, Any]] = None

    if policy_output.decision == GatewayDecision.ALLOW and adapter is not None:
        # 9a. Memory TOCTOU Revalidation (SEC-GW-007)
        toctou_violation = False
        toctou_reason = ""
        if body.memory_refs and memory_repo is not None:
            for ref_id in body.memory_refs:
                cur_rec = memory_repo.get_record(ref_id, tenant_id)
                if cur_rec is None or cur_rec.trust_state != TrustState.TRUSTED.value:
                    toctou_violation = True
                    cur_st = cur_rec.trust_state if cur_rec else "DELETED"
                    toctou_reason = f"Memory trust revoked for '{ref_id}' (state: {cur_st}) before adapter dispatch."
                    break
                cur_ver = memory_repo.get_latest_version(ref_id, tenant_id)
                if cur_ver is None or sha256_hex(cur_ver.content) != cur_ver.checksum:
                    toctou_violation = True
                    toctou_reason = f"Memory integrity invalidated for '{ref_id}' before adapter dispatch."
                    break

        if toctou_violation:
            logger.warning("TOCTOU protection triggered: %s", toctou_reason)
            execution_status = ExecutionStatus.NOT_EXECUTED.value
            policy_output.decision = GatewayDecision.BLOCK
            policy_output.policy_result = PolicyResult.DENIED
            policy_output.reasons.append(toctou_reason)

            abort_exec = ToolExecutionEntity(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                proposal_id=proposal_id,
                decision_id=decision_id,
                status="BLOCKED_BY_TOCTOU",
                status_code=403,
                result_payload_json={"error": toctou_reason},
                duration_ms=0,
                executed_at=datetime.now(timezone.utc),
            )
            await gateway_repo.record_execution_outcome(
                tenant_id=tenant_id,
                proposal_id=proposal_id,
                decision_id=decision_id,
                execution=abort_exec,
                execution_status=execution_status,
            )
        else:
            # 9b. Execute protected adapter
            execution_entity: Optional[ToolExecutionEntity] = None
            try:
                exec_res = await adapter.execute(
                    operation=body.operation,
                    parameters=body.parameters,
                    context={"tenant_id": tenant_id, "agent_id": body.agent_id, "trace_id": body.trace_id},
                )
                execution_status = ExecutionStatus.EXECUTED.value
                execution_result_payload = exec_res.result_payload
                execution_entity = ToolExecutionEntity(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    proposal_id=proposal_id,
                    decision_id=decision_id,
                    status=exec_res.status,
                    status_code=exec_res.status_code,
                    result_payload_json=exec_res.result_payload,
                    duration_ms=exec_res.duration_ms,
                    executed_at=datetime.now(timezone.utc),
                )
            except (TimeoutError, asyncio.TimeoutError):
                logger.error("Adapter timed out for tool '%s'. Side effect outcome is UNKNOWN.", body.tool_name)
                execution_status = ExecutionStatus.UNKNOWN.value
                execution_result_payload = {
                    "error": "Tool execution timed out. Outcome is ambiguous and requires reconciliation."
                }
                execution_entity = ToolExecutionEntity(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    proposal_id=proposal_id,
                    decision_id=decision_id,
                    status="UNKNOWN",
                    status_code=504,
                    result_payload_json=execution_result_payload,
                    duration_ms=0,
                    executed_at=datetime.now(timezone.utc),
                )
            except Exception as exc:
                logger.exception("Tool execution failed for tool '%s': %s", body.tool_name, exc)
                execution_status = ExecutionStatus.FAILED.value
                execution_result_payload = {"error": "Tool execution exception occurred."}
                execution_entity = ToolExecutionEntity(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    proposal_id=proposal_id,
                    decision_id=decision_id,
                    status="FAILED",
                    status_code=500,
                    result_payload_json=execution_result_payload,
                    duration_ms=0,
                    executed_at=datetime.now(timezone.utc),
                )

            # Record final execution outcome
            await gateway_repo.record_execution_outcome(
                tenant_id=tenant_id,
                proposal_id=proposal_id,
                decision_id=decision_id,
                execution=execution_entity,
                execution_status=execution_status,
            )

    # 10. Return Canonical Action Proposal Response
    return ActionProposalResponse(
        action_id=body.action_id,
        proposal_id=proposal_id,
        decision=policy_output.decision.value,
        memory_trust=policy_output.memory_trust.value,
        policy_result=policy_output.policy_result.value,
        reasons=policy_output.reasons,
        execution_status=execution_status,
        result=execution_result_payload,
    )


@router.get(
    "/actions",
    response_model=List[ProposalDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="List Tool Action Proposals",
    description="List forensic proposals, policy decisions, and execution outcomes for authorized tenant members.",
)
async def list_tool_actions(
    request: Request,
    context: TenantContextDep,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> List[ProposalDetailResponse]:
    gateway_repo = await get_gateway_repository(request)
    records = await gateway_repo.list_proposals(context.tenant_id, limit=limit, offset=offset)
    results = []
    for prop, dec, exe in records:
        redacted_parameters = redact_sensitive_payload(prop.parameters_json)
        results.append(
            ProposalDetailResponse(
                proposal_id=prop.id,
                tenant_id=prop.tenant_id,
                agent_id=prop.agent_id,
                action_id=prop.action_id,
                tool_name=prop.tool_name,
                operation=prop.operation,
                parameters=redacted_parameters,
                memory_refs=prop.memory_refs_json,
                idempotency_key=prop.idempotency_key,
                trace_id=prop.trace_id,
                decision=dec.decision,
                memory_trust=dec.memory_trust,
                policy_result=dec.policy_result,
                reasons=list(dec.reasons_json),
                execution_status=dec.execution_status,
                execution_result=exe.result_payload_json if exe else None,
                created_at=prop.created_at.isoformat(),
            )
        )
    return results


@router.get(
    "/actions/{proposal_id}",
    response_model=ProposalDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect Tool Action Proposal & Decision Audit Detail",
    description="Fetch forensic proposal, policy decision, and execution details for authorized tenant members.",
)
async def get_tool_action_detail(
    proposal_id: str,
    request: Request,
    context: TenantContextDep,
) -> ProposalDetailResponse:
    if not SAFE_ID_REGEX.match(proposal_id):
        raise ValidationError("Invalid proposal identifier format.")

    gateway_repo = await get_gateway_repository(request)
    record = await gateway_repo.get_by_id(context.tenant_id, proposal_id)
    if record is None:
        raise NotFoundError(f"Proposal '{proposal_id}' not found in the authenticated tenant.")

    proposal, decision, execution = record
    redacted_parameters = redact_sensitive_payload(proposal.parameters_json)

    return ProposalDetailResponse(
        proposal_id=proposal.id,
        tenant_id=proposal.tenant_id,
        agent_id=proposal.agent_id,
        action_id=proposal.action_id,
        tool_name=proposal.tool_name,
        operation=proposal.operation,
        parameters=redacted_parameters,
        memory_refs=proposal.memory_refs_json,
        idempotency_key=proposal.idempotency_key,
        trace_id=proposal.trace_id,
        decision=decision.decision,
        memory_trust=decision.memory_trust,
        policy_result=decision.policy_result,
        reasons=list(decision.reasons_json),
        execution_status=decision.execution_status,
        execution_result=execution.result_payload_json if execution else None,
        created_at=proposal.created_at.isoformat(),
    )
