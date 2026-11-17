"""M4 Security Engine: Quarantine State Machine & Policy Transitions.

Module: backend.app.security.quarantine
Owner: M4 — Security Engine & Incident Response Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Dynamic Memory Trust & Threat Quarantine
- AMSC-DOC-005 (Database & API Schema) Section 3.5: Table 22 (quarantines) & Table 11 (memory_records)
- AMSC-DOC-006 (Team Implementation Plan) Day 5: Quarantine Workflow
- AMSC-DOC-008: GAP-001, GAP-004, GAP-019, GAP-021
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from backend.app.core.exceptions import ForbiddenError, ValidationError
from backend.app.memory.models import MemoryRecord, TrustState

logger = logging.getLogger("amsc.security.quarantine")


class QuarantineReasonCode(str, Enum):
    """Documented quarantine trigger classifications."""
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    UNTRUSTED_MEMORY_ACTION = "UNTRUSTED_MEMORY_ACTION"
    DRIFT_DIVERGENCE_THRESHOLD = "DRIFT_DIVERGENCE_THRESHOLD"
    MANUAL_ANALYST_ISOLATION = "MANUAL_ANALYST_ISOLATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"


@dataclass(frozen=True)
class QuarantineTransitionResult:
    """Canonical result of an M4 quarantine transition."""
    record_id: str
    tenant_id: str
    previous_state: str
    new_state: str
    quarantined_by: str
    reason: str
    timestamp: datetime


@runtime_checkable
class QuarantineServiceProtocol(Protocol):
    """Protocol boundary for M4 Quarantine evaluation and state transition."""

    def evaluate_quarantine_eligibility(
        self,
        record: Any,
        actor_role: str,
    ) -> Tuple[bool, Optional[str]]:
        """Determine whether the memory record can be quarantined by the actor."""
        ...

    def execute_quarantine_transition(
        self,
        record: Any,
        reason: str,
        actor_id: str,
        analyst_notes: Optional[str] = None,
    ) -> QuarantineTransitionResult:
        """Execute state transition to QUARANTINED and return transition audit."""
        ...


class M4QuarantineService:
    """Authoritative M4 Trust State Machine & Quarantine Transition Engine.

    Guarantees:
    1. Only authorized analysts and tenant admins can trigger quarantine.
    2. Records transition deterministically to QUARANTINED.
    3. Idempotent: Quarantining an already QUARANTINED record succeeds without corrupting previous state.
    4. Transition reason and actor must be non-empty and validated.
    """

    ALLOWED_SOURCE_STATES = {
        TrustState.SUSPICIOUS.value,
        TrustState.UNVERIFIED.value,
        TrustState.TRUSTED.value,
        TrustState.REJECTED.value,
        TrustState.QUARANTINED.value,
        TrustState.SUPERSEDED.value,
    }

    def evaluate_quarantine_eligibility(
        self,
        record: Any,
        actor_role: str,
    ) -> Tuple[bool, Optional[str]]:
        """Validate if actor role and current record state permit quarantine."""
        if actor_role not in ("SECURITY_ANALYST", "TENANT_ADMIN"):
            return False, f"Role '{actor_role}' is not authorized to quarantine memory records."

        current_state = getattr(record, "trust_state", None)
        if isinstance(current_state, TrustState):
            current_state = current_state.value
        elif isinstance(current_state, str):
            current_state = current_state.upper()
        else:
            return False, "Invalid record trust state representation."

        if current_state not in self.ALLOWED_SOURCE_STATES:
            return False, f"Cannot quarantine record in unknown state '{current_state}'."

        return True, None

    def execute_quarantine_transition(
        self,
        record: Any,
        reason: str,
        actor_id: str,
        analyst_notes: Optional[str] = None,
    ) -> QuarantineTransitionResult:
        """Perform authoritative state transition to QUARANTINED.

        Mutates record.trust_state in-place to QUARANTINED and stamps updated_at.
        """
        if not reason or not reason.strip():
            raise ValidationError("Quarantine reason cannot be empty or whitespace only.")
        if not actor_id or not actor_id.strip():
            raise ValidationError("Actor ID must be provided by authenticated context.")

        raw_prev = getattr(record, "trust_state", None)
        prev_state = raw_prev.value if isinstance(raw_prev, TrustState) else str(raw_prev)

        # Apply state transition
        if isinstance(raw_prev, TrustState):
            record.trust_state = TrustState.QUARANTINED
        else:
            record.trust_state = "QUARANTINED"

        now = datetime.now(timezone.utc)
        if hasattr(record, "updated_at"):
            record.updated_at = now

        logger.info(
            f"M4 Security: Quarantined record '{record.id}' [tenant={record.tenant_id}] "
            f"from '{prev_state}' to 'QUARANTINED' by actor '{actor_id}'."
        )

        return QuarantineTransitionResult(
            record_id=record.id,
            tenant_id=record.tenant_id,
            previous_state=prev_state,
            new_state="QUARANTINED",
            quarantined_by=actor_id,
            reason=reason.strip(),
            timestamp=now,
        )


_default_quarantine_service: Optional[QuarantineServiceProtocol] = None


def get_default_quarantine_service() -> QuarantineServiceProtocol:
    """Factory for M4 Quarantine Service instance."""
    global _default_quarantine_service
    if _default_quarantine_service is None:
        _default_quarantine_service = M4QuarantineService()
    return _default_quarantine_service


def set_default_quarantine_service(service: Optional[QuarantineServiceProtocol]) -> None:
    """Testing override for quarantine service."""
    global _default_quarantine_service
    _default_quarantine_service = service
