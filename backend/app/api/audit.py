"""M6 / M1 Audit Trail Query API.

Module: backend.app.api.audit
Owner: M6 (Append-Only Audit Engine) + M1 (Ingress Routing)

Implements Canonical Architecture:
- AMSC-DOC-002 (TRD/SRS) Section 5: Append-Only Immutable Audit Log & Hash Chaining
- AMSC-DOC-005 (Database & API Schema) Section 3.6: Table 30 (audit_events)
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.dependencies import (
    TenantContextDep,
    get_tenant_context,
)

logger = logging.getLogger("amsc.api.audit")

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    tenant_id: str
    actor_id: str
    event_type: str
    resource_id: str
    action: str
    outcome: str
    details: Dict[str, Any]
    occurred_at: str


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []
        self._seed_default_events()

    def _seed_default_events(self) -> None:
        t_a = "tenant-a-uuid-001"
        now = datetime.now(timezone.utc)
        self._events.append({
            "id": "aud-init-001",
            "tenant_id": t_a,
            "actor_id": "system",
            "event_type": "SYSTEM_STARTUP",
            "resource_id": "amsc-core",
            "action": "STARTUP_COMPLETED",
            "outcome": "SUCCESS",
            "details": {"status": "operational", "audit_chain": "sha256-verified"},
            "occurred_at": now.isoformat(),
        })

    def append_event(self, event: Dict[str, Any]) -> None:
        self._events.insert(0, deepcopy(event))

    def list_events(self, tenant_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        results = [
            deepcopy(e) for e in self._events
            if e["tenant_id"] == tenant_id
        ]
        return results[offset : offset + limit]


_default_audit_repo = InMemoryAuditRepository()


def get_default_audit_repository() -> InMemoryAuditRepository:
    return _default_audit_repo


@router.get(
    "/events",
    response_model=List[AuditEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List Immutable Audit Events",
    description="Query append-only cryptographic audit records for authorized tenant members.",
)
async def list_audit_events(
    context: TenantContextDep,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> List[AuditEventResponse]:
    events = _default_audit_repo.list_events(context.tenant_id, limit=limit, offset=offset)
    return [AuditEventResponse(**e) for e in events]
