"""Tenant-scoped repositories for the protected tool gateway chain (Day 4).

Module: backend.app.database.repositories.gateway
Owner: M6

Proposal -> decision -> approval / execution, plus the audit trail. Use them
through ``UnitOfWork`` so that all writes of one gateway action commit or roll
back together (DOC-006 Day 4, GAP-008). Like every M6 repository they never
commit, and every query is filtered by the bound tenant.

Values such as ``decision``, ``execution_status`` or ``status`` are stored as
given. Their allowed sets are owned by M4/M2/M1 and are tracked in
OPEN-DEPENDENCIES (M6 progress log); the database enforces them only after
those owners confirm.
"""

from collections.abc import Sequence
from typing import Any, NoReturn, Optional

from sqlalchemy import func, select

from backend.app.database.models import (
    Approval,
    AuditEvent,
    PolicyDecision,
    ToolExecution,
    ToolProposal,
)
from backend.app.database.repositories.base import (
    DEFAULT_PAGE_SIZE,
    TenantScopedRepository,
    check_page,
)


def _check_text(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


class AppendOnlyError(RuntimeError):
    """Raised when code tries to change or delete an append-only row (audit events)."""


class ToolProposalRepository(TenantScopedRepository[ToolProposal]):
    model = ToolProposal

    async def get_by_idempotency_key(self, idempotency_key: str) -> Optional[ToolProposal]:
        """The proposal stored under this key in this tenant (UNIQUE (tenant_id, idempotency_key))."""
        _check_text("idempotency_key", idempotency_key)
        stmt = select(ToolProposal).where(
            ToolProposal.tenant_id == self.tenant_id, ToolProposal.idempotency_key == idempotency_key
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()


class PolicyDecisionRepository(TenantScopedRepository[PolicyDecision]):
    model = PolicyDecision

    async def get_for_proposal(self, proposal_id: str) -> Optional[PolicyDecision]:
        """The decision of a proposal (at most one: policy_decisions.proposal_id is UNIQUE)."""
        _check_text("proposal_id", proposal_id)
        stmt = select(PolicyDecision).where(
            PolicyDecision.tenant_id == self.tenant_id, PolicyDecision.proposal_id == proposal_id
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()


class ApprovalRepository(TenantScopedRepository[Approval]):
    model = Approval

    async def list_for_decision(
        self, decision_id: str, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0
    ) -> Sequence[Approval]:
        """Approvals of one decision, ordered by id, bounded like every list."""
        _check_text("decision_id", decision_id)
        return await self.list(limit=limit, offset=offset, decision_id=decision_id)


class ToolExecutionRepository(TenantScopedRepository[ToolExecution]):
    model = ToolExecution

    async def get_for_proposal(self, proposal_id: str) -> Optional[ToolExecution]:
        """The execution of a proposal (at most one while tool_executions.proposal_id is UNIQUE)."""
        _check_text("proposal_id", proposal_id)
        stmt = select(ToolExecution).where(
            ToolExecution.tenant_id == self.tenant_id, ToolExecution.proposal_id == proposal_id
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()


CHAIN_COLUMNS = ("chain_seq", "prev_hash", "event_hash")


class AuditEventRepository(TenantScopedRepository[AuditEvent]):
    """Insert and read only. The database rejects UPDATE/DELETE/TRUNCATE too (migration 0004)
    and assigns the per-tenant hash chain on insert (migration 0009)."""

    model = AuditEvent

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Insert one event; the returned object carries the chain values the database assigned."""
        for column in CHAIN_COLUMNS:
            if getattr(event, column) is not None:
                raise ValueError(f"{column} is assigned by the database; do not set it")
        await self.add(event)
        await self.session.refresh(event, attribute_names=list(CHAIN_COLUMNS) + ["occurred_at"])
        return event

    async def list_recent(self, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0) -> Sequence[AuditEvent]:
        """Newest first by the tenant's chain order (UNIQUE (tenant_id, chain_seq)), bounded."""
        check_page(limit, offset)
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.tenant_id == self.tenant_id)
            .order_by(AuditEvent.chain_seq.desc())
            .limit(limit)
            .offset(offset)
        )
        return (await self.session.execute(stmt)).scalars().all()

    async def chain_break(self) -> Optional[int]:
        """First broken chain_seq of this tenant's audit chain, or None if it is intact."""
        stmt = select(func.amsc_audit_chain_break(self.tenant_id))
        return (await self.session.execute(stmt)).scalar()

    async def update(self, entity_id: str, **values: Any) -> NoReturn:
        raise AppendOnlyError("audit_events is append-only; updates are not allowed")

    async def delete(self, entity_id: str) -> NoReturn:
        raise AppendOnlyError("audit_events is append-only; deletes are not allowed")
