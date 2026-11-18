"""Tenant-scoped unit of work: one transaction for one gateway action (Day 4).

Module: backend.app.database.unit_of_work
Owner: M6
Spec: AMSC-DOC-006 Day 4 M6 row ("atomic transaction wrapping proposal, decision, and
tool execution"), AMSC-DOC-008 GAP-008 ("M6 must expose transaction-scoped repository
operations").

Usage::

    uow = UnitOfWork(session_factory)
    async with uow(tenant_id) as tx:
        await tx.proposals.add(ToolProposal(...))
        await tx.decisions.add(PolicyDecision(...))
        await tx.executions.add(ToolExecution(...))
        await tx.audit.append(AuditEvent(...))
    # normal exit -> COMMIT; any exception -> ROLLBACK and the exception is re-raised.

Guarantees:
- One new ``AsyncSession`` and one database transaction per ``async with``; the session
  is always closed afterwards. Sessions are never shared between units of work.
- Every repository on ``tx`` is bound to the same session AND the same tenant.
- The transaction starts with ``set_config('app.tenant_id', <tenant>, true)``. The setting
  is transaction-local, so it cannot leak to the next user of a pooled connection.
  (Groundwork for row-level security; no RLS policy exists yet.)
- Optional ``statement_timeout`` / ``lock_timeout`` are also transaction-local. They are
  off by default because the values are an operations decision (OPEN-DEPENDENCIES).
- Repositories never commit. Do not call ``tx.session.commit()``: leaving the block commits.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.repositories.base import TenantScopeError
from backend.app.database.repositories.gateway import (
    ApprovalRepository,
    AuditEventRepository,
    PolicyDecisionRepository,
    ToolExecutionRepository,
    ToolProposalRepository,
)

TENANT_SETTING = "app.tenant_id"


class TenantTransaction:
    """Repositories that share one session and one tenant inside a unit of work."""

    def __init__(self, session: AsyncSession, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.proposals = ToolProposalRepository(session, tenant_id)
        self.decisions = PolicyDecisionRepository(session, tenant_id)
        self.approvals = ApprovalRepository(session, tenant_id)
        self.executions = ToolExecutionRepository(session, tenant_id)
        self.audit = AuditEventRepository(session, tenant_id)

    async def flush(self) -> None:
        """Send pending writes now (still inside the transaction), e.g. to surface constraint errors early."""
        await self.session.flush()


def _check_timeout(name: str, value: Optional[int]) -> None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
        raise ValueError(f"{name} must be a positive integer number of milliseconds or None")


class UnitOfWork:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        statement_timeout_ms: Optional[int] = None,
        lock_timeout_ms: Optional[int] = None,
    ) -> None:
        _check_timeout("statement_timeout_ms", statement_timeout_ms)
        _check_timeout("lock_timeout_ms", lock_timeout_ms)
        self._session_factory = session_factory
        self._statement_timeout_ms = statement_timeout_ms
        self._lock_timeout_ms = lock_timeout_ms

    @asynccontextmanager
    async def __call__(self, tenant_id: str) -> AsyncIterator[TenantTransaction]:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise TenantScopeError("A non-empty tenant_id is required for a unit of work.")
        async with self._session_factory() as session:
            async with session.begin():
                await self._set_local(session, TENANT_SETTING, tenant_id)
                if self._statement_timeout_ms is not None:
                    await self._set_local(session, "statement_timeout", f"{self._statement_timeout_ms}ms")
                if self._lock_timeout_ms is not None:
                    await self._set_local(session, "lock_timeout", f"{self._lock_timeout_ms}ms")
                yield TenantTransaction(session, tenant_id)

    @staticmethod
    async def _set_local(session: AsyncSession, name: str, value: str) -> None:
        await session.execute(text("SELECT set_config(:name, :value, true)"), {"name": name, "value": value})
