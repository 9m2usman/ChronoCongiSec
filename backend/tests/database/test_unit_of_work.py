"""UnitOfWork: one atomic transaction per gateway action (DOC-006 Day 4, GAP-008).

Owner: M6
These tests really COMMIT (that is what is being tested), so every test works in its
own fresh tenant inside the module's temporary database. No value used here implies a
decision vocabulary: decision/status columns get neutral placeholders on purpose
(see OPEN-DEPENDENCIES).
"""

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.database.models import (
    Agent,
    Approval,
    AuditEvent,
    PolicyDecision,
    Tenant,
    ToolExecution,
    ToolProposal,
)
from backend.app.database.repositories import AppendOnlyError, TenantScopeError
from backend.app.database.unit_of_work import TENANT_SETTING, UnitOfWork
from backend.tests.database import helpers

pytestmark = pytest.mark.asyncio

PLACEHOLDER = "TEST_VALUE"  # deliberately not a real decision/status value


def _id() -> str:
    return str(uuid.uuid4())


@pytest_asyncio.fixture
async def session_factory(module_db: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), poolclass=NullPool)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def tenant_with_agent(session_factory) -> tuple[str, str]:
    tenant_id, agent_id = _id(), _id()
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=tenant_id, name="Company", slug=f"co-{tenant_id[:8]}"))
        await session.flush()
        session.add(Agent(id=agent_id, tenant_id=tenant_id, name="bot"))
    return tenant_id, agent_id


def _proposal(agent_id: str, key: str | None = None) -> ToolProposal:
    return ToolProposal(
        id=_id(), agent_id=agent_id, action_id="act", tool_name="tool", operation="op",
        idempotency_key=key or _id(), trace_id="trace",
    )


def _decision(proposal_id: str) -> PolicyDecision:
    return PolicyDecision(
        id=_id(), proposal_id=proposal_id, decision=PLACEHOLDER, memory_trust=PLACEHOLDER,
        policy_result=PLACEHOLDER,
    )


def _execution(proposal_id: str, decision_id: str) -> ToolExecution:
    return ToolExecution(id=_id(), proposal_id=proposal_id, decision_id=decision_id, status=PLACEHOLDER)


def _audit(resource_id: str) -> AuditEvent:
    return AuditEvent(
        id=_id(), actor_id="actor", event_type=PLACEHOLDER, resource_id=resource_id,
        action=PLACEHOLDER, outcome=PLACEHOLDER,
    )


async def _count(session_factory, model, tenant_id: str) -> int:
    async with session_factory() as session:
        stmt = select(func.count()).select_from(model).where(model.tenant_id == tenant_id)
        return (await session.execute(stmt)).scalar_one()


async def _chain_counts(session_factory, tenant_id: str) -> tuple[int, int, int, int]:
    return tuple([
        await _count(session_factory, model, tenant_id)
        for model in (ToolProposal, PolicyDecision, ToolExecution, AuditEvent)
    ])


# -- commit / rollback ------------------------------------------------------------------


async def test_full_chain_commits_atomically(session_factory, tenant_with_agent) -> None:
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)

    async with uow(tenant_id) as tx:
        proposal = await tx.proposals.add(_proposal(agent_id))
        decision = await tx.decisions.add(_decision(proposal.id))
        await tx.executions.add(_execution(proposal.id, decision.id))
        await tx.audit.append(_audit(proposal.id))

    assert await _chain_counts(session_factory, tenant_id) == (1, 1, 1, 1)


@pytest.mark.parametrize("fail_after", ["proposal", "decision", "execution", "audit"])
async def test_exception_after_any_write_rolls_back_everything(session_factory, tenant_with_agent, fail_after) -> None:
    """GAP-008 fault injection: a failure at every write boundary leaves no partial chain."""
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)

    class Injected(Exception):
        pass

    with pytest.raises(Injected):
        async with uow(tenant_id) as tx:
            proposal = await tx.proposals.add(_proposal(agent_id))
            if fail_after == "proposal":
                raise Injected
            decision = await tx.decisions.add(_decision(proposal.id))
            if fail_after == "decision":
                raise Injected
            await tx.executions.add(_execution(proposal.id, decision.id))
            if fail_after == "execution":
                raise Injected
            await tx.audit.append(_audit(proposal.id))
            raise Injected

    assert await _chain_counts(session_factory, tenant_id) == (0, 0, 0, 0)


async def test_database_error_midway_rolls_back_earlier_writes(session_factory, tenant_with_agent) -> None:
    """An execution citing another proposal's decision (0007 FK) aborts the whole action."""
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)

    with pytest.raises(IntegrityError, match="fk_tool_executions_decision_matches_proposal"):
        async with uow(tenant_id) as tx:
            first = await tx.proposals.add(_proposal(agent_id))
            second = await tx.proposals.add(_proposal(agent_id))
            await tx.decisions.add(_decision(first.id))
            other_decision = await tx.decisions.add(_decision(second.id))
            await tx.executions.add(_execution(first.id, other_decision.id))

    assert await _chain_counts(session_factory, tenant_id) == (0, 0, 0, 0)


async def test_cancellation_rolls_back(session_factory, tenant_with_agent) -> None:
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)
    inserted = asyncio.Event()

    async def action() -> None:
        async with uow(tenant_id) as tx:
            await tx.proposals.add(_proposal(agent_id))
            inserted.set()
            await asyncio.sleep(30)

    task = asyncio.create_task(action())
    await inserted.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert await _count(session_factory, ToolProposal, tenant_id) == 0


# -- tenant scope ------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", None, 7])
async def test_unit_of_work_requires_a_tenant(session_factory, bad) -> None:
    with pytest.raises(TenantScopeError):
        async with UnitOfWork(session_factory)(bad):
            pass


async def test_entity_of_another_tenant_is_refused_and_rolled_back(session_factory, tenant_with_agent) -> None:
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)

    with pytest.raises(TenantScopeError):
        async with uow(tenant_id) as tx:
            await tx.proposals.add(_proposal(agent_id))
            smuggled = _proposal(agent_id)
            smuggled.tenant_id = _id()
            await tx.proposals.add(smuggled)

    assert await _count(session_factory, ToolProposal, tenant_id) == 0


async def test_cross_tenant_reference_inside_unit_of_work_is_rejected(session_factory, tenant_with_agent) -> None:
    """Tenant A's unit of work cannot attach a proposal to tenant B's agent (composite FK)."""
    tenant_a, _ = tenant_with_agent
    tenant_b, agent_b = _id(), _id()
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=tenant_b, name="Other", slug=f"co-{tenant_b[:8]}"))
        await session.flush()
        session.add(Agent(id=agent_b, tenant_id=tenant_b, name="other-bot"))

    with pytest.raises(IntegrityError):
        async with UnitOfWork(session_factory)(tenant_a) as tx:
            await tx.proposals.add(_proposal(agent_b))

    assert await _count(session_factory, ToolProposal, tenant_a) == 0


async def test_reads_inside_unit_of_work_are_tenant_scoped(session_factory, tenant_with_agent) -> None:
    tenant_a, agent_a = tenant_with_agent
    uow = UnitOfWork(session_factory)
    async with uow(tenant_a) as tx:
        proposal = await tx.proposals.add(_proposal(agent_a, key="shared-key"))
        decision = await tx.decisions.add(_decision(proposal.id))
        await tx.executions.add(_execution(proposal.id, decision.id))

    other_tenant = _id()
    async with session_factory() as session, session.begin():
        session.add(Tenant(id=other_tenant, name="Other", slug=f"co-{other_tenant[:8]}"))
    async with uow(other_tenant) as tx:
        assert await tx.proposals.get(proposal.id) is None
        assert await tx.proposals.get_by_idempotency_key("shared-key") is None
        assert await tx.decisions.get_for_proposal(proposal.id) is None
        assert await tx.executions.get_for_proposal(proposal.id) is None

    async with uow(tenant_a) as tx:
        assert (await tx.proposals.get_by_idempotency_key("shared-key")).id == proposal.id
        assert (await tx.decisions.get_for_proposal(proposal.id)).id == decision.id
        assert (await tx.executions.get_for_proposal(proposal.id)).decision_id == decision.id


# -- session and connection hygiene -------------------------------------------------------


async def test_each_unit_of_work_gets_its_own_session(session_factory, tenant_with_agent) -> None:
    tenant_id, _ = tenant_with_agent
    uow = UnitOfWork(session_factory)

    async with uow(tenant_id) as first, uow(tenant_id) as second:
        assert first.session is not second.session
        assert first.proposals.session is first.decisions.session is first.audit.session
        assert first.tenant_id == first.proposals.tenant_id == first.executions.tenant_id


async def test_tenant_setting_is_transaction_local_and_never_leaks(module_db: str, tenant_with_agent) -> None:
    """With a one-connection pool, the next transaction on the SAME connection sees no tenant."""
    tenant_id, agent_id = tenant_with_agent
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), pool_size=1, max_overflow=0)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    uow = UnitOfWork(factory)
    try:
        async with uow(tenant_id) as tx:
            inside = (await tx.session.execute(text(f"SELECT current_setting('{TENANT_SETTING}', true)"))).scalar()
            pid_inside = (await tx.session.execute(text("SELECT pg_backend_pid()"))).scalar()

        with pytest.raises(RuntimeError):
            async with uow(tenant_id) as tx:
                raise RuntimeError("rolled back")

        async with factory() as session:
            after = (await session.execute(text(f"SELECT current_setting('{TENANT_SETTING}', true)"))).scalar()
            pid_after = (await session.execute(text("SELECT pg_backend_pid()"))).scalar()
    finally:
        await engine.dispose()

    assert inside == tenant_id
    assert pid_after == pid_inside, "the test must reuse the same pooled connection"
    assert after in (None, ""), f"tenant setting leaked into the next transaction: {after!r}"


async def test_optional_timeouts_are_transaction_local(module_db: str, tenant_with_agent) -> None:
    tenant_id, _ = tenant_with_agent
    engine = create_async_engine(helpers.sqlalchemy_url(module_db), pool_size=1, max_overflow=0)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with UnitOfWork(factory, statement_timeout_ms=1500, lock_timeout_ms=700)(tenant_id) as tx:
            inside = (await tx.session.execute(text("SELECT current_setting('statement_timeout')"))).scalar()
            lock = (await tx.session.execute(text("SELECT current_setting('lock_timeout')"))).scalar()
        async with factory() as session:
            after = (await session.execute(text("SELECT current_setting('statement_timeout')"))).scalar()
    finally:
        await engine.dispose()

    assert (inside, lock) == ("1500ms", "700ms")
    assert after == "0", "statement_timeout leaked out of the transaction"


async def test_statement_timeout_cancels_and_rolls_back(session_factory, tenant_with_agent) -> None:
    tenant_id, agent_id = tenant_with_agent

    with pytest.raises(DBAPIError, match="statement timeout"):
        async with UnitOfWork(session_factory, statement_timeout_ms=100)(tenant_id) as tx:
            await tx.proposals.add(_proposal(agent_id))
            await tx.session.execute(text("SELECT pg_sleep(2)"))

    assert await _count(session_factory, ToolProposal, tenant_id) == 0


@pytest.mark.parametrize("bad", [0, -5, 1.5, True, "100"])
async def test_invalid_timeouts_are_rejected(bad) -> None:
    with pytest.raises(ValueError):
        UnitOfWork(object(), statement_timeout_ms=bad)
    with pytest.raises(ValueError):
        UnitOfWork(object(), lock_timeout_ms=bad)


# -- concurrency -----------------------------------------------------------------------------


async def test_concurrent_duplicate_idempotency_key_lets_exactly_one_commit(session_factory, tenant_with_agent) -> None:
    """Two actions with the same key: the second blocks on the unique index, then fails."""
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)
    first_inserted = asyncio.Event()

    async def first() -> str:
        async with uow(tenant_id) as tx:
            proposal = await tx.proposals.add(_proposal(agent_id, key="same-key"))
            first_inserted.set()
            await asyncio.sleep(0.5)  # keep the transaction open while the second one tries
            return proposal.id

    async def second() -> str:
        await first_inserted.wait()
        async with uow(tenant_id) as tx:
            proposal = await tx.proposals.add(_proposal(agent_id, key="same-key"))
            return proposal.id

    results = await asyncio.gather(first(), second(), return_exceptions=True)

    assert isinstance(results[0], str)
    assert isinstance(results[1], IntegrityError) and "uq_tenant_idemp_key" in str(results[1])
    async with uow(tenant_id) as tx:
        assert (await tx.proposals.get_by_idempotency_key("same-key")).id == results[0]


# -- repositories ------------------------------------------------------------------------------


async def test_audit_repository_is_append_only(session_factory, tenant_with_agent) -> None:
    tenant_id, _ = tenant_with_agent
    uow = UnitOfWork(session_factory)
    async with uow(tenant_id) as tx:
        event = await tx.audit.append(_audit("r1"))
        with pytest.raises(AppendOnlyError):
            await tx.audit.update(event.id, action="TAMPERED")
        with pytest.raises(AppendOnlyError):
            await tx.audit.delete(event.id)

    async with uow(tenant_id) as tx:
        stored = await tx.audit.get(event.id)
        assert stored.action == PLACEHOLDER


async def test_audit_list_recent_is_newest_first_and_bounded(session_factory, tenant_with_agent) -> None:
    tenant_id, _ = tenant_with_agent
    uow = UnitOfWork(session_factory)
    async with uow(tenant_id) as tx:
        for i in range(3):
            await tx.audit.append(_audit(f"r{i}"))
            await tx.session.execute(text("SELECT pg_sleep(0.01)"))
    async with uow(tenant_id) as tx:
        recent = await tx.audit.list_recent(limit=2)
        with pytest.raises(ValueError):
            await tx.audit.list_recent(limit=101)

    assert len(recent) == 2
    assert recent[0].occurred_at >= recent[1].occurred_at


async def test_approvals_for_decision_are_listed_and_bounded(session_factory, tenant_with_agent) -> None:
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)
    async with uow(tenant_id) as tx:
        proposal = await tx.proposals.add(_proposal(agent_id))
        decision = await tx.decisions.add(_decision(proposal.id))
        ids = sorted([(await tx.approvals.add(Approval(id=_id(), decision_id=decision.id))).id for _ in range(3)])

    async with uow(tenant_id) as tx:
        assert [a.id for a in await tx.approvals.list_for_decision(decision.id)] == ids
        assert [a.id for a in await tx.approvals.list_for_decision(decision.id, limit=2, offset=2)] == ids[2:]
        with pytest.raises(ValueError):
            await tx.approvals.list_for_decision(decision.id, limit=0)


@pytest.mark.parametrize("bad", ["", "  ", None])
async def test_lookup_keys_are_validated(session_factory, tenant_with_agent, bad) -> None:
    tenant_id, _ = tenant_with_agent
    async with UnitOfWork(session_factory)(tenant_id) as tx:
        with pytest.raises(ValueError):
            await tx.proposals.get_by_idempotency_key(bad)
        with pytest.raises(ValueError):
            await tx.decisions.get_for_proposal(bad)
        with pytest.raises(ValueError):
            await tx.executions.get_for_proposal(bad)
        with pytest.raises(ValueError):
            await tx.approvals.list_for_decision(bad)


async def test_gateway_chain_rows_cannot_be_deleted_once_committed(session_factory, tenant_with_agent) -> None:
    """RESTRICT (0007): deleting a proposal or decision with dependants fails and keeps everything."""
    tenant_id, agent_id = tenant_with_agent
    uow = UnitOfWork(session_factory)
    async with uow(tenant_id) as tx:
        proposal = await tx.proposals.add(_proposal(agent_id))
        decision = await tx.decisions.add(_decision(proposal.id))
        await tx.executions.add(_execution(proposal.id, decision.id))

    for repo_name, entity_id in (("proposals", proposal.id), ("decisions", decision.id)):
        with pytest.raises(IntegrityError):
            async with uow(tenant_id) as tx:
                await getattr(tx, repo_name).delete(entity_id)

    assert await _chain_counts(session_factory, tenant_id) == (1, 1, 1, 0)
