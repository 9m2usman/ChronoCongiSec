"""Memory version and provenance edge repositories (migration 0006 work, requested by M3).

Owner: M6
Real PostgreSQL through the ORM session; every test is rolled back.
"""

import uuid

import pytest

from backend.app.database.models import MemoryRecord, MemoryVersion, ProvenanceEdge, Tenant
from backend.app.database.repositories import (
    MAX_PAGE_SIZE,
    EdgePage,
    MemoryVersionRepository,
    ProvenanceEdgeRepository,
)

pytestmark = pytest.mark.asyncio


def _id() -> str:
    return str(uuid.uuid4())


async def _tenant(session) -> str:
    tenant = Tenant(id=_id(), name="Company", slug=f"co-{uuid.uuid4().hex[:8]}")
    session.add(tenant)
    await session.flush()
    return tenant.id


async def _records(session, tenant_id: str, count: int) -> list[str]:
    ids = [_id() for _ in range(count)]
    session.add_all([MemoryRecord(id=i, tenant_id=tenant_id) for i in ids])
    await session.flush()
    return ids


async def _edge(session, tenant_id: str, src: str, dst: str, relation: str = "DERIVED_FROM") -> str:
    edge = ProvenanceEdge(id=_id(), tenant_id=tenant_id, from_record_id=src, to_record_id=dst, relation_type=relation)
    session.add(edge)
    await session.flush()
    return edge.id


async def _versions(session, tenant_id: str, record_id: str, numbers: list[int]) -> dict[int, str]:
    ids = {n: _id() for n in numbers}
    session.add_all([
        MemoryVersion(id=ids[n], tenant_id=tenant_id, record_id=record_id, version=n, content=f"v{n}", checksum="h")
        for n in numbers
    ])
    await session.flush()
    return ids


# -- edges_for_record ---------------------------------------------------------------


async def test_edges_for_record_returns_both_directions_in_id_order(session) -> None:
    tenant = await _tenant(session)
    center, parent, child, unrelated_a, unrelated_b = await _records(session, tenant, 5)
    incoming = await _edge(session, tenant, parent, center)
    outgoing = await _edge(session, tenant, center, child, "TRANSFORMED_INTO")
    await _edge(session, tenant, unrelated_a, unrelated_b)

    page = await ProvenanceEdgeRepository(session, tenant).edges_for_record(center)

    assert isinstance(page, EdgePage)
    assert [e.id for e in page.edges] == sorted([incoming, outgoing])
    assert page.has_more is False and (page.limit, page.offset) == (50, 0)
    directions = {(e.from_record_id, e.to_record_id) for e in page.edges}
    assert directions == {(parent, center), (center, child)}  # stored direction is kept


async def test_edges_for_record_is_tenant_isolated(session) -> None:
    tenant_a, tenant_b = await _tenant(session), await _tenant(session)
    a1, a2 = await _records(session, tenant_a, 2)
    b1, b2 = await _records(session, tenant_b, 2)
    await _edge(session, tenant_a, a1, a2)
    await _edge(session, tenant_b, b1, b2)

    repo_a = ProvenanceEdgeRepository(session, tenant_a)

    assert (await repo_a.edges_for_record(b1)).edges == []
    assert [e.tenant_id for e in (await repo_a.edges_for_record(a1)).edges] == [tenant_a]


async def test_edges_for_record_pages_with_has_more(session) -> None:
    tenant = await _tenant(session)
    center, *others = await _records(session, tenant, 6)
    edge_ids = sorted([await _edge(session, tenant, center, other) for other in others])  # 5 edges
    repo = ProvenanceEdgeRepository(session, tenant)

    first = await repo.edges_for_record(center, limit=2, offset=0)
    second = await repo.edges_for_record(center, limit=2, offset=2)
    last = await repo.edges_for_record(center, limit=2, offset=4)
    beyond = await repo.edges_for_record(center, limit=2, offset=6)

    assert [first.has_more, second.has_more, last.has_more, beyond.has_more] == [True, True, False, False]
    assert [e.id for page in (first, second, last) for e in page.edges] == edge_ids
    assert beyond.edges == []


async def test_edges_for_record_has_more_is_false_on_exact_fit(session) -> None:
    tenant = await _tenant(session)
    center, *others = await _records(session, tenant, 3)
    for other in others:
        await _edge(session, tenant, center, other)

    page = await ProvenanceEdgeRepository(session, tenant).edges_for_record(center, limit=2)

    assert len(page.edges) == 2 and page.has_more is False


async def test_edges_for_record_returns_at_most_100(session) -> None:
    tenant = await _tenant(session)
    center, *others = await _records(session, tenant, 102)
    session.add_all([
        ProvenanceEdge(id=_id(), tenant_id=tenant, from_record_id=center, to_record_id=o) for o in others
    ])
    await session.flush()

    page = await ProvenanceEdgeRepository(session, tenant).edges_for_record(center, limit=MAX_PAGE_SIZE)

    assert len(page.edges) == 100 and page.has_more is True


@pytest.mark.parametrize("bad", [0, -1, 101, 1000, True, 50.0, "50", None])
async def test_edges_for_record_rejects_invalid_limit(session, bad) -> None:
    repo = ProvenanceEdgeRepository(session, _id())

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        await repo.edges_for_record(_id(), limit=bad)


@pytest.mark.parametrize("bad", [-1, True, 1.5, "0", None])
async def test_edges_for_record_rejects_invalid_offset(session, bad) -> None:
    repo = ProvenanceEdgeRepository(session, _id())

    with pytest.raises(ValueError, match="offset"):
        await repo.edges_for_record(_id(), offset=bad)


@pytest.mark.parametrize("bad", ["", "   ", None, 42])
async def test_record_id_is_required(session, bad) -> None:
    with pytest.raises(ValueError, match="record_id"):
        await ProvenanceEdgeRepository(session, _id()).edges_for_record(bad)
    with pytest.raises(ValueError, match="record_id"):
        await MemoryVersionRepository(session, _id()).highest_version_for_record(bad)
    with pytest.raises(ValueError, match="record_id"):
        await MemoryVersionRepository(session, _id()).current_version_for_record(bad)


# -- current / highest version --------------------------------------------------------


async def test_current_and_highest_version_can_differ(session) -> None:
    tenant = await _tenant(session)
    (record,) = await _records(session, tenant, 1)
    versions = await _versions(session, tenant, record, [1, 2, 3])
    repo = MemoryVersionRepository(session, tenant)

    # memory_records.current_version defaults to 1, while versions go up to 3.
    assert (await repo.current_version_for_record(record)).id == versions[1]
    assert (await repo.highest_version_for_record(record)).id == versions[3]

    record_row = await session.get(MemoryRecord, record)
    record_row.current_version = 2
    await session.flush()
    assert (await repo.current_version_for_record(record)).id == versions[2]


async def test_versions_return_none_when_missing(session) -> None:
    tenant = await _tenant(session)
    no_versions, dangling = await _records(session, tenant, 2)
    await _versions(session, tenant, dangling, [2])  # current_version = 1 does not exist
    repo = MemoryVersionRepository(session, tenant)

    assert await repo.highest_version_for_record(no_versions) is None
    assert await repo.current_version_for_record(no_versions) is None
    assert await repo.current_version_for_record(dangling) is None
    assert await repo.highest_version_for_record(_id()) is None


async def test_versions_are_tenant_isolated(session) -> None:
    tenant_a, tenant_b = await _tenant(session), await _tenant(session)
    (record_b,) = await _records(session, tenant_b, 1)
    await _versions(session, tenant_b, record_b, [1])
    repo_a = MemoryVersionRepository(session, tenant_a)

    assert await repo_a.current_version_for_record(record_b) is None
    assert await repo_a.highest_version_for_record(record_b) is None
