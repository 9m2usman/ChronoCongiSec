"""Tests for atomic write groups and optimistic concurrency control (GAP-008).

Module: backend.app.memory.tests.test_atomic_writes
Owner: M3 — Knowledge & Memory Systems Lead
"""

import asyncio
from copy import deepcopy
from pathlib import Path
import sys
import pytest

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.core.exceptions import ValidationError
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.models import AgentRecord, MemoryRecord, MemoryVersion, SourceRecord, TrustState
from backend.app.memory.provenance import create_provenance_edge
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.retrieval import get_memory_detail, transition_memory_trust_state
from backend.app.memory.versioning import update_memory


@pytest.fixture
def repo():
    return InMemoryMemoryRepository()


@pytest.mark.asyncio
async def test_atomic_success_commits_all_items(repo):
    """When ingestion succeeds, record, initial version, and optional edge are atomically committed."""
    tenant_id = "tenant-atomic-001"
    rec, ver = await ingest_memory(
        tenant_id=tenant_id,
        content="Atomic transaction successful content.",
        repository=repo,
    )

    # Both record and version exist in repository
    stored_rec = await repo.get_record(rec.id, tenant_id)
    stored_ver = await repo.get_version(rec.id, 1, tenant_id)
    assert stored_rec is not None
    assert stored_rec.id == rec.id
    assert stored_ver is not None
    assert stored_ver.version == 1
    assert stored_ver.content == "Atomic transaction successful content."


@pytest.mark.asyncio
async def test_ingest_failure_after_record_creation_leaves_no_partial_record(repo):
    """If a failure occurs after record creation (e.g. during create_version), the record is rolled back."""
    tenant_id = "tenant-atomic-001"

    class FailureRepo(InMemoryMemoryRepository):
        async def create_version(self, version):
            raise RuntimeError("Injected database crash on version creation")

    faulty_repo = FailureRepo()
    faulty_repo._agents = deepcopy(repo._agents)
    faulty_repo._sources = deepcopy(repo._sources)

    with pytest.raises(RuntimeError) as exc:
        await ingest_memory(
            tenant_id=tenant_id,
            content="Content doomed to fail on version creation",
            repository=faulty_repo,
        )
    assert "Injected database crash" in str(exc.value)

    # Repository must contain zero records and zero versions
    records = await faulty_repo.list_records(tenant_id=tenant_id, only_trusted=False)
    assert len(records) == 0
    assert len(faulty_repo._records) == 0
    assert len(faulty_repo._versions) == 0


@pytest.mark.asyncio
async def test_ingest_failure_during_provenance_edge_leaves_no_record_version_or_edge(repo):
    """If edge creation fails during derived ingestion, record, version, and edge are all rolled back."""
    tenant_id = "tenant-atomic-001"
    parent, _ = await ingest_memory(tenant_id=tenant_id, content="Parent record", repository=repo)

    class EdgeFailureRepo(InMemoryMemoryRepository):
        async def create_edge(self, edge):
            raise RuntimeError("Injected crash during provenance edge insertion")

    faulty_repo = EdgeFailureRepo()
    faulty_repo._records = deepcopy(repo._records)
    faulty_repo._versions = deepcopy(repo._versions)
    faulty_repo._edges = deepcopy(repo._edges)

    with pytest.raises(RuntimeError) as exc:
        await ingest_memory(
            tenant_id=tenant_id,
            content="Child record doomed to fail on edge creation",
            parent_record_id=parent.id,
            repository=faulty_repo,
        )
    assert "Injected crash during provenance edge insertion" in str(exc.value)

    # Only parent record exists; child record, child version, and edge must NOT exist
    all_recs = await faulty_repo.list_records(tenant_id=tenant_id, only_trusted=False)
    assert len(all_recs) == 1
    assert all_recs[0].id == parent.id

    parent_edges = await faulty_repo.get_edges_for_record(parent.id, tenant_id)
    assert len(parent_edges) == 0


@pytest.mark.asyncio
async def test_update_failure_after_version_insert_leaves_old_version_and_no_new_version_row(repo):
    """If an update fails during update_record, the appended version row is rolled back and current_version unchanged."""
    tenant_id = "tenant-atomic-001"
    rec, ver1 = await ingest_memory(tenant_id=tenant_id, content="Initial v1 content", repository=repo)

    class RecordUpdateFailureRepo(InMemoryMemoryRepository):
        async def update_record(self, record):
            raise RuntimeError("Injected database crash on update_record")

    faulty_repo = RecordUpdateFailureRepo()
    faulty_repo._records = deepcopy(repo._records)
    faulty_repo._versions = deepcopy(repo._versions)

    with pytest.raises(RuntimeError) as exc:
        await update_memory(
            tenant_id=tenant_id,
            record_id=rec.id,
            content="Attempted v2 update that crashes",
            repository=faulty_repo,
        )
    assert "Injected database crash on update_record" in str(exc.value)

    # Invariants: current_version stays 1, versions list has only version 1
    stored_rec = await faulty_repo.get_record(rec.id, tenant_id)
    assert stored_rec.current_version == 1
    versions = await faulty_repo.get_versions(rec.id, tenant_id)
    assert len(versions) == 1
    assert versions[0].version == 1
    assert versions[0].content == "Initial v1 content"


@pytest.mark.asyncio
async def test_nested_transaction_joins_outer_and_rolls_back_everything(repo):
    """Nested transaction() calls join the outer transaction and roll back everything on failure."""
    tenant_id = "tenant-atomic-001"

    with pytest.raises(ValueError):
        async with repo.transaction():
            rec = MemoryRecord(id="rec-tx-1", tenant_id=tenant_id, current_version=1)
            await repo.create_record(rec)
            async with repo.transaction():
                ver = MemoryVersion(
                    id="ver-tx-1",
                    tenant_id=tenant_id,
                    record_id="rec-tx-1",
                    version=1,
                    content="Nested transaction content",
                    checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
                await repo.create_version(ver)
                raise ValueError("Boom inside nested transaction")

    # Both record and version must be rolled back completely
    assert await repo.get_record("rec-tx-1", tenant_id) is None
    assert len(await repo.get_versions("rec-tx-1", tenant_id)) == 0


@pytest.mark.asyncio
async def test_duplicate_record_id_version_rejected(repo):
    """Attempting to insert a duplicate (record_id, version) is rejected by repository integrity check."""
    tenant_id = "tenant-atomic-001"
    rec, ver = await ingest_memory(tenant_id=tenant_id, content="Initial record", repository=repo)

    duplicate_ver = MemoryVersion(
        id="ver-dup-uuid",
        tenant_id=tenant_id,
        record_id=rec.id,
        version=1,
        content="Duplicate version 1 content",
        checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    with pytest.raises(ValueError) as exc:
        await repo.create_version(duplicate_ver)
    assert "already exists" in str(exc.value)


@pytest.mark.asyncio
async def test_concurrent_updates_with_expected_current_version(repo):
    """Two concurrent updates with expected_current_version=1: exactly one succeeds and one raises ValidationError."""
    tenant_id = "tenant-atomic-001"
    rec, ver = await ingest_memory(tenant_id=tenant_id, content="Version 1 baseline", repository=repo)

    async def do_update(new_text: str):
        return await update_memory(
            tenant_id=tenant_id,
            record_id=rec.id,
            content=new_text,
            expected_current_version=1,
            repository=repo,
        )

    # Launch two updates targeting expected_current_version=1 concurrently
    res1, res2 = await asyncio.gather(
        do_update("Update Attempt A"),
        do_update("Update Attempt B"),
        return_exceptions=True,
    )

    successes = [r for r in (res1, res2) if not isinstance(r, Exception)]
    errors = [r for r in (res1, res2) if isinstance(r, Exception)]

    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ValidationError)
    assert "Optimistic concurrency conflict" in str(errors[0])

    # Record must be at version 2, and exactly 2 version rows exist
    final_rec = await repo.get_record(rec.id, tenant_id)
    assert final_rec.current_version == 2
    versions = await repo.get_versions(rec.id, tenant_id)
    assert len(versions) == 2
