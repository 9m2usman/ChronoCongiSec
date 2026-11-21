"""Tests for memory cryptographic integrity audit (Day 7).

Module: backend.app.memory.tests.test_integrity_audit
Owner: M3 — Knowledge & Memory Systems Lead
"""

import asyncio
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import pytest

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.integrity import audit_memory_integrity
from backend.app.memory.models import AgentRecord, SourceRecord
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.versioning import update_memory


@pytest.fixture
def repo():
    return InMemoryMemoryRepository()


@pytest.mark.asyncio
async def test_audit_all_clean_gives_100_percent(repo):
    """When all versions have valid cryptographic checksums, audit returns 100.0% match."""
    tenant_id = "tenant-a-uuid-001"
    await repo.create_agent(AgentRecord(id="agent-001", tenant_id=tenant_id, name="Bot", status="ACTIVE"))
    await repo.create_source(SourceRecord(id="src-doc-001", tenant_id=tenant_id, name="Doc", source_type="DOC", status="ACTIVE"))

    r1, _ = await ingest_memory(tenant_id=tenant_id, content="Record 1 v1", repository=repo)
    await update_memory(tenant_id=tenant_id, record_id=r1.id, content="Record 1 v2", repository=repo)

    r2, _ = await ingest_memory(tenant_id=tenant_id, content="Record 2 v1", repository=repo)

    report = await audit_memory_integrity(tenant_id=tenant_id, repository=repo, batch_size=2)

    assert report.total_records == 2
    assert report.total_versions == 3
    assert report.matched == 3
    assert len(report.mismatched) == 0
    assert len(report.missing_versions) == 0
    assert report.match_percentage == 100.0
    assert report.started_at <= report.finished_at


@pytest.mark.asyncio
async def test_audit_one_tampered_version_reported_and_others_counted(repo):
    """One tampered version is flagged in mismatched; other records and versions are still counted."""
    tenant_id = "tenant-a-uuid-001"
    r1, _ = await ingest_memory(tenant_id=tenant_id, content="Record 1 v1", repository=repo)
    r1, _ = await update_memory(tenant_id=tenant_id, record_id=r1.id, content="Record 1 v2", repository=repo)

    r2, _ = await ingest_memory(tenant_id=tenant_id, content="Record 2 v1", repository=repo)

    # Tamper with version 1 of record 1
    repo._versions[r1.id][0].content = "TAMPERED PAYLOAD"

    report = await audit_memory_integrity(tenant_id=tenant_id, repository=repo, batch_size=10)

    assert report.total_records == 2
    assert report.total_versions == 3
    assert report.matched == 2
    assert len(report.mismatched) == 1
    assert report.mismatched[0].record_id == r1.id
    assert report.mismatched[0].version == 1
    assert report.match_percentage == 66.67


@pytest.mark.asyncio
async def test_audit_record_missing_current_version_reported(repo):
    """A record whose current_version has no corresponding version row is reported in missing_versions."""
    tenant_id = "tenant-a-uuid-001"
    r1, _ = await ingest_memory(tenant_id=tenant_id, content="Record 1 v1", repository=repo)

    # Artificially increment record current_version without adding a version row
    stored_rec = await repo.get_record(r1.id, tenant_id)
    stored_rec.current_version = 99
    await repo.update_record(stored_rec)

    report = await audit_memory_integrity(tenant_id=tenant_id, repository=repo)

    assert report.total_records == 1
    assert report.total_versions == 1
    assert report.matched == 1
    assert r1.id in report.missing_versions


@pytest.mark.asyncio
async def test_audit_empty_tenant_returns_100_percent(repo):
    """An empty tenant returns 0 records, 0 versions, and 100.0% match."""
    report = await audit_memory_integrity(tenant_id="empty-tenant-999", repository=repo)

    assert report.total_records == 0
    assert report.total_versions == 0
    assert report.matched == 0
    assert report.match_percentage == 100.0
    assert len(report.mismatched) == 0
    assert len(report.missing_versions) == 0


@pytest.mark.asyncio
async def test_audit_repository_error_on_one_record_does_not_abort_audit(repo):
    """A repository exception when querying one record's versions is logged and does not abort the audit."""
    tenant_id = "tenant-a-uuid-001"
    r1, _ = await ingest_memory(tenant_id=tenant_id, content="Rec 1", repository=repo)
    r2, _ = await ingest_memory(tenant_id=tenant_id, content="Rec 2", repository=repo)

    class FaultyMemoryRepo(InMemoryMemoryRepository):
        async def get_versions(self, record_id: str, tenant_id: str):
            if record_id == r1.id:
                raise RuntimeError("Simulated database timeout on get_versions")
            return await super().get_versions(record_id, tenant_id)

    faulty_repo = FaultyMemoryRepo()
    faulty_repo._records = deepcopy(repo._records)
    faulty_repo._versions = deepcopy(repo._versions)

    report = await audit_memory_integrity(tenant_id=tenant_id, repository=faulty_repo)

    assert report.total_records == 2
    # Record 1 was flagged under missing_versions due to the error
    assert r1.id in report.missing_versions
    # Record 2 was still processed
    assert report.matched == 1


@pytest.mark.asyncio
async def test_audit_strictly_ignores_other_tenants_data(repo):
    """Data belonging to other tenants is never read or included in the tenant audit report."""
    tenant_a = "tenant-a-uuid-001"
    tenant_b = "tenant-b-uuid-002"

    await repo.create_agent(AgentRecord(id="agent-b", tenant_id=tenant_b, name="Bot B", status="ACTIVE"))
    await repo.create_source(SourceRecord(id="src-b", tenant_id=tenant_b, name="Source B", source_type="DOC", status="ACTIVE"))

    await ingest_memory(tenant_id=tenant_a, content="Tenant A content", repository=repo)
    await ingest_memory(tenant_id=tenant_b, content="Tenant B content", agent_id="agent-b", source_id="src-b", repository=repo)

    report_a = await audit_memory_integrity(tenant_id=tenant_a, repository=repo)
    assert report_a.total_records == 1
    assert report_a.total_versions == 1

    report_b = await audit_memory_integrity(tenant_id=tenant_b, repository=repo)
    assert report_b.total_records == 1
    assert report_b.total_versions == 1


def test_audit_cli_entry_point(monkeypatch):
    """Test running python -m backend.app.memory.integrity_audit via subprocess and in-process."""
    # 1. Subprocess test
    res = subprocess.run(
        [sys.executable, "-m", "backend.app.memory.integrity_audit", "--tenant-id", "tenant-test-cli"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert res.returncode == 0
    assert "AMSC Memory Cryptographic Integrity Audit Runner" in res.stdout
    assert "NOTE: Using in-memory repository stand-in" in res.stdout
    assert "AUDIT RESULT: PASSED" in res.stdout

    # 2. In-process test to measure coverage
    from backend.app.memory.integrity_audit import main
    monkeypatch.setattr(sys, "argv", ["integrity_audit", "--tenant-id", "tenant-test-cli"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_audit_cli_entry_point_failure_exit_code(monkeypatch, repo):
    """Test CLI runner exits with code 1 when mismatches are detected."""
    from backend.app.memory.integrity_audit import main
    from backend.app.memory.repository import get_default_repository

    tenant_id = "tenant-cli-fail"
    default_repo = get_default_repository()
    r1, _ = asyncio.run(ingest_memory(tenant_id=tenant_id, content="Tampered content", repository=default_repo))
    # Tamper with version content
    default_repo._versions[r1.id][0].content = "TAMPERED SECRET"

    monkeypatch.setattr(sys, "argv", ["integrity_audit", "--tenant-id", tenant_id])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
