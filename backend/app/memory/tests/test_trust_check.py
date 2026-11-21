"""Unit tests for memory trust-check connector for Security Gateway (Gate G4).

Module: backend.app.memory.tests.test_trust_check
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 02 §16 (Check 6: Memory Trust Check), Document 03 §VerifyTrustState,
and Document 06 Day 4 specifications.
"""

from copy import deepcopy
import sys
from pathlib import Path
import pytest

# Ensure repo root is in sys.path
repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.main import app
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.models import (
    AgentRecord,
    MemoryRecord,
    MemoryRefCheck,
    MemoryRefStatus,
    MemoryVersion,
    SourceRecord,
    TrustState,
)
from backend.app.memory.repository import InMemoryMemoryRepository
from backend.app.memory.retrieval import (
    MAX_MEMORY_REFS_PER_PROPOSAL,
    transition_memory_trust_state,
    verify_memory_refs,
)
from backend.app.memory.tests.trust_helpers import force_trust_state


@pytest.fixture
def repo():
    """Isolated in-memory repository for test execution."""
    return InMemoryMemoryRepository()


@pytest.fixture
def seeded_repo(repo):
    """Seed sample records across different trust states within tenant-a and tenant-b."""
    t_a = "tenant-a"
    t_b = "tenant-b"

    # Setup active agent & source
    repo.create_agent(AgentRecord(id="agent-01", tenant_id=t_a, name="Bot A", status="ACTIVE"))
    repo.create_source(SourceRecord(id="src-01", tenant_id=t_a, name="Source A", source_type="DOC"))
    repo.create_agent(AgentRecord(id="agent-02", tenant_id=t_b, name="Bot B", status="ACTIVE"))
    repo.create_source(SourceRecord(id="src-02", tenant_id=t_b, name="Source B", source_type="DOC"))

    # Ingest baseline records in tenant-a
    rec_trusted, _ = ingest_memory(
        tenant_id=t_a,
        content="Policy threshold $500",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )
    force_trust_state(
        tenant_id=t_a,
        record_id=rec_trusted.id,
        new_trust_state="TRUSTED",
        repository=repo,
    )

    rec_unverified, _ = ingest_memory(
        tenant_id=t_a,
        content="Unverified market note",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )

    rec_suspicious, _ = ingest_memory(
        tenant_id=t_a,
        content="Suspicious memory item",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )
    transition_memory_trust_state(
        tenant_id=t_a,
        record_id=rec_suspicious.id,
        new_trust_state="SUSPICIOUS",
        repository=repo,
    )

    rec_quarantined, _ = ingest_memory(
        tenant_id=t_a,
        content="Quarantined wire memo",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )
    transition_memory_trust_state(
        tenant_id=t_a,
        record_id=rec_quarantined.id,
        new_trust_state="QUARANTINED",
        repository=repo,
    )

    rec_rejected, _ = ingest_memory(
        tenant_id=t_a,
        content="Rejected proposal memo",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )
    force_trust_state(
        tenant_id=t_a,
        record_id=rec_rejected.id,
        new_trust_state="REJECTED",
        repository=repo,
    )

    rec_superseded, _ = ingest_memory(
        tenant_id=t_a,
        content="Superseded parameter guide",
        agent_id="agent-01",
        source_id="src-01",
        repository=repo,
    )
    force_trust_state(
        tenant_id=t_a,
        record_id=rec_superseded.id,
        new_trust_state="SUPERSEDED",
        repository=repo,
    )

    # Ingest record in tenant-b (cross-tenant)
    rec_tenant_b, _ = ingest_memory(
        tenant_id=t_b,
        content="Secret tenant b policy",
        agent_id="agent-02",
        source_id="src-02",
        repository=repo,
    )
    force_trust_state(
        tenant_id=t_b,
        record_id=rec_tenant_b.id,
        new_trust_state="TRUSTED",
        repository=repo,
    )

    return {
        "repo": repo,
        "tenant_a": t_a,
        "tenant_b": t_b,
        "trusted_id": rec_trusted.id,
        "unverified_id": rec_unverified.id,
        "suspicious_id": rec_suspicious.id,
        "quarantined_id": rec_quarantined.id,
        "rejected_id": rec_rejected.id,
        "superseded_id": rec_superseded.id,
        "tenant_b_id": rec_tenant_b.id,
    }


def test_trusted_gives_ok(seeded_repo):
    """TRUSTED record with valid checksum returns OK status, TRUSTED state, and current version."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    trusted_id = seeded_repo["trusted_id"]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=[trusted_id], repository=repo)

    assert len(results) == 1
    res = results[0]
    assert res.record_id == trusted_id
    assert res.status == MemoryRefStatus.OK
    assert res.trust_state == TrustState.TRUSTED.value
    assert res.current_version == 1
    assert "verified" in res.reason.lower()


def test_all_trust_states_return_ok_status_with_exact_trust_state(seeded_repo):
    """QUARANTINED, SUSPICIOUS, UNVERIFIED, REJECTED, and SUPERSEDED return OK status with exact trust_state."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]

    refs = [
        seeded_repo["unverified_id"],
        seeded_repo["suspicious_id"],
        seeded_repo["quarantined_id"],
        seeded_repo["rejected_id"],
        seeded_repo["superseded_id"],
    ]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=refs, repository=repo)

    assert len(results) == 5

    # UNVERIFIED
    assert results[0].record_id == seeded_repo["unverified_id"]
    assert results[0].status == MemoryRefStatus.OK
    assert results[0].trust_state == TrustState.UNVERIFIED.value
    assert results[0].current_version == 1

    # SUSPICIOUS
    assert results[1].record_id == seeded_repo["suspicious_id"]
    assert results[1].status == MemoryRefStatus.OK
    assert results[1].trust_state == TrustState.SUSPICIOUS.value
    assert results[1].current_version == 1

    # QUARANTINED
    assert results[2].record_id == seeded_repo["quarantined_id"]
    assert results[2].status == MemoryRefStatus.OK
    assert results[2].trust_state == TrustState.QUARANTINED.value
    assert results[2].current_version == 1

    # REJECTED
    assert results[3].record_id == seeded_repo["rejected_id"]
    assert results[3].status == MemoryRefStatus.OK
    assert results[3].trust_state == TrustState.REJECTED.value
    assert results[3].current_version == 1

    # SUPERSEDED
    assert results[4].record_id == seeded_repo["superseded_id"]
    assert results[4].status == MemoryRefStatus.OK
    assert results[4].trust_state == TrustState.SUPERSEDED.value
    assert results[4].current_version == 1


def test_unknown_id_gives_not_found(seeded_repo):
    """An unknown record id returns NOT_FOUND status, None trust_state/version, and sanitized reason."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    unknown_id = "mem-nonexistent-999"

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=[unknown_id], repository=repo)

    assert len(results) == 1
    res = results[0]
    assert res.record_id == unknown_id
    assert res.status == MemoryRefStatus.NOT_FOUND
    assert res.trust_state is None
    assert res.current_version is None
    assert res.reason == "Memory record not found or inaccessible in tenant scope."


def test_cross_tenant_id_gives_identical_not_found(seeded_repo):
    """Another tenant's record id returns NOT_FOUND with the exact same reason text as unknown id."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    tenant_b_id = seeded_repo["tenant_b_id"]

    results_cross = verify_memory_refs(tenant_id=tenant_a, memory_refs=[tenant_b_id], repository=repo)
    results_unknown = verify_memory_refs(tenant_id=tenant_a, memory_refs=["unknown-123"], repository=repo)

    assert len(results_cross) == 1
    assert len(results_unknown) == 1
    assert results_cross[0].status == MemoryRefStatus.NOT_FOUND
    assert results_cross[0].trust_state is None
    assert results_cross[0].current_version is None
    # Must never reveal that the record exists in another tenant
    assert results_cross[0].reason == results_unknown[0].reason
    assert "not found or inaccessible" in results_cross[0].reason.lower()


def test_tampered_content_gives_integrity_failed(seeded_repo):
    """Tampering with stored content results in INTEGRITY_FAILED status."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    trusted_id = seeded_repo["trusted_id"]

    # Tamper with the raw in-memory stored version content
    stored_ver = repo._versions[trusted_id][0]
    stored_ver.content = "MALICIOUS TAMPERED INJECTION: wire $999999"

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=[trusted_id], repository=repo)

    assert len(results) == 1
    res = results[0]
    assert res.record_id == trusted_id
    assert res.status == MemoryRefStatus.INTEGRITY_FAILED
    assert res.trust_state == TrustState.TRUSTED.value
    assert res.current_version == 1
    assert "checksum mismatch" in res.reason.lower()


def test_empty_non_string_and_duplicate_refs_handled(seeded_repo):
    """Malformed, empty, non-string, and duplicate refs are handled gracefully without raising."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    trusted_id = seeded_repo["trusted_id"]

    refs = [
        "",                     # empty string
        "   ",                  # whitespace string
        12345,                  # integer ref
        None,                   # None ref
        trusted_id,             # first occurrence (OK)
        trusted_id,             # duplicate occurrence (DUPLICATE_REF)
    ]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=refs, repository=repo)

    assert len(results) == 6
    assert results[0].status == MemoryRefStatus.INVALID_REF
    assert results[1].status == MemoryRefStatus.INVALID_REF
    assert results[2].status == MemoryRefStatus.INVALID_REF
    assert results[3].status == MemoryRefStatus.INVALID_REF

    # 1st valid ref
    assert results[4].record_id == trusted_id
    assert results[4].status == MemoryRefStatus.OK

    # 2nd duplicate ref
    assert results[5].record_id == trusted_id
    assert results[5].status == MemoryRefStatus.DUPLICATE_REF
    assert "duplicate" in results[5].reason.lower()


def test_injected_repository_exception_gives_error_and_continues(seeded_repo):
    """An injected repository exception for one ref returns ERROR for that ref and checks remaining refs."""
    base_repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    trusted_id = seeded_repo["trusted_id"]
    unverified_id = seeded_repo["unverified_id"]

    class FaultyRepository(InMemoryMemoryRepository):
        def get_record(self, record_id: str, tenant_id: str):
            if record_id == "faulty-ref-id":
                raise RuntimeError("Simulated transient database driver timeout")
            return super().get_record(record_id, tenant_id)

    faulty_repo = FaultyRepository()
    # Copy data from base_repo
    faulty_repo._records = deepcopy(base_repo._records)
    faulty_repo._versions = deepcopy(base_repo._versions)

    refs = [trusted_id, "faulty-ref-id", unverified_id]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=refs, repository=faulty_repo)

    assert len(results) == 3

    # Ref 1: OK
    assert results[0].record_id == trusted_id
    assert results[0].status == MemoryRefStatus.OK

    # Ref 2: ERROR (fail-closed, does not raise)
    assert results[1].record_id == "faulty-ref-id"
    assert results[1].status == MemoryRefStatus.ERROR
    assert "unexpected error" in results[1].reason.lower()

    # Ref 3: OK (still verified)
    assert results[2].record_id == unverified_id
    assert results[2].status == MemoryRefStatus.OK
    assert results[2].trust_state == TrustState.UNVERIFIED.value


def test_ordering_is_strictly_preserved(seeded_repo):
    """The returned result list must match the exact sequence and length of the input refs."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]

    refs = [
        seeded_repo["quarantined_id"],
        "unknown-ref-z",
        seeded_repo["trusted_id"],
        "",
        seeded_repo["suspicious_id"],
    ]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=refs, repository=repo)

    assert len(results) == len(refs)
    assert results[0].record_id == seeded_repo["quarantined_id"]
    assert results[0].status == MemoryRefStatus.OK
    assert results[0].trust_state == TrustState.QUARANTINED.value

    assert results[1].record_id == "unknown-ref-z"
    assert results[1].status == MemoryRefStatus.NOT_FOUND

    assert results[2].record_id == seeded_repo["trusted_id"]
    assert results[2].status == MemoryRefStatus.OK
    assert results[2].trust_state == TrustState.TRUSTED.value

    assert results[3].status == MemoryRefStatus.INVALID_REF

    assert results[4].record_id == seeded_repo["suspicious_id"]
    assert results[4].status == MemoryRefStatus.OK
    assert results[4].trust_state == TrustState.SUSPICIOUS.value


def test_no_record_or_version_modified_read_only(seeded_repo):
    """Verification must be strictly read-only: no record, version, or updated_at may be changed."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]
    trusted_id = seeded_repo["trusted_id"]
    quarantined_id = seeded_repo["quarantined_id"]

    # Capture state before verification
    rec_before_trusted = deepcopy(repo.get_record(trusted_id, tenant_a))
    ver_before_trusted = deepcopy(repo.get_versions(trusted_id, tenant_a))
    rec_before_quar = deepcopy(repo.get_record(quarantined_id, tenant_a))
    ver_before_quar = deepcopy(repo.get_versions(quarantined_id, tenant_a))

    # Run verification
    results = verify_memory_refs(
        tenant_id=tenant_a,
        memory_refs=[trusted_id, quarantined_id],
        repository=repo,
    )

    assert len(results) == 2

    # Capture state after verification
    rec_after_trusted = repo.get_record(trusted_id, tenant_a)
    ver_after_trusted = repo.get_versions(trusted_id, tenant_a)
    rec_after_quar = repo.get_record(quarantined_id, tenant_a)
    ver_after_quar = repo.get_versions(quarantined_id, tenant_a)

    assert rec_before_trusted == rec_after_trusted
    assert ver_before_trusted == ver_after_trusted
    assert rec_before_quar == rec_after_quar
    assert ver_before_quar == ver_after_quar
    assert rec_after_trusted.trust_state == TrustState.TRUSTED.value
    assert rec_after_quar.trust_state == TrustState.QUARANTINED.value
    assert rec_after_trusted.updated_at == rec_before_trusted.updated_at
    assert rec_after_quar.updated_at == rec_before_quar.updated_at


def test_oversized_list_is_rejected(seeded_repo):
    """A list exceeding MAX_MEMORY_REFS_PER_PROPOSAL is rejected with ERROR status."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]

    oversized = [f"ref-id-{i}" for i in range(MAX_MEMORY_REFS_PER_PROPOSAL + 1)]
    results = verify_memory_refs(tenant_id=tenant_a, memory_refs=oversized, repository=repo)

    assert len(results) == 1
    assert results[0].status == MemoryRefStatus.ERROR
    assert "exceeds maximum allowed memory references limit" in results[0].reason


def test_non_list_payload_is_rejected(seeded_repo):
    """Passing a non-list object as memory_refs returns INVALID_REF without raising."""
    repo = seeded_repo["repo"]
    tenant_a = seeded_repo["tenant_a"]

    results = verify_memory_refs(tenant_id=tenant_a, memory_refs="not-a-list", repository=repo)
    assert len(results) == 1
    assert results[0].status == MemoryRefStatus.INVALID_REF


def test_openapi_has_no_route_exposing_verify_memory_refs():
    """Verify that verify_memory_refs is NOT exposed through any FastAPI API route in app.openapi()."""
    schema = app.openapi()
    paths = schema.get("paths", {})

    forbidden_terms = ["verify_memory_refs", "verify-memory-refs", "verify_memory", "memory_refs"]

    for path, path_item in paths.items():
        for term in forbidden_terms:
            assert term not in path.lower(), f"Path '{path}' exposes forbidden memory trust check term '{term}'"

        for method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId", "")
            summary = operation.get("summary", "")
            description = operation.get("description", "")

            assert "verify_memory_refs" not in op_id.lower()
            assert "verify_memory_refs" not in summary.lower()
            assert "verify_memory_refs" not in description.lower()
