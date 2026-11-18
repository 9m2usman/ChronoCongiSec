"""API integration tests for Memory & Provenance endpoints.

Module: backend.app.memory.tests.test_api
Owner: M3 — Knowledge & Memory Systems Lead
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.api.memory import get_repository
from backend.app.core.config import get_settings
from backend.app.core.security import create_access_token
from backend.app.main import create_app
from backend.app.memory.hashing import sha256_hex
from backend.app.memory.repository import InMemoryMemoryRepository


@pytest.fixture
def repo():
    """Isolated repository instance for test isolation."""
    return InMemoryMemoryRepository()


@pytest.fixture
def app_and_client(repo):
    """Create test application instance with isolated memory repository."""
    settings = get_settings()
    app = create_app(settings)
    app.state.memory_repo = repo
    app.dependency_overrides[get_repository] = lambda: repo
    client = TestClient(app)
    return app, client, repo


def _make_auth_header(
    tenant_id: str = "tenant-a-uuid-001",
    user_id: str = "user-a-analyst-001",
    role: str = "SECURITY_ANALYST",
) -> dict:
    """Helper to generate valid JWT Bearer authentication headers for testing."""
    settings = get_settings()
    token = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        settings=settings,
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": tenant_id,
    }


def test_api_ingest_memory_success(app_and_client):
    """POST /api/v1/memory must ingest a chunk, return version 1, UNVERIFIED trust state, and SHA-256."""
    _, client, _ = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    payload = {
        "content": "Operating memo on dual custody approval thresholds.",
        "record_type": "KNOWLEDGE",
        "source_id": "src-doc-001",
    }

    response = client.post("/api/v1/memory", json=payload, headers=headers)
    assert response.status_code == 201

    data = response.json()
    assert data["tenant_id"] == "tenant-a-uuid-001"
    assert data["current_version"] == 1
    assert data["trust_state"] == "UNVERIFIED"
    assert data["checksum"] == sha256_hex(payload["content"])
    assert data["content"] == payload["content"]
    assert "id" in data


def test_api_ingest_memory_invalid_record_type_returns_400(app_and_client):
    """POST /api/v1/memory with invalid record_type must fail at schema validation with 400 Bad Request."""
    _, client, _ = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    payload = {
        "content": "Operating memo on dual custody approval thresholds.",
        "record_type": "BOGUS_INVALID_TYPE",
    }

    response = client.post("/api/v1/memory", json=payload, headers=headers)
    assert response.status_code == 400
    err_envelope = response.json()
    assert err_envelope["error"]["code"] == "VALIDATION_ERROR"


def test_api_query_memory_and_strict_tenant_isolation(app_and_client):
    """GET /api/v1/memory must scope results to caller's tenant and exclude other tenants."""
    _, client, repo = app_and_client
    headers_a = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    headers_b = _make_auth_header(tenant_id="tenant-b-uuid-002", user_id="user-b-analyst-003")

    # Ingest for Tenant A
    client.post(
        "/api/v1/memory",
        json={"content": "Company A Treasury Guidelines."},
        headers=headers_a,
    )

    # Ingest for Tenant B
    client.post(
        "/api/v1/memory",
        json={"content": "Company B Treasury Guidelines."},
        headers=headers_b,
    )

    # Transition records to TRUSTED so normal retrieval returns them (GAP-001)
    for r in repo._records.values():
        r.trust_state = "TRUSTED"

    # Tenant A querying -> receives ONLY Company A's record
    res_a = client.get("/api/v1/memory", headers=headers_a)
    assert res_a.status_code == 200
    items_a = res_a.json()
    assert len(items_a) == 1
    assert items_a[0]["tenant_id"] == "tenant-a-uuid-001"
    assert items_a[0]["content"] == "Company A Treasury Guidelines."

    # Tenant B querying -> receives ONLY Company B's record
    res_b = client.get("/api/v1/memory", headers=headers_b)
    assert res_b.status_code == 200
    items_b = res_b.json()
    assert len(items_b) == 1
    assert items_b[0]["tenant_id"] == "tenant-b-uuid-002"
    assert items_b[0]["content"] == "Company B Treasury Guidelines."


def test_api_unauthenticated_request_rejected(app_and_client):
    """Requests without authentication Bearer token must be rejected with 401."""
    _, client, _ = app_and_client

    # 1. Ingest without auth
    res_post = client.post("/api/v1/memory", json={"content": "Unauthorized memory."})
    assert res_post.status_code in (401, 403)
    error_data = res_post.json()
    assert "error" in error_data

    # 2. Query without auth
    res_get = client.get("/api/v1/memory")
    assert res_get.status_code in (401, 403)
    assert "error" in res_get.json()


def test_api_forged_mismatched_tenant_header_rejected(app_and_client):
    """Supplying a forged X-Tenant-ID header differing from authenticated token claims must be rejected with 403."""
    _, client, _ = app_and_client
    # Token minted for Company A, but client attaches forged X-Tenant-ID for Company B
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    headers["X-Tenant-ID"] = "tenant-b-uuid-002"

    response = client.get("/api/v1/memory", headers=headers)
    assert response.status_code == 403
    error_data = response.json()
    assert error_data["error"]["code"] == "TENANT_ACCESS_FORBIDDEN"


def test_api_cross_tenant_parent_reference_rejected(app_and_client):
    """Attempting to ingest a child record linked to another tenant's parent must fail with 404."""
    _, client, _ = app_and_client
    headers_a = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    headers_b = _make_auth_header(tenant_id="tenant-b-uuid-002", user_id="user-b-analyst-003")

    # Ingest parent in Tenant A
    parent_res = client.post(
        "/api/v1/memory",
        json={"content": "Parent document in Tenant A."},
        headers=headers_a,
    )
    assert parent_res.status_code == 201
    parent_id = parent_res.json()["id"]

    # Tenant B tries to ingest referencing Tenant A's parent_id
    child_res = client.post(
        "/api/v1/memory",
        json={
            "content": "Child document attempting cross-tenant linkage.",
            "parent_record_id": parent_id,
        },
        headers=headers_b,
    )
    assert child_res.status_code == 404
    error_data = child_res.json()
    assert error_data["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_api_get_memory_detail_and_cross_tenant_rejection(app_and_client):
    """GET /api/v1/memory/{id} returns full detail to owner; returns 404 to another tenant."""
    _, client, repo = app_and_client
    headers_a = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    headers_b = _make_auth_header(tenant_id="tenant-b-uuid-002", user_id="user-b-analyst-003")

    create_res = client.post(
        "/api/v1/memory",
        json={"content": "Root policy document."},
        headers=headers_a,
    )
    record_id = create_res.json()["id"]
    # Transition record to TRUSTED so normal detail access succeeds (GAP-004)
    repo._records[record_id].trust_state = "TRUSTED"

    # Detail request by Tenant A
    res_a = client.get(f"/api/v1/memory/{record_id}", headers=headers_a)
    assert res_a.status_code == 200
    detail = res_a.json()
    assert detail["record"]["id"] == record_id
    assert detail["record"]["current_version"] == 1
    assert len(detail["versions"]) == 1
    assert detail["versions"][0]["checksum"] == sha256_hex("Root policy document.")

    # Cross-tenant detail access by Tenant B must return 404 Not Found
    res_b = client.get(f"/api/v1/memory/{record_id}", headers=headers_b)
    assert res_b.status_code == 404
    assert res_b.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


# ============================================================================
# Finding 1 Regression Tests: Mandatory Quarantine Exclusion & No Bypass
# ============================================================================

def test_api_quarantined_records_excluded_and_bypass_prohibited(app_and_client):
    """Quarantined records must never appear in normal retrieval, even if client attempts bypass."""
    _, client, repo = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    # Ingest clean record
    res1 = client.post("/api/v1/memory", json={"content": "Clean record."}, headers=headers)
    id1 = res1.json()["id"]
    # Mark record 1 as TRUSTED
    repo._records[id1].trust_state = "TRUSTED"

    # Ingest second record and mark it QUARANTINED in repository
    res2 = client.post("/api/v1/memory", json={"content": "Poisoned record."}, headers=headers)
    id2 = res2.json()["id"]
    repo._records[id2].trust_state = "QUARANTINED"

    # 1. Standard retrieval excludes quarantined record
    res_active = client.get("/api/v1/memory", headers=headers)
    ids_active = [r["id"] for r in res_active.json()]
    assert id1 in ids_active
    assert id2 not in ids_active

    # 2. Attempting to pass exclude_quarantined=false cannot bypass quarantine exclusion
    res_bypass = client.get("/api/v1/memory?exclude_quarantined=false", headers=headers)
    ids_bypass = [r["id"] for r in res_bypass.json()]
    assert id1 in ids_bypass
    assert id2 not in ids_bypass

    # 3. Explicitly querying trust_state=QUARANTINED is forbidden (403)
    res_forbidden = client.get("/api/v1/memory?trust_state=QUARANTINED", headers=headers)
    assert res_forbidden.status_code == 403
    assert res_forbidden.json()["error"]["code"] == "FORBIDDEN_ACTION"


def test_api_detail_endpoint_hides_quarantined_and_rejected_records(app_and_client):
    """GET /api/v1/memory/{id} returns 404 Not Found for QUARANTINED and REJECTED records."""
    _, client, repo = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    # Ingest record and mark it QUARANTINED
    res_q = client.post("/api/v1/memory", json={"content": "Poisoned data"}, headers=headers)
    id_q = res_q.json()["id"]
    repo._records[id_q].trust_state = "QUARANTINED"

    # Detail access on quarantined record must return 404
    detail_res_q = client.get(f"/api/v1/memory/{id_q}", headers=headers)
    assert detail_res_q.status_code == 404
    assert detail_res_q.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

    # Mark as REJECTED
    repo._records[id_q].trust_state = "REJECTED"
    detail_res_r = client.get(f"/api/v1/memory/{id_q}", headers=headers)
    assert detail_res_r.status_code == 404


# ============================================================================
# Finding 3 Regression Tests: Bounded Pagination (TRD §22)
# ============================================================================

def test_api_pagination_defaults_and_limits(app_and_client):
    """Listing supports default 50, custom limits, offset, and max 100 limit."""
    _, client, repo = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    # Ingest 55 records
    for i in range(55):
        client.post(
            "/api/v1/memory",
            json={"content": f"Document index {i:02d}"},
            headers=headers,
        )

    # Transition all records to TRUSTED for normal query retrieval (GAP-001)
    for r in repo._records.values():
        r.trust_state = "TRUSTED"

    # 1. Default query returns exactly 50 records
    res_default = client.get("/api/v1/memory", headers=headers)
    assert res_default.status_code == 200
    items_default = res_default.json()
    assert len(items_default) == 50

    # 2. Query with offset=50, limit=10 returns remaining 5 records
    res_paged = client.get("/api/v1/memory?offset=50&limit=10", headers=headers)
    assert res_paged.status_code == 200
    items_paged = res_paged.json()
    assert len(items_paged) == 5

    # 3. Query with limit=100 returns all 55 records
    res_100 = client.get("/api/v1/memory?limit=100", headers=headers)
    assert res_100.status_code == 200
    assert len(res_100.json()) == 55

    # 4. Invalid limit > 100 rejected (400 VALIDATION_ERROR)
    res_over = client.get("/api/v1/memory?limit=101", headers=headers)
    assert res_over.status_code in (400, 422)

    # 5. Invalid limit < 1 rejected
    res_under = client.get("/api/v1/memory?limit=0", headers=headers)
    assert res_under.status_code in (400, 422)

    # 6. Negative offset rejected
    res_neg = client.get("/api/v1/memory?offset=-1", headers=headers)
    assert res_neg.status_code in (400, 422)


def test_api_pagination_preserves_tenant_isolation(app_and_client):
    """Pagination never crosses tenant boundaries."""
    _, client, repo = app_and_client
    headers_a = _make_auth_header(tenant_id="tenant-a-uuid-001", user_id="user-a-analyst-001")
    headers_b = _make_auth_header(tenant_id="tenant-b-uuid-002", user_id="user-b-analyst-003")

    # Ingest 5 for Tenant A and 5 for Tenant B
    for i in range(5):
        client.post("/api/v1/memory", json={"content": f"A record {i}"}, headers=headers_a)
        client.post("/api/v1/memory", json={"content": f"B record {i}"}, headers=headers_b)

    # Transition records to TRUSTED
    for r in repo._records.values():
        r.trust_state = "TRUSTED"

    # Tenant B paging with limit=100 only receives 5 records, all belonging to tenant-b
    res_b = client.get("/api/v1/memory?limit=100", headers=headers_b)
    items_b = res_b.json()
    assert len(items_b) == 5
    for item in items_b:
        assert item["tenant_id"] == "tenant-b-uuid-002"


def test_api_tampered_checksum_returns_sanitized_500(app_and_client):
    """If a memory version in DB is tampered with, API must return sanitized 500 error envelope."""
    _, client, repo = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    res = client.post("/api/v1/memory", json={"content": "Original authentic content."}, headers=headers)
    record_id = res.json()["id"]

    # Transition to TRUSTED so query attempts retrieval
    repo._records[record_id].trust_state = "TRUSTED"

    # Tamper with stored content in repository
    repo._versions[record_id][0].content = "Tampered content injected directly into storage."

    # Query must trigger 500 error
    query_res = client.get("/api/v1/memory", headers=headers)
    assert query_res.status_code == 500
    error_data = query_res.json()
    assert error_data["error"]["code"] == "MEMORY_INTEGRITY_VIOLATION"
    # Verify no raw traceback or internal file paths leaked
    assert "Traceback" not in str(error_data)
    assert "Exception" not in str(error_data)
    assert "Stored=" not in str(error_data)


# ============================================================================
# GAP-001, GAP-003, GAP-004 Dedicated API Tests
# ============================================================================

def test_api_gap_001_unverified_records_hidden_from_retrieval(app_and_client):
    """GAP-001: Newly ingested UNVERIFIED records are not returned by GET /api/v1/memory."""
    _, client, _ = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    post_res = client.post("/api/v1/memory", json={"content": "New unverified memo."}, headers=headers)
    assert post_res.status_code == 201

    # Normal retrieval returns 0 records
    get_res = client.get("/api/v1/memory", headers=headers)
    assert get_res.status_code == 200
    assert len(get_res.json()) == 0

    # Querying trust_state=UNVERIFIED returns 403 Forbidden
    forbidden_res = client.get("/api/v1/memory?trust_state=UNVERIFIED", headers=headers)
    assert forbidden_res.status_code == 403


def test_api_gap_003_ingest_validates_agent_and_source(app_and_client):
    """GAP-003: Ingest API rejects nonexistent, unowned, or inactive agents and sources."""
    _, client, _ = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    # 1. Nonexistent agent
    res_bad_agent = client.post(
        "/api/v1/memory",
        json={"content": "Memo", "agent_id": "ghost-agent-999"},
        headers=headers,
    )
    assert res_bad_agent.status_code in (400, 422)

    # 2. Inactive / ISOLATED agent (agent-inactive-001 was seeded with status ISOLATED)
    res_isolated_agent = client.post(
        "/api/v1/memory",
        json={"content": "Memo", "agent_id": "agent-inactive-001"},
        headers=headers,
    )
    assert res_isolated_agent.status_code in (400, 422)

    # 3. Nonexistent source
    res_bad_source = client.post(
        "/api/v1/memory",
        json={"content": "Memo", "source_id": "ghost-source-999"},
        headers=headers,
    )
    assert res_bad_source.status_code in (400, 422)

    # 4. Inactive source (src-inactive-001 was seeded with status INACTIVE)
    res_inactive_source = client.post(
        "/api/v1/memory",
        json={"content": "Memo", "source_id": "src-inactive-001"},
        headers=headers,
    )
    assert res_inactive_source.status_code in (400, 422)


def test_api_gap_004_detail_endpoint_hides_unverified_records(app_and_client):
    """GAP-004: GET /api/v1/memory/{id} returns 404 for UNVERIFIED records; returns 200 once TRUSTED."""
    _, client, repo = app_and_client
    headers = _make_auth_header(tenant_id="tenant-a-uuid-001")

    post_res = client.post("/api/v1/memory", json={"content": "Initial unverified record."}, headers=headers)
    rec_id = post_res.json()["id"]

    # Initial state is UNVERIFIED -> returns 404
    detail_res_unverified = client.get(f"/api/v1/memory/{rec_id}", headers=headers)
    assert detail_res_unverified.status_code == 404

    # Promote to TRUSTED -> returns 200
    repo._records[rec_id].trust_state = "TRUSTED"
    detail_res_trusted = client.get(f"/api/v1/memory/{rec_id}", headers=headers)
    assert detail_res_trusted.status_code == 200
    assert detail_res_trusted.json()["record"]["trust_state"] == "TRUSTED"
