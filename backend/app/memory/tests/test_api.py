"""API tests for Memory & Provenance FastAPI router."""

import sys
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[4]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.api.memory import get_repository, router
from backend.app.memory.hashing import sha256_hex
from backend.app.memory.repository import InMemoryMemoryRepository


@pytest.fixture
def test_app():
    """Create a test FastAPI app containing the memory router."""
    app = FastAPI(title="AMSC Test Application")
    # Mount at /memory and /api/v1/memory to test canonical routes
    app.include_router(router, prefix="/api/v1")
    app.include_router(router)

    # Isolated repository for tests
    repo = InMemoryMemoryRepository()
    app.dependency_overrides[get_repository] = lambda: repo
    return app, repo


@pytest.fixture
def client(test_app):
    app, _ = test_app
    return TestClient(app)


def test_api_ingest_memory(client):
    """POST /api/v1/memory must ingest a chunk, return version 1 and SHA-256."""
    headers = {"X-Tenant-ID": "tenant-alpha"}
    payload = {
        "content": "Operating memo on dual custody approval thresholds.",
        "record_type": "KNOWLEDGE",
        "source_id": "src-doc-001",
    }

    response = client.post("/api/v1/memory", json=payload, headers=headers)
    assert response.status_code == 201

    data = response.json()
    assert data["tenant_id"] == "tenant-alpha"
    assert data["current_version"] == 1
    assert data["trust_state"] == "UNVERIFIED"
    assert data["checksum"] == sha256_hex(payload["content"])
    assert data["content"] == payload["content"]
    assert "id" in data


def test_api_query_memory_and_tenant_isolation(client):
    """GET /api/v1/memory must scope results to tenant and support exclude_quarantined."""
    # 1. Ingest record for Tenant A
    client.post(
        "/api/v1/memory",
        json={"content": "Company A Treasury Guidelines."},
        headers={"X-Tenant-ID": "tenant-company-a"},
    )

    # 2. Ingest record for Tenant B
    client.post(
        "/api/v1/memory",
        json={"content": "Company B Treasury Guidelines."},
        headers={"X-Tenant-ID": "tenant-company-b"},
    )

    # 3. Query as Tenant A -> only gets Tenant A's record
    res_a = client.get("/api/v1/memory", headers={"X-Tenant-ID": "tenant-company-a"})
    assert res_a.status_code == 200
    items_a = res_a.json()
    assert len(items_a) == 1
    assert items_a[0]["tenant_id"] == "tenant-company-a"
    assert items_a[0]["content"] == "Company A Treasury Guidelines."

    # 4. Query as Tenant B -> only gets Tenant B's record
    res_b = client.get("/api/v1/memory", headers={"X-Tenant-ID": "tenant-company-b"})
    assert res_b.status_code == 200
    items_b = res_b.json()
    assert len(items_b) == 1
    assert items_b[0]["tenant_id"] == "tenant-company-b"
    assert items_b[0]["content"] == "Company B Treasury Guidelines."

    # 5. Query as unrepresented Tenant C -> gets empty list
    res_c = client.get("/api/v1/memory", headers={"X-Tenant-ID": "tenant-company-c"})
    assert res_c.status_code == 200
    assert len(res_c.json()) == 0


def test_api_get_memory_detail(client):
    """GET /api/v1/memory/{id} returns full record, versions list, and provenance edges."""
    headers = {"X-Tenant-ID": "tenant-alpha"}
    create_res = client.post(
        "/api/v1/memory",
        json={"content": "Root policy document."},
        headers=headers,
    )
    record_id = create_res.json()["id"]

    # Detail request
    res = client.get(f"/api/v1/memory/{record_id}", headers=headers)
    assert res.status_code == 200

    detail = res.json()
    assert detail["record"]["id"] == record_id
    assert detail["record"]["current_version"] == 1
    assert len(detail["versions"]) == 1
    assert detail["versions"][0]["version"] == 1
    assert detail["versions"][0]["checksum"] == sha256_hex("Root policy document.")

    # Cross-tenant detail access must return 404 Not Found
    forbidden_res = client.get(
        f"/api/v1/memory/{record_id}",
        headers={"X-Tenant-ID": "tenant-adversary"},
    )
    assert forbidden_res.status_code == 404


def test_api_request_without_tenant_header_returns_403(client):
    """Requests without mandatory X-Tenant-ID header must be rejected with 403 Forbidden."""
    # 1. Ingest without header
    post_res = client.post(
        "/api/v1/memory",
        json={"content": "Unauthorized payload without tenant context."},
    )
    assert post_res.status_code == 403
    assert "Forbidden" in post_res.json()["detail"]

    # 2. Query without header
    get_res = client.get("/api/v1/memory")
    assert get_res.status_code == 403
    assert "Forbidden" in get_res.json()["detail"]

    # 3. Get detail without header
    detail_res = client.get("/api/v1/memory/rec-12345")
    assert detail_res.status_code == 403
    assert "Forbidden" in detail_res.json()["detail"]

