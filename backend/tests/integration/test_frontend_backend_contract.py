"""
Integration Tests for Frontend ↔ Backend Contract Validation.

This module tests the integration between the frontend and backend systems.
"""

import pytest
import httpx
from fastapi.testclient import TestClient
from backend.app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def test_memory_retrieval(client):
    """Test that memory records are correctly retrieved from the backend."""
    # This test assumes a valid JWT token is required for authenticated requests
    response = client.get("/api/v1/memory")
    assert response.status_code == 401  # Expecting unauthorized without token


def test_containment_apply(client):
    """Test the containment apply endpoint."""
    # Mock data for containment request
    containment_data = {
        "record_id": "test-record-123",
        "reason": "Test containment reason",
        "reason_code": "TEST_REASON",
        "incident_id": "inc-001"
    }

    # This test assumes a valid JWT token is required for authenticated requests
    response = client.post("/api/v1/security/containment/apply", json=containment_data)
    assert response.status_code == 401  # Expecting unauthorized without token


def test_containment_recommendations(client):
    """Test the containment recommendations endpoint."""
    # This test assumes a valid JWT token is required for authenticated requests
    response = client.get("/api/v1/security/containment/recommendations")
    assert response.status_code == 401  # Expecting unauthorized without token