"""
CloudGuard Phase 4 Tests — Resource Explorer API

Tests for:
  GET /resources
  GET /resources/{resource_id}
  Filtering by service, region, posture
  Pagination limit/offset
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client(auth_client):
    auth_client.post("/scans", json={"scenario": "default"})
    return auth_client


class TestResourceExplorerAPI:
    def test_list_resources_returns_200(self, client):
        resp = client.get("/resources")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["total"] > 0

    def test_resource_item_structure(self, client):
        resp = client.get("/resources")
        item = resp.json()["items"][0]
        required = [
            "resource_id", "resource_type", "service", "provider",
            "account_id", "region", "security_posture", "finding_count",
            "critical_count", "high_count", "medium_count", "low_count",
            "relationships",
        ]
        for field in required:
            assert field in item, f"Missing field {field} in resource response"

    def test_filter_by_service(self, client):
        resp = client.get("/resources?service=s3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) > 0
        assert all(r["service"] == "s3" for r in data["items"])

    def test_filter_by_security_posture(self, client):
        resp = client.get("/resources?security_posture=CRITICAL")
        assert resp.status_code == 200
        data = resp.json()
        assert all(r["security_posture"] == "CRITICAL" for r in data["items"])

    def test_invalid_security_posture_returns_400(self, client):
        resp = client.get("/resources?security_posture=INVALID_POSTURE")
        assert resp.status_code == 400

    def test_pagination(self, client):
        resp = client.get("/resources?limit=3&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 3
        assert data["limit"] == 3

    def test_get_resource_by_id_returns_200(self, client):
        list_resp = client.get("/resources")
        resource_id = list_resp.json()["items"][0]["resource_id"]

        detail_resp = client.get(f"/resources/{resource_id}")
        assert detail_resp.status_code == 200
        data = detail_resp.json()
        assert data["resource_id"] == resource_id
        assert "config" in data
        assert "findings" in data

    def test_get_unknown_resource_returns_404(self, client):
        resp = client.get("/resources/non-existent-resource-999")
        assert resp.status_code == 404

    def test_clean_resource_has_secure_posture(self, client):
        # In default scenario, acme-audit-logs bucket is clean
        resp = client.get("/resources/acme-audit-logs")
        if resp.status_code == 200:
            assert resp.json()["security_posture"] == "SECURE"
            assert resp.json()["finding_count"] == 0
