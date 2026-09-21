"""
CloudGuard Phase 4 Tests — Security Posture API

Tests for:
  GET /posture
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client(auth_client):
    auth_client.post("/scans", json={"scenario": "default"})
    return auth_client


class TestPostureAPI:
    def test_get_posture_returns_200(self, client):
        resp = client.get("/posture")
        assert resp.status_code == 200
        data = resp.json()

        assert "posture_score" in data
        assert 0.0 <= data["posture_score"] <= 100.0
        assert "risk_level" in data
        assert data["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
        assert "total_resources" in data
        assert data["total_resources"] > 0
        assert "total_findings" in data
        assert "service_posture" in data
        assert "resource_posture_summary" in data

    def test_service_posture_breakdown_covers_scanned_services(self, client):
        resp = client.get("/posture")
        svc = resp.json()["service_posture"]
        assert isinstance(svc, dict)
        # S3 and IAM are always present in default demo scenario
        assert "s3" in svc or "iam" in svc

    def test_resource_posture_summary_structure(self, client):
        resp = client.get("/posture")
        summary = resp.json()["resource_posture_summary"]
        for key in ("SECURE", "AT_RISK", "HIGH_RISK", "CRITICAL"):
            assert key in summary
            assert summary[key] >= 0
