"""
CloudGuard Phase 4 Tests — Investigation API Endpoint

Tests for:
  GET /findings/{finding_id}/investigation
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app
from services.scan_store import get_scan_store


@pytest.fixture
def client(auth_client):
    auth_client.post("/scans", json={"scenario": "default"})
    return auth_client


class TestInvestigationAPI:
    def test_investigation_endpoint_returns_200_for_known_finding(self, client):
        findings_resp = client.get("/findings")
        assert findings_resp.status_code == 200
        items = findings_resp.json()["items"]
        assert len(items) > 0

        finding_id = items[0]["finding_id"]
        inv_resp = client.get(f"/findings/{finding_id}/investigation")
        assert inv_resp.status_code == 200

        data = inv_resp.json()
        assert "finding" in data
        assert "rule" in data
        assert "evidence" in data
        assert "risk_context" in data
        assert "security_context" in data
        assert "related_resources" in data
        assert "related_findings" in data
        assert "ai_analysis" in data
        assert "remediation_context" in data
        assert "compliance_context" in data

    def test_investigation_by_canonical_id(self, client):
        findings_resp = client.get("/findings")
        items = findings_resp.json()["items"]
        canonical_id = items[0]["canonical_id"]
        assert canonical_id is not None

        inv_resp = client.get(f"/findings/{canonical_id}/investigation")
        assert inv_resp.status_code == 200
        assert inv_resp.json()["finding"]["canonical_id"] == canonical_id

    def test_investigation_endpoint_returns_404_for_unknown(self, client):
        inv_resp = client.get("/findings/nonexistent-999-uuid/investigation")
        assert inv_resp.status_code == 404

    def test_investigation_with_enrich_with_ai(self, client):
        findings_resp = client.get("/findings")
        finding_id = findings_resp.json()["items"][0]["finding_id"]

        inv_resp = client.get(f"/findings/{finding_id}/investigation?enrich_with_ai=true")
        assert inv_resp.status_code == 200
        data = inv_resp.json()
        assert data["ai_analysis"] is not None
        assert data["ai_analysis"]["ai_source"] in ("template", "claude")

    def test_investigation_finding_matches_direct_finding(self, client):
        findings_resp = client.get("/findings")
        direct_finding = findings_resp.json()["items"][0]
        finding_id = direct_finding["finding_id"]

        inv_resp = client.get(f"/findings/{finding_id}/investigation")
        inv_finding = inv_resp.json()["finding"]

        assert inv_finding["finding_id"] == direct_finding["finding_id"]
        assert inv_finding["rule_id"] == direct_finding["rule_id"]
        assert inv_finding["resource_id"] == direct_finding["resource_id"]
        assert inv_finding["severity"] == direct_finding["severity"]
