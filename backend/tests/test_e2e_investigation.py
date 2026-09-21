"""
CloudGuard Phase 4 Tests — End-to-End Investigation Pipeline

Tests the complete flow:
  POST /scans
      ↓
  Discovered resources & findings
      ↓
  GET /findings
      ↓
  GET /findings/{finding_id}/investigation
      ↓
  GET /resources/{resource_id}
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client(auth_client):
    return auth_client


class TestEndToEndInvestigationPipeline:
    def test_full_investigation_flow(self, client):
        # 1. Run a scan in default scenario
        scan_resp = client.post("/scans", json={"scenario": "default"})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["scan_id"]

        # 2. Get findings for that scan
        findings_resp = client.get(f"/findings?scan_id={scan_id}")
        assert findings_resp.status_code == 200
        findings = findings_resp.json()["items"]
        assert len(findings) > 0

        # Choose an S3 finding
        s3_finding = next((f for f in findings if f["service"] == "s3"), findings[0])
        finding_id = s3_finding["finding_id"]
        resource_id = s3_finding["resource_id"]

        # 3. Investigate the finding
        inv_resp = client.get(f"/findings/{finding_id}/investigation")
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()

        assert inv_data["finding"]["finding_id"] == finding_id
        assert inv_data["finding"]["canonical_id"] is not None
        assert inv_data["rule"]["rule_id"] == s3_finding["rule_id"]
        assert inv_data["risk_context"] is not None
        assert inv_data["risk_context"]["final_score"] == s3_finding["risk_score"]

        # 4. Explore the affected resource
        res_resp = client.get(f"/resources/{resource_id}?scan_id={scan_id}")
        assert res_resp.status_code == 200
        res_data = res_resp.json()

        assert res_data["resource_id"] == resource_id
        assert res_data["finding_count"] >= 1
        # Finding must be listed in resource findings
        res_finding_ids = [f["finding_id"] for f in res_data["findings"]]
        assert finding_id in res_finding_ids

    def test_investigation_flow_with_relationships(self, client):
        # Run scan
        scan_resp = client.post("/scans", json={"scenario": "default"})
        scan_id = scan_resp.json()["scan_id"]

        # Get EC2 finding (which has attached security group)
        findings_resp = client.get(f"/findings?scan_id={scan_id}&service=ec2")
        findings = findings_resp.json()["items"]
        if findings:
            target = findings[0]
            inv_resp = client.get(f"/findings/{target['finding_id']}/investigation")
            assert inv_resp.status_code == 200
            inv_data = inv_resp.json()
            assert "related_resources" in inv_data
            assert "related_findings" in inv_data
