"""
Phase 2 Tests — API Endpoints (HTTP-level)

Uses FastAPI TestClient (httpx) to test actual HTTP behavior.
No AWS credentials, no Anthropic API key needed.
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False)

@pytest.fixture(autouse=True, scope="module")
def setup_client_auth(setup_auth_db):
    """Authenticate the global test client before running any tests in this module."""
    from tests.conftest import _get_auth_headers
    client.headers.update(_get_auth_headers("test_admin", "AdminTestPass12!"))


# ──────────────────────────────────────────────────────────────────────────────
# System Endpoints
# ──────────────────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_is_healthy(self):
        r = client.get("/health")
        assert r.json()["status"] == "healthy"

    def test_has_mode(self):
        r = client.get("/health")
        assert r.json()["mode"] in ("demo", "aws")

    def test_has_version(self):
        r = client.get("/health")
        assert "version" in r.json()

    def test_has_timestamp(self):
        r = client.get("/health")
        assert "timestamp" in r.json()

    def test_has_ai_enabled(self):
        r = client.get("/health")
        assert "ai_enabled" in r.json()

    def test_has_uptime(self):
        r = client.get("/health")
        assert "uptime_seconds" in r.json()
        assert r.json()["uptime_seconds"] >= 0


class TestModeEndpoint:
    def test_returns_200(self):
        r = client.get("/mode")
        assert r.status_code == 200

    def test_has_mode_field(self):
        r = client.get("/mode")
        assert r.json()["mode"] in ("demo", "aws")

    def test_is_demo_accurate(self):
        r = client.get("/mode")
        data = r.json()
        # In test environment CLOUDGUARD_MODE=demo
        assert data["is_demo"] == (data["mode"] == "demo")
        assert data["is_aws"] == (data["mode"] == "aws")

    def test_has_ai_source(self):
        r = client.get("/mode")
        assert r.json()["ai_source"] in ("claude", "template")

    def test_demo_mode_has_scenarios(self):
        r = client.get("/mode")
        data = r.json()
        if data["is_demo"]:
            assert "available_scenarios" in data
            assert "default" in data["available_scenarios"]

    def test_has_message(self):
        r = client.get("/mode")
        assert r.json()["message"]


# ──────────────────────────────────────────────────────────────────────────────
# Scan Endpoints
# ──────────────────────────────────────────────────────────────────────────────

class TestPostScans:
    def test_returns_201(self):
        r = client.post("/scans", json={})
        assert r.status_code == 201

    def test_returns_scan_id(self):
        r = client.post("/scans", json={})
        assert "scan_id" in r.json()
        assert r.json()["scan_id"]

    def test_status_completed(self):
        r = client.post("/scans", json={})
        assert r.json()["status"] == "COMPLETED"

    def test_resource_count_positive(self):
        r = client.post("/scans", json={})
        assert r.json()["resource_count"] > 0

    def test_finding_count_positive(self):
        r = client.post("/scans", json={})
        assert r.json()["finding_count"] > 0

    def test_severity_summary_present(self):
        r = client.post("/scans", json={})
        sev = r.json()["severity_summary"]
        assert "critical" in sev
        assert "high" in sev
        assert "medium" in sev
        assert "low" in sev

    def test_risk_summary_present(self):
        r = client.post("/scans", json={})
        rs = r.json()["risk_summary"]
        assert rs is not None
        assert 0 <= rs["posture_score"] <= 100

    def test_has_correlation_id(self):
        r = client.post("/scans", json={})
        assert "correlation_id" in r.json()

    def test_has_duration(self):
        r = client.post("/scans", json={})
        assert r.json()["duration_seconds"] is not None
        assert r.json()["duration_seconds"] >= 0

    def test_default_scenario(self):
        r = client.post("/scans", json={"scenario": "default"})
        assert r.status_code == 201
        assert r.json()["scenario"] == "default"

    def test_healthy_scenario(self):
        r = client.post("/scans", json={"scenario": "healthy"})
        assert r.status_code == 201
        assert r.json()["severity_summary"]["critical"] == 0

    def test_critical_scenario_has_critical_findings(self):
        r = client.post("/scans", json={"scenario": "critical"})
        assert r.status_code == 201
        assert r.json()["severity_summary"]["critical"] > 0

    def test_invalid_scenario_returns_400(self):
        r = client.post("/scans", json={"scenario": "nonexistent_xyz"})
        assert r.status_code == 400
        assert "error_code" in r.json()
        assert r.json()["error_code"] == "INVALID_SCENARIO"

    def test_no_body_still_works(self):
        r = client.post("/scans")
        assert r.status_code == 201


class TestGetScans:
    def test_returns_200(self):
        # Ensure at least one scan exists
        client.post("/scans", json={})
        r = client.get("/scans")
        assert r.status_code == 200

    def test_has_items_and_total(self):
        client.post("/scans", json={})
        r = client.get("/scans")
        data = r.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data

    def test_pagination_limit(self):
        for _ in range(3):
            client.post("/scans", json={})
        r = client.get("/scans?limit=2&offset=0")
        assert len(r.json()["items"]) <= 2

    def test_invalid_status_filter_returns_400(self):
        r = client.get("/scans?status=INVALID_STATUS_XYZ")
        assert r.status_code == 400


class TestGetScanById:
    def test_returns_scan_by_id(self):
        post = client.post("/scans", json={})
        scan_id = post.json()["scan_id"]
        r = client.get(f"/scans/{scan_id}")
        assert r.status_code == 200
        assert r.json()["scan_id"] == scan_id

    def test_missing_scan_returns_404(self):
        r = client.get("/scans/nonexistent-scan-id-99999")
        assert r.status_code == 404
        assert r.json()["error_code"] == "NOT_FOUND"

    def test_404_has_request_id(self):
        r = client.get("/scans/nonexistent-scan-id-99999")
        assert "request_id" in r.json()


# ──────────────────────────────────────────────────────────────────────────────
# Findings Endpoints
# ──────────────────────────────────────────────────────────────────────────────

class TestGetFindings:
    @pytest.fixture(autouse=True)
    def run_scan(self):
        """Ensure at least one scan with findings exists."""
        self.scan_r = client.post("/scans", json={"scenario": "default"})
        self.scan_id = self.scan_r.json()["scan_id"]

    def test_returns_200(self):
        r = client.get("/findings")
        assert r.status_code == 200

    def test_has_items_total_pagination(self):
        r = client.get("/findings")
        data = r.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data

    def test_findings_have_required_fields(self):
        r = client.get("/findings")
        for item in r.json()["items"]:
            assert "finding_id" in item
            assert "rule_id" in item
            assert "severity" in item
            assert "risk_score" in item
            assert "status" in item
            assert "title" in item
            assert "evidence" in item

    def test_severity_filter_critical(self):
        r = client.get("/findings?severity=critical")
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "critical"

    def test_severity_filter_high(self):
        r = client.get("/findings?severity=high")
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "high"

    def test_invalid_severity_returns_400(self):
        r = client.get("/findings?severity=SUPER_CRITICAL")
        assert r.status_code == 400
        assert r.json()["error_code"] == "INVALID_FILTER"

    def test_service_filter(self):
        r = client.get("/findings?service=s3")
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["service"] == "s3"

    def test_scan_id_filter(self):
        r = client.get(f"/findings?scan_id={self.scan_id}")
        assert r.status_code == 200
        assert r.json()["total"] > 0

    def test_scan_id_filter_missing_scan_returns_404(self):
        r = client.get("/findings?scan_id=nonexistent-scan-id")
        assert r.status_code == 404

    def test_pagination_works(self):
        r1 = client.get("/findings?limit=2&offset=0")
        r2 = client.get("/findings?limit=2&offset=2")
        ids1 = {f["finding_id"] for f in r1.json()["items"]}
        ids2 = {f["finding_id"] for f in r2.json()["items"]}
        assert ids1.isdisjoint(ids2)

    def test_internet_exposed_filter(self):
        r = client.get("/findings?internet_exposed=true")
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["internet_exposed"] is True

    def test_rule_id_filter(self):
        r_all = client.get("/findings")
        if r_all.json()["total"] > 0:
            rule_id = r_all.json()["items"][0]["rule_id"]
            r = client.get(f"/findings?rule_id={rule_id}")
            for f in r.json()["items"]:
                assert f["rule_id"] == rule_id

    def test_filters_applied_in_response(self):
        r = client.get("/findings?severity=high&service=s3")
        assert "filters_applied" in r.json()


class TestGetFindingById:
    def test_returns_finding(self):
        client.post("/scans", json={})
        findings_r = client.get("/findings?limit=1")
        if findings_r.json()["total"] > 0:
            fid = findings_r.json()["items"][0]["finding_id"]
            r = client.get(f"/findings/{fid}")
            assert r.status_code == 200
            assert r.json()["finding_id"] == fid

    def test_missing_finding_returns_404(self):
        r = client.get("/findings/nonexistent-finding-id-99999")
        assert r.status_code == 404
        assert r.json()["error_code"] == "NOT_FOUND"
