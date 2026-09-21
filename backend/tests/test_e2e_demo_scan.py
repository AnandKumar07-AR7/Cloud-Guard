"""
Phase 2 Tests — End-to-End Demo Mode Scan

Proves the complete pipeline works without mocking any internal layer:

    POST /scans
        ↓
    DemoProvider (default scenario)
        ↓
    CloudResource normalization
        ↓
    SecurityRuleEngine (23 rules)
        ↓
    RiskEngine (deterministic scoring)
        ↓
    AIService (template fallback — no API key needed)
        ↓
    ScanRecord (COMPLETED)
        ↓
    GET /scans/{scan_id}
        ↓
    GET /findings?scan_id={scan_id}
        ↓
    GET /findings/{finding_id}

This test does NOT mock the rule engine, risk engine, or finding generation.
It is the authoritative proof that Phase 2 works end-to-end.
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=True)

@pytest.fixture(autouse=True, scope="module")
def setup_client_auth(setup_auth_db):
    from tests.conftest import _get_auth_headers
    client.headers.update(_get_auth_headers("test_admin", "AdminTestPass12!"))


class TestEndToEndDemoScan:
    """
    Complete end-to-end scan flow test.
    One scan → verify at every layer.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def scan_result(cls):
        """Run a single demo scan and cache the result for the whole class."""
        response = client.post("/scans", json={"scenario": "default"})
        assert response.status_code == 201, f"Scan failed: {response.text}"
        return response.json()

    # ── Scan creation and basic structure ──────────────────────────────────────

    def test_scan_status_completed(self, scan_result):
        assert scan_result["status"] == "COMPLETED"

    def test_scan_has_unique_id(self, scan_result):
        assert scan_result["scan_id"]
        assert len(scan_result["scan_id"]) > 8

    def test_scan_has_correlation_id(self, scan_result):
        assert scan_result["correlation_id"]

    def test_scan_provider_is_demo(self, scan_result):
        assert scan_result["provider"] == "demo"

    def test_scan_mode_is_demo(self, scan_result):
        assert scan_result["mode"] == "demo"

    def test_scan_has_resources(self, scan_result):
        assert scan_result["resource_count"] >= 10, (
            f"Default scenario should have 10+ resources, got {scan_result['resource_count']}"
        )

    def test_scan_has_findings(self, scan_result):
        assert scan_result["finding_count"] > 0

    def test_scan_has_critical_findings(self, scan_result):
        assert scan_result["severity_summary"]["critical"] > 0, (
            "Default scenario must have CRITICAL findings"
        )

    def test_scan_has_risk_summary(self, scan_result):
        rs = scan_result["risk_summary"]
        assert rs is not None
        assert 0.0 <= rs["posture_score"] <= 100.0
        assert rs["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")

    def test_scan_posture_below_100(self, scan_result):
        # Default scenario has vulnerabilities → posture < 100
        assert scan_result["risk_summary"]["posture_score"] < 100.0

    def test_scan_has_duration(self, scan_result):
        assert scan_result["duration_seconds"] is not None
        assert scan_result["duration_seconds"] >= 0.0

    def test_scan_has_timestamps(self, scan_result):
        assert scan_result["started_at"]
        assert scan_result["completed_at"]

    # ── GET /scans/{scan_id} ───────────────────────────────────────────────────

    def test_get_scan_by_id_returns_same_data(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/scans/{scan_id}")
        assert r.status_code == 200
        retrieved = r.json()
        assert retrieved["scan_id"] == scan_id
        assert retrieved["status"] == "COMPLETED"
        assert retrieved["finding_count"] == scan_result["finding_count"]
        assert retrieved["resource_count"] == scan_result["resource_count"]

    def test_get_scan_severity_summary_matches(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/scans/{scan_id}")
        retrieved = r.json()
        assert retrieved["severity_summary"] == scan_result["severity_summary"]

    # ── GET /findings?scan_id={id} ─────────────────────────────────────────────

    def test_get_findings_by_scan_id(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == scan_result["finding_count"]

    def test_findings_sorted_by_risk_score_descending(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        items = r.json()["items"]
        scores = [f["risk_score"] for f in items]
        assert scores == sorted(scores, reverse=True), (
            "Findings must be sorted by risk_score descending"
        )

    def test_all_findings_have_required_structure(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        required = [
            "finding_id", "rule_id", "resource_id", "resource_type",
            "service", "account_id", "region", "severity", "risk_score",
            "status", "title", "description", "evidence",
            "internet_exposed", "privilege_escalation_risk", "data_exposure_risk",
            "detected_at", "updated_at",
        ]
        for item in r.json()["items"]:
            for field in required:
                assert field in item, f"Finding missing field: {field}"

    def test_finding_severity_is_canonical(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        valid = {"critical", "high", "medium", "low", "informational"}
        for item in r.json()["items"]:
            assert item["severity"] in valid, (
                f"Non-canonical severity: {item['severity']}"
            )

    def test_finding_status_is_open(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        for item in r.json()["items"]:
            assert item["status"] == "OPEN"

    def test_finding_risk_scores_nonzero(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        for item in r.json()["items"]:
            assert item["risk_score"] > 0.0, (
                f"Finding {item['rule_id']} has zero risk_score"
            )

    def test_finding_evidence_is_structured(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=1")
        item = r.json()["items"][0]
        ev = item["evidence"]
        assert "rule_id" in ev
        assert "field_path" in ev
        assert "observed_value" in ev
        assert "expected_value" in ev
        assert "summary" in ev

    def test_findings_cover_multiple_services(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&limit=100")
        services = {f["service"] for f in r.json()["items"]}
        assert len(services) >= 2, (
            f"Expected findings across 2+ services, got: {services}"
        )

    # ── GET /findings/{finding_id} ─────────────────────────────────────────────

    def test_get_finding_by_id(self, scan_result):
        scan_id = scan_result["scan_id"]
        findings_r = client.get(f"/findings?scan_id={scan_id}&limit=1")
        finding_id = findings_r.json()["items"][0]["finding_id"]

        r = client.get(f"/findings/{finding_id}")
        assert r.status_code == 200
        assert r.json()["finding_id"] == finding_id

    def test_finding_by_id_has_scan_id(self, scan_result):
        scan_id = scan_result["scan_id"]
        findings_r = client.get(f"/findings?scan_id={scan_id}&limit=1")
        finding_id = findings_r.json()["items"][0]["finding_id"]

        r = client.get(f"/findings/{finding_id}")
        assert r.json()["scan_id"] == scan_id

    # ── Severity filter E2E ────────────────────────────────────────────────────

    def test_severity_filter_returns_only_requested_severity(self, scan_result):
        scan_id = scan_result["scan_id"]
        if scan_result["severity_summary"]["critical"] > 0:
            r = client.get(f"/findings?scan_id={scan_id}&severity=critical")
            assert r.status_code == 200
            for f in r.json()["items"]:
                assert f["severity"] == "critical"

    def test_service_filter_returns_only_s3(self, scan_result):
        scan_id = scan_result["scan_id"]
        r = client.get(f"/findings?scan_id={scan_id}&service=s3")
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["service"] == "s3"

    # ── Determinism ────────────────────────────────────────────────────────────

    def test_two_scans_same_finding_count(self, scan_result):
        """Two default scans must produce the same number of findings."""
        r2 = client.post("/scans", json={"scenario": "default"})
        assert r2.status_code == 201
        assert r2.json()["finding_count"] == scan_result["finding_count"]

    def test_two_scans_same_rule_ids(self, scan_result):
        """Two default scans must trigger identical rule IDs."""
        scan_id_1 = scan_result["scan_id"]
        r2 = client.post("/scans", json={"scenario": "default"})
        scan_id_2 = r2.json()["scan_id"]

        f1 = client.get(f"/findings?scan_id={scan_id_1}&limit=100").json()["items"]
        f2 = client.get(f"/findings?scan_id={scan_id_2}&limit=100").json()["items"]

        rules1 = sorted(f["rule_id"] for f in f1)
        rules2 = sorted(f["rule_id"] for f in f2)
        assert rules1 == rules2, (
            f"Rule IDs not deterministic:\n  Scan1: {rules1}\n  Scan2: {rules2}"
        )


class TestEndToEndScanListPagination:
    """Verify scan listing and pagination across multiple scans."""

    def test_multiple_scans_appear_in_list(self):
        # Run 3 scans
        ids = []
        for scenario in ["default", "healthy", "critical"]:
            r = client.post("/scans", json={"scenario": scenario})
            assert r.status_code == 201
            ids.append(r.json()["scan_id"])

        r = client.get("/scans?limit=50")
        listed_ids = {s["scan_id"] for s in r.json()["items"]}
        for sid in ids:
            assert sid in listed_ids

    def test_scan_list_total_increases(self):
        before = client.get("/scans").json()["total"]
        client.post("/scans", json={})
        after = client.get("/scans").json()["total"]
        assert after == before + 1
