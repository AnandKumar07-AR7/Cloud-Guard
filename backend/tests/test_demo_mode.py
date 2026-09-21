"""
End-to-end demo mode test.

This is the most important integration test — it exercises the full pipeline:
  DemoProvider.discover() → SecurityRuleEngine.scan() → Risk enrichment

Validates that:
  1. Demo mode produces a deterministic set of resources.
  2. Expected misconfigurations are detected.
  3. Risk scores are calculated and non-zero.
  4. Posture score is below 100 (environment has issues).
  5. Clean resources do NOT produce false findings.
"""
import pytest
from core.providers.demo.provider import DemoProvider
from core.security.engine import SecurityRuleEngine
from core.security.models import Severity
from core.risk.engine import enrich_all_findings, calculate_risk_summary


@pytest.fixture(scope="module")
def demo_scan_result():
    """Run a full demo scan once and share results across the test module."""
    provider = DemoProvider()
    assert provider.validate_connection() is True

    discovery = provider.discover()
    assert discovery.resource_count > 0

    engine = SecurityRuleEngine()
    scan_result = engine.scan(
        resources=discovery.resources,
        provider=provider.provider_name,
        account_id=provider.account_id,
        regions=discovery.regions,
        mode="demo",
    )

    # Enrich with risk scores
    scan_result.findings = enrich_all_findings(scan_result.findings)
    return scan_result


class TestDemoProviderDiscovery:
    def test_provider_name_is_demo(self):
        provider = DemoProvider()
        assert provider.provider_name == "demo"

    def test_connection_always_valid(self):
        provider = DemoProvider()
        assert provider.validate_connection() is True

    def test_discovers_multiple_services(self, demo_scan_result):
        services = {r.service for r in []}  # Will use discovery directly
        provider = DemoProvider()
        discovery = provider.discover()
        services = {r.service for r in discovery.resources}
        expected_services = {"s3", "iam", "ec2", "lambda"}
        assert expected_services.issubset(services), (
            f"Missing services: {expected_services - services}"
        )

    def test_no_errors_during_discovery(self):
        provider = DemoProvider()
        discovery = provider.discover()
        assert discovery.error_count == 0

    def test_discovery_is_deterministic(self):
        """Same resources every call."""
        provider = DemoProvider()
        d1 = provider.discover()
        d2 = provider.discover()
        ids1 = sorted(r.resource_id for r in d1.resources)
        ids2 = sorted(r.resource_id for r in d2.resources)
        assert ids1 == ids2


class TestDemoScanFindings:
    def test_scan_produces_findings(self, demo_scan_result):
        assert len(demo_scan_result.findings) > 0, "Demo scan should produce findings"

    def test_scan_has_critical_findings(self, demo_scan_result):
        critical = [f for f in demo_scan_result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) > 0, "Demo environment should have CRITICAL findings"

    def test_all_findings_have_rule_ids(self, demo_scan_result):
        for finding in demo_scan_result.findings:
            assert finding.rule_id, f"Finding {finding.finding_id} missing rule_id"

    def test_all_findings_have_evidence(self, demo_scan_result):
        for finding in demo_scan_result.findings:
            assert finding.evidence is not None
            assert finding.evidence.field_path

    def test_expected_s3_findings_present(self, demo_scan_result):
        """acme-public-data-lake should have S3-001 (no public access block)."""
        s3_findings = [
            f for f in demo_scan_result.findings
            if f.service == "s3" and "acme-public-data-lake" in f.resource_id
        ]
        rule_ids = {f.rule_id for f in s3_findings}
        assert "S3-001" in rule_ids, "Expected S3-001 on acme-public-data-lake"

    def test_expected_sg_finding_present(self, demo_scan_result):
        """Database SG should have SG-004 (MySQL exposed)."""
        sg_findings = [
            f for f in demo_scan_result.findings
            if f.service == "ec2" and f.rule_id == "SG-004"
        ]
        assert len(sg_findings) > 0, "Expected SG-004 for MySQL exposure"

    def test_clean_resources_no_false_positives(self, demo_scan_result):
        """acme-audit-logs bucket should have no S3 findings."""
        audit_findings = [
            f for f in demo_scan_result.findings
            if "acme-audit-logs" in f.resource_id
        ]
        assert len(audit_findings) == 0, (
            f"acme-audit-logs should be clean but has: {[f.rule_id for f in audit_findings]}"
        )


class TestDemoRiskScoring:
    def test_all_findings_have_risk_scores(self, demo_scan_result):
        for finding in demo_scan_result.findings:
            assert finding.risk_score > 0.0, f"Finding {finding.rule_id} has zero risk score"

    def test_posture_score_below_100(self, demo_scan_result):
        summary = calculate_risk_summary(demo_scan_result.findings)
        assert summary["posture_score"] < 100.0, "Posture should be degraded in demo env"

    def test_risk_summary_has_expected_structure(self, demo_scan_result):
        summary = calculate_risk_summary(demo_scan_result.findings)
        assert "posture_score" in summary
        assert "risk_level" in summary
        assert summary["open_finding_count"] > 0
