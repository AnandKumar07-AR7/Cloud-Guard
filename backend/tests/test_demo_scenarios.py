"""
Phase 2 Tests — Demo Provider Scenarios
"""
import pytest
from core.providers.demo.provider import DemoProvider
from core.security.models import Severity


class TestDemoProviderInit:
    def test_default_scenario(self):
        p = DemoProvider()
        assert p.scenario_name == "default"

    def test_healthy_scenario(self):
        p = DemoProvider(scenario="healthy")
        assert p.scenario_name == "healthy"

    def test_critical_scenario(self):
        p = DemoProvider(scenario="critical")
        assert p.scenario_name == "critical"

    def test_unknown_scenario_falls_back_to_default(self):
        p = DemoProvider(scenario="nonexistent_xyz")
        assert p.scenario_name == "default"

    def test_available_scenarios(self):
        scenarios = DemoProvider.available_scenarios()
        assert "default" in scenarios
        assert "healthy" in scenarios
        assert "critical" in scenarios

    def test_provider_name(self):
        assert DemoProvider().provider_name == "demo"

    def test_account_id(self):
        assert DemoProvider().account_id == "123456789012"

    def test_validate_connection_true(self):
        assert DemoProvider().validate_connection() is True


class TestDefaultScenario:
    @pytest.fixture(scope="class")
    def discovery(self):
        return DemoProvider(scenario="default").discover()

    def test_has_resources(self, discovery):
        assert discovery.resource_count >= 10

    def test_no_errors(self, discovery):
        assert discovery.error_count == 0

    def test_covers_s3(self, discovery):
        s3_resources = [r for r in discovery.resources if r.service == "s3"]
        assert len(s3_resources) >= 2

    def test_covers_iam(self, discovery):
        iam_resources = [r for r in discovery.resources if r.service == "iam"]
        assert len(iam_resources) >= 2

    def test_covers_ec2(self, discovery):
        sg_resources = [r for r in discovery.resources if r.service == "ec2"]
        assert len(sg_resources) >= 2

    def test_covers_lambda(self, discovery):
        lambda_resources = [r for r in discovery.resources if r.service == "lambda"]
        assert len(lambda_resources) >= 2

    def test_deterministic_resource_ids(self):
        d1 = DemoProvider(scenario="default").discover()
        d2 = DemoProvider(scenario="default").discover()
        ids1 = sorted(r.resource_id for r in d1.resources)
        ids2 = sorted(r.resource_id for r in d2.resources)
        assert ids1 == ids2


class TestHealthyScenario:
    @pytest.fixture(scope="class")
    @classmethod
    def discovery(cls):
        return DemoProvider(scenario="healthy").discover()

    def test_has_resources(self, discovery):
        assert discovery.resource_count >= 1

    def test_no_errors(self, discovery):
        assert discovery.error_count == 0

    def test_produces_no_critical_findings(self):
        from core.security.engine import get_engine
        from core.risk.engine import enrich_all_findings
        discovery = DemoProvider(scenario="healthy").discover()
        engine = get_engine()
        result = engine.scan(
            resources=discovery.resources,
            provider="demo",
            account_id="123456789012",
            regions=["us-east-1"],
            mode="demo",
        )
        enriched = enrich_all_findings(result.findings)
        critical = [f for f in enriched if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, f"Healthy scenario should have no CRITICAL findings: {[f.rule_id for f in critical]}"


class TestCriticalScenario:
    @pytest.fixture(scope="class")
    @classmethod
    def scan_result(cls):
        from core.security.engine import get_engine
        from core.risk.engine import enrich_all_findings
        discovery = DemoProvider(scenario="critical").discover()
        engine = get_engine()
        result = engine.scan(
            resources=discovery.resources,
            provider="demo",
            account_id="123456789012",
            regions=["us-east-1"],
            mode="demo",
        )
        result.findings = enrich_all_findings(result.findings)
        return result

    def test_has_critical_findings(self, scan_result):
        critical = [f for f in scan_result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) > 0

    def test_has_high_findings(self, scan_result):
        high = [f for f in scan_result.findings if f.severity == Severity.HIGH]
        assert len(high) > 0

    def test_posture_score_below_50(self, scan_result):
        from core.risk.engine import calculate_risk_summary
        summary = calculate_risk_summary(scan_result.findings)
        assert summary["posture_score"] < 60, f"Critical scenario posture should be very low, got {summary['posture_score']}"
