"""
Phase 2 Tests — Scan Service

Tests the ScanService orchestration pipeline without hitting AWS or Claude.
"""
import pytest
from unittest.mock import MagicMock

from core.providers.demo.provider import DemoProvider
from core.ai.service import AIService
from services.scan_models import ScanStatus, ScanScenario
from services.scan_service import ScanService
from services.scan_store import ScanStore


@pytest.fixture
def no_ai():
    """AIService with no API key — always uses template fallback."""
    return AIService(api_key=None)


@pytest.fixture
def store():
    return ScanStore()


@pytest.fixture
def service(store, no_ai):
    return ScanService(ai_service=no_ai, scan_store=store)


@pytest.fixture
def demo_provider():
    return DemoProvider(scenario="default")


class TestScanServiceDemoScan:
    def test_run_scan_returns_completed_record(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.status == ScanStatus.COMPLETED

    def test_scan_id_is_unique(self, service, demo_provider):
        r1 = service.run_scan(provider=demo_provider)
        r2 = service.run_scan(provider=demo_provider)
        assert r1.scan_id != r2.scan_id

    def test_correlation_id_present(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.correlation_id
        assert len(record.correlation_id) >= 8

    def test_resource_count_matches_fixtures(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        # Default scenario: 8 fixture loaders, 2+ resources each
        assert record.resource_count >= 10

    def test_findings_produced(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.finding_count > 0

    def test_risk_summary_populated(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.risk_summary is not None
        assert 0.0 <= record.risk_summary.posture_score <= 100.0
        assert record.risk_summary.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")

    def test_severity_counts_consistent(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        severity_counts = record.severity_counts
        total = sum(severity_counts.values())
        assert total == record.finding_count

    def test_all_findings_have_risk_scores(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        for f in record.findings:
            assert f.risk_score > 0.0, f"Finding {f.rule_id} has zero risk score"

    def test_scan_stored_in_store(self, service, demo_provider):
        """The ScanService should save each scan into its own store."""
        record = service.run_scan(provider=demo_provider)
        # Access the store that the service actually uses
        retrieved = service._scan_store.get(record.scan_id)
        assert retrieved is not None, (
            f"Scan {record.scan_id} not found in service store."
        )
        assert retrieved.scan_id == record.scan_id

    def test_duration_calculated(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.duration_seconds is not None
        assert record.duration_seconds >= 0.0

    def test_provider_and_mode_recorded(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        assert record.provider == "demo"
        assert record.mode == "demo"


class TestScanServiceScenarios:
    def test_default_scenario_has_findings(self, service):
        provider = DemoProvider(scenario="default")
        record = service.run_scan(provider=provider, scenario="default")
        assert record.finding_count > 0

    def test_healthy_scenario_minimal_findings(self, service):
        provider = DemoProvider(scenario="healthy")
        record = service.run_scan(provider=provider, scenario="healthy")
        # Healthy scenario has no/few findings
        critical = record.severity_counts.get("critical", 0)
        assert critical == 0, f"Healthy scenario should have no CRITICAL findings, got {critical}"

    def test_critical_scenario_has_critical_findings(self, service):
        provider = DemoProvider(scenario="critical")
        record = service.run_scan(provider=provider, scenario="critical")
        critical = record.severity_counts.get("critical", 0)
        assert critical > 0, "Critical scenario must have CRITICAL findings"

    def test_scenario_recorded_on_record(self, service):
        provider = DemoProvider(scenario="critical")
        record = service.run_scan(provider=provider, scenario="critical")
        assert record.scenario == "critical"


class TestScanServiceDeterminism:
    def test_same_scenario_same_resource_count(self, service):
        p1 = DemoProvider(scenario="default")
        p2 = DemoProvider(scenario="default")
        r1 = service.run_scan(provider=p1)
        r2 = service.run_scan(provider=p2)
        assert r1.resource_count == r2.resource_count

    def test_same_scenario_same_finding_count(self, service):
        p1 = DemoProvider(scenario="default")
        p2 = DemoProvider(scenario="default")
        r1 = service.run_scan(provider=p1)
        r2 = service.run_scan(provider=p2)
        assert r1.finding_count == r2.finding_count

    def test_same_scenario_same_rule_ids(self, service):
        p1 = DemoProvider(scenario="default")
        p2 = DemoProvider(scenario="default")
        r1 = service.run_scan(provider=p1)
        r2 = service.run_scan(provider=p2)
        ids1 = sorted(f.rule_id for f in r1.findings)
        ids2 = sorted(f.rule_id for f in r2.findings)
        assert ids1 == ids2


class TestScanServiceListGet:
    def test_list_scans_returns_records(self, service, demo_provider):
        service.run_scan(provider=demo_provider)
        scans = service.list_scans(limit=10)
        assert len(scans) >= 1

    def test_get_scan_by_id(self, service, demo_provider):
        record = service.run_scan(provider=demo_provider)
        retrieved = service.get_scan(record.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == record.scan_id

    def test_get_scan_missing_returns_none(self, service):
        result = service.get_scan("nonexistent-scan-id")
        assert result is None

    def test_total_count_increments(self, service, store, no_ai):
        svc = ScanService(ai_service=no_ai, scan_store=store)
        initial = svc.total_scan_count()
        svc.run_scan(provider=DemoProvider())
        assert svc.total_scan_count() == initial + 1
