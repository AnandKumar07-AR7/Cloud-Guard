"""
CloudGuard Phase 4 Tests — Investigation Service

Tests for:
  - InvestigationService.investigate()
  - Assembly of complete finding context
  - Integration with RuleCatalog
  - Resolution of related resources and related findings
  - AI analysis assembly (template)
  - Missing finding returns None
"""
from __future__ import annotations

import pytest
from core.providers.demo.provider import DemoProvider
from services.investigation_service import InvestigationService
from services.scan_service import ScanService
from services.scan_store import ScanStore


@pytest.fixture
def scan_service():
    store = ScanStore()
    return ScanService(scan_store=store)


@pytest.fixture
def executed_scan(scan_service):
    provider = DemoProvider(scenario="default")
    record = scan_service.run_scan(provider=provider, scenario="default")
    return scan_service._scan_store, record


class TestInvestigationService:
    def test_investigate_known_finding_returns_complete_context(self, executed_scan):
        store, record = executed_scan
        assert len(record.findings) > 0

        target_finding = record.findings[0]
        inv_svc = InvestigationService(scan_store=store)
        ctx = inv_svc.investigate(target_finding.finding_id)

        assert ctx is not None, f"Investigation returned None for finding_id {target_finding.finding_id}. Store findings: {[f.finding_id for f in record.findings]}"
        assert ctx.finding.finding_id == target_finding.finding_id
        assert ctx.evidence["field_path"] == target_finding.evidence.field_path
        assert ctx.risk_context is not None
        assert ctx.security_context is not None
        assert ctx.ai_analysis is not None
        assert ctx.ai_analysis.ai_source == "template"

    def test_investigate_includes_rule_metadata(self, executed_scan):
        store, record = executed_scan
        # Find S3 finding
        s3_finding = next(f for f in record.findings if f.service == "s3")
        inv_svc = InvestigationService(scan_store=store)
        ctx = inv_svc.investigate(s3_finding.finding_id)

        assert ctx.rule_metadata is not None
        assert ctx.rule_metadata["rule_id"] == s3_finding.rule_id
        assert "compliance_mappings" in ctx.rule_metadata
        assert "remediation_template" in ctx.rule_metadata

    def test_investigate_finds_related_findings(self, executed_scan):
        store, record = executed_scan
        # S3 bucket acme-public-data-lake has multiple findings (S3-001, S3-002, S3-004, etc.)
        data_lake_findings = [f for f in record.findings if "acme-public-data-lake" in f.resource_id]
        if len(data_lake_findings) > 1:
            inv_svc = InvestigationService(scan_store=store)
            ctx = inv_svc.investigate(data_lake_findings[0].finding_id)
            assert len(ctx.related_findings) >= 1
            assert all(f.finding_id != data_lake_findings[0].finding_id for f in ctx.related_findings)

    def test_investigate_resolves_related_resources(self, executed_scan):
        store, record = executed_scan
        # EC2 finding has attached security group
        ec2_findings = [f for f in record.findings if f.service == "ec2"]
        if ec2_findings:
            inv_svc = InvestigationService(scan_store=store)
            ctx = inv_svc.investigate(ec2_findings[0].finding_id)
            assert isinstance(ctx.related_resources, list)

    def test_investigate_by_canonical_id(self, executed_scan):
        store, record = executed_scan
        target_finding = record.findings[0]
        inv_svc = InvestigationService(scan_store=store)
        ctx = inv_svc.investigate(target_finding.canonical_id)

        assert ctx is not None
        assert ctx.finding.finding_id == target_finding.finding_id

    def test_investigate_unknown_finding_returns_none(self, executed_scan):
        store, record = executed_scan
        inv_svc = InvestigationService(scan_store=store)
        assert inv_svc.investigate("non-existent-finding-uuid") is None
