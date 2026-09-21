"""
Tests for the Risk Engine.
"""
import pytest
from core.security.models import Finding, Severity, FindingStatus, Evidence
from core.risk.engine import (
    calculate_risk_score,
    calculate_security_posture_score,
    calculate_risk_summary,
    enrich_finding_with_risk,
    enrich_all_findings,
)


def _make_finding(severity: Severity, internet=False, priv_esc=False, data=False) -> Finding:
    return Finding(
        rule_id="TEST-001",
        resource_id="res-1",
        resource_type="s3_bucket",
        service="s3",
        account_id="123",
        region="us-east-1",
        severity=severity,
        title="Test finding",
        description="Test description",
        evidence=Evidence(
            rule_id="TEST-001",
            observed_value="test",
            expected_value="safe",
            field_path="config.test",
        ),
        internet_exposed=internet,
        privilege_escalation_risk=priv_esc,
        data_exposure_risk=data,
    )


class TestCalculateRiskScore:
    def test_critical_base_score_high(self):
        f = _make_finding(Severity.CRITICAL)
        score = calculate_risk_score(f)
        assert 90 <= score <= 100

    def test_low_base_score_low(self):
        f = _make_finding(Severity.LOW)
        score = calculate_risk_score(f)
        assert score < 30

    def test_internet_exposed_increases_score(self):
        f_no_internet = _make_finding(Severity.HIGH, internet=False)
        f_internet = _make_finding(Severity.HIGH, internet=True)
        assert calculate_risk_score(f_internet) > calculate_risk_score(f_no_internet)

    def test_multiple_factors_compound(self):
        f_none = _make_finding(Severity.MEDIUM)
        f_all = _make_finding(Severity.MEDIUM, internet=True, priv_esc=True, data=True)
        assert calculate_risk_score(f_all) > calculate_risk_score(f_none)

    def test_score_never_exceeds_100(self):
        f = _make_finding(Severity.CRITICAL, internet=True, priv_esc=True, data=True)
        score = calculate_risk_score(f)
        assert score <= 100.0

    def test_score_never_below_zero(self):
        f = _make_finding(Severity.INFORMATIONAL)
        score = calculate_risk_score(f)
        assert score >= 0.0


class TestSecurityPostureScore:
    def test_no_findings_returns_100(self):
        score = calculate_security_posture_score([])
        assert score == 100.0

    def test_critical_findings_lower_posture_significantly(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(5)]
        score = calculate_security_posture_score(findings)
        assert score < 70.0, f"5 CRITICAL findings should significantly reduce posture, got {score}"

    def test_low_findings_have_minor_impact(self):
        findings = [_make_finding(Severity.LOW) for _ in range(5)]
        score = calculate_security_posture_score(findings)
        assert score > 70.0

    def test_posture_bounded_0_to_100(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(100)]
        score = calculate_security_posture_score(findings)
        assert 0.0 <= score <= 100.0


class TestEnrichFindingWithRisk:
    def test_sets_risk_score(self):
        f = _make_finding(Severity.HIGH, internet=True)
        enriched = enrich_finding_with_risk(f)
        assert enriched.risk_score > 0
        assert enriched.risk_score <= 100.0

    def test_does_not_mutate_original(self):
        f = _make_finding(Severity.HIGH)
        assert f.risk_score == 0.0
        enriched = enrich_finding_with_risk(f)
        assert f.risk_score == 0.0
        assert enriched.risk_score > 0


class TestCalculateRiskSummary:
    def test_empty_findings(self):
        summary = calculate_risk_summary([])
        assert summary["posture_score"] == 100.0
        assert summary["open_finding_count"] == 0

    def test_summary_contains_all_keys(self):
        findings = [_make_finding(Severity.HIGH)]
        enriched = enrich_all_findings(findings)
        summary = calculate_risk_summary(enriched)
        required_keys = [
            "posture_score", "risk_level", "severity_counts",
            "top_risk_score", "average_risk_score",
            "open_finding_count", "total_finding_count",
        ]
        for key in required_keys:
            assert key in summary, f"Missing key: {key}"

    def test_risk_level_critical_when_posture_low(self):
        findings = [_make_finding(Severity.CRITICAL) for _ in range(20)]
        enriched = enrich_all_findings(findings)
        summary = calculate_risk_summary(enriched)
        assert summary["risk_level"] in ("CRITICAL", "HIGH")
