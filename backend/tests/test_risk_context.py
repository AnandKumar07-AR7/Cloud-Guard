"""
CloudGuard Phase 4 Tests — Risk Context and Explainability

Tests for:
  - build_risk_context()
  - Explainable breakdown matching calculate_risk_score()
  - Factor multiplier verification
  - Capping at 100.0
  - Human-readable rationale format
  - calculate_service_posture()
"""
from __future__ import annotations

import pytest
from core.risk.engine import (
    build_risk_context,
    calculate_risk_score,
    calculate_service_posture,
    enrich_finding_with_risk,
)
from core.security.models import Evidence, Finding, RiskContext, Severity


def _make_finding(
    severity: Severity = Severity.HIGH,
    internet_exposed: bool = False,
    privilege_escalation_risk: bool = False,
    data_exposure_risk: bool = False,
    service: str = "s3",
) -> Finding:
    ev = Evidence(
        rule_id="TEST-001",
        observed_value="bad",
        expected_value="good",
        field_path="config.test",
        source="test",
    )
    return Finding(
        rule_id="TEST-001",
        resource_id="res-001",
        resource_type="s3_bucket",
        service=service,
        account_id="123456789012",
        region="us-east-1",
        severity=severity,
        title="Test finding",
        description="Test description",
        evidence=ev,
        internet_exposed=internet_exposed,
        privilege_escalation_risk=privilege_escalation_risk,
        data_exposure_risk=data_exposure_risk,
    )


class TestRiskContext:
    def test_build_risk_context_matches_calculate_risk_score(self):
        test_cases = [
            (Severity.CRITICAL, True, True, True),
            (Severity.HIGH, True, False, False),
            (Severity.MEDIUM, False, True, False),
            (Severity.LOW, False, False, True),
            (Severity.INFORMATIONAL, False, False, False),
        ]
        for sev, inet, priv, data in test_cases:
            f = _make_finding(sev, inet, priv, data)
            score = calculate_risk_score(f)
            ctx = build_risk_context(f)
            assert ctx.final_score == score, f"Mismatch for {sev}: ctx={ctx.final_score} vs fn={score}"

    def test_base_scores_per_severity(self):
        f_crit = _make_finding(Severity.CRITICAL)
        f_high = _make_finding(Severity.HIGH)
        f_med = _make_finding(Severity.MEDIUM)
        f_low = _make_finding(Severity.LOW)
        f_info = _make_finding(Severity.INFORMATIONAL)

        assert build_risk_context(f_crit).base_score == 92.0
        assert build_risk_context(f_high).base_score == 72.0
        assert build_risk_context(f_med).base_score == 45.0
        assert build_risk_context(f_low).base_score == 18.0
        assert build_risk_context(f_info).base_score == 5.0

    def test_internet_exposure_multiplier_applied(self):
        f = _make_finding(Severity.MEDIUM, internet_exposed=True)
        ctx = build_risk_context(f)
        assert ctx.internet_exposure_applied is True
        assert ctx.internet_exposure_factor == 1.20
        assert ctx.final_score == round(45.0 * 1.20, 1)

    def test_privilege_escalation_multiplier_applied(self):
        f = _make_finding(Severity.MEDIUM, privilege_escalation_risk=True)
        ctx = build_risk_context(f)
        assert ctx.privilege_applied is True
        assert ctx.privilege_factor == 1.15
        assert ctx.final_score == round(45.0 * 1.15, 1)

    def test_data_exposure_multiplier_applied(self):
        f = _make_finding(Severity.MEDIUM, data_exposure_risk=True)
        ctx = build_risk_context(f)
        assert ctx.data_exposure_applied is True
        assert ctx.data_exposure_factor == 1.10
        assert ctx.final_score == round(45.0 * 1.10, 1)

    def test_score_capped_at_100(self):
        f = _make_finding(Severity.CRITICAL, internet_exposed=True, privilege_escalation_risk=True, data_exposure_risk=True)
        ctx = build_risk_context(f)
        assert ctx.final_score == 100.0
        assert "Capped at maximum score" in ctx.rationale

    def test_rationale_format(self):
        f = _make_finding(Severity.HIGH, internet_exposed=True)
        ctx = build_risk_context(f)
        assert "Base score (high): 72" in ctx.rationale
        assert "Internet exposure" in ctx.rationale
        assert "Final score:" in ctx.rationale

    def test_enrich_finding_attaches_risk_context(self):
        f = _make_finding(Severity.HIGH, internet_exposed=True)
        enriched = enrich_finding_with_risk(f)
        assert enriched.risk_score > 0
        assert enriched.risk_context is not None
        assert enriched.risk_context.final_score == enriched.risk_score

    def test_calculate_service_posture(self):
        f1 = _make_finding(Severity.CRITICAL, service="s3")
        f2 = _make_finding(Severity.HIGH, service="iam")
        f3 = _make_finding(Severity.LOW, service="s3")
        posture = calculate_service_posture([f1, f2, f3])
        assert "s3" in posture
        assert "iam" in posture
        assert posture["s3"]["critical"] == 1
        assert posture["s3"]["low"] == 1
        assert posture["s3"]["finding_count"] == 2
        assert posture["iam"]["high"] == 1
        assert posture["iam"]["finding_count"] == 1
