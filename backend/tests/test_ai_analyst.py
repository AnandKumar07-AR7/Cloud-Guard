"""
CloudGuard Phase 4 Tests — AI Security Analyst Foundation

Tests for:
  - SecurityAnalystContextBuilder
  - AIService.analyze_finding() with template fallback
  - Masking sensitive config before context building
  - Structured AIAnalysis schema (observed_facts vs ai_inferences)
"""
from __future__ import annotations

import pytest
from core.ai.service import AIService, SecurityAnalystContextBuilder
from core.security.models import Evidence, Finding, Severity


def _make_finding(**overrides) -> Finding:
    ev = Evidence(
        rule_id="LAM-002",
        observed_value={"DB_PASS": "secret123", "API_KEY": "sk-1234567890"},
        expected_value={},
        field_path="config.environment_variables",
        source="Lambda environment configuration",
    )
    data = {
        "rule_id": "LAM-002",
        "resource_id": "arn:aws:lambda:us-east-1:123456789012:function:my-fn",
        "resource_type": "lambda_function",
        "service": "lambda",
        "account_id": "123456789012",
        "region": "us-east-1",
        "severity": Severity.HIGH,
        "title": "Lambda Function May Expose Secrets in Environment Variables",
        "description": "Environment variables contain potential secrets.",
        "evidence": ev,
        "data_exposure_risk": True,
    }
    data.update(overrides)
    return Finding(**data)


class TestAISecurityAnalyst:
    def test_context_builder_masks_sensitive_config(self):
        builder = SecurityAnalystContextBuilder()
        finding = _make_finding()
        sensitive_config = {
            "password": "plain-text-pass",
            "api_key": "sk-live-secret",
            "safe_setting": "enabled",
        }
        ctx = builder.build(finding, resource_config=sensitive_config)
        assert "resource_config_sample" in ctx
        sample = ctx["resource_config_sample"]
        assert sample["password"] == "[MASKED]"
        assert sample["api_key"] == "[MASKED]"
        assert sample["safe_setting"] == "enabled"

    def test_context_builder_masks_evidence(self):
        builder = SecurityAnalystContextBuilder()
        finding = _make_finding()
        ctx = builder.build(finding)
        ev = ctx["evidence"]
        assert "DB_PASS" in str(ev["observed_value"])
        assert "secret123" not in str(ev["observed_value"])

    def test_template_analysis_returns_structured_ai_analysis(self):
        ai = AIService(api_key=None)
        finding = _make_finding()
        analysis = ai.analyze_finding(finding)

        assert analysis.ai_source == "template"
        assert len(analysis.executive_summary) > 0
        assert len(analysis.technical_analysis) > 0
        assert len(analysis.business_impact) > 0
        assert len(analysis.recommended_action) > 0
        assert len(analysis.observed_facts) > 0
        assert len(analysis.ai_inferences) > 0
        assert analysis.confidence in ("high", "medium", "low")

    def test_template_analysis_distinguishes_facts_from_inferences(self):
        ai = AIService(api_key=None)
        finding = _make_finding()
        analysis = ai.analyze_finding(finding)

        # Observed facts must mention the field and rule
        facts_text = " ".join(analysis.observed_facts)
        assert finding.evidence.field_path in facts_text
        assert finding.rule_id in facts_text

        # Inferences must not claim to be deterministic observations
        assert len(analysis.ai_inferences) >= 2

    def test_ai_service_does_not_mutate_finding_risk_score(self):
        ai = AIService(api_key=None)
        finding = _make_finding(risk_score=72.0)
        orig_score = finding.risk_score
        analysis = ai.analyze_finding(finding)
        assert finding.risk_score == orig_score
