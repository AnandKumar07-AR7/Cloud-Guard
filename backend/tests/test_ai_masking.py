"""
Phase 2 Tests — AI Data Masking

Verifies that secrets and credentials are masked before AI prompt construction.
"""
import pytest
from core.ai.masking import (
    mask_env_vars,
    mask_config,
    mask_finding_evidence_for_ai,
    _is_sensitive_key,
)


class TestMaskEnvVars:
    def test_masks_password_value(self):
        result = mask_env_vars({"DATABASE_PASSWORD": "super_secret_123"})
        assert result["DATABASE_PASSWORD"] == "[REDACTED]"

    def test_masks_api_key_value(self):
        result = mask_env_vars({"API_KEY": "sk-abc123"})
        assert result["API_KEY"] == "[REDACTED]"

    def test_masks_secret_key(self):
        result = mask_env_vars({"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI"})
        assert result["AWS_SECRET_ACCESS_KEY"] == "[REDACTED]"

    def test_masks_token(self):
        result = mask_env_vars({"AUTH_TOKEN": "eyJhbGciOiJIUzI1NiJ9"})
        assert result["AUTH_TOKEN"] == "[REDACTED]"

    def test_preserves_safe_value(self):
        result = mask_env_vars({"LOG_LEVEL": "INFO"})
        assert result["LOG_LEVEL"] == "INFO"

    def test_preserves_environment_value(self):
        result = mask_env_vars({"ENVIRONMENT": "production"})
        assert result["ENVIRONMENT"] == "production"

    def test_does_not_mutate_original(self):
        original = {"DATABASE_PASSWORD": "secret"}
        mask_env_vars(original)
        assert original["DATABASE_PASSWORD"] == "secret"

    def test_empty_dict(self):
        assert mask_env_vars({}) == {}

    def test_masks_aws_access_key_inline(self):
        result = mask_env_vars({"SOME_VAR": "key is AKIAIOSFODNN7EXAMPLE here"})
        assert "AKIAIOSFODNN7EXAMPLE" not in result["SOME_VAR"]
        assert "[AWS_KEY_REDACTED]" in result["SOME_VAR"]


class TestMaskConfig:
    def test_masks_nested_env_vars(self):
        config = {
            "environment_variables": {
                "DATABASE_PASSWORD": "secret123",
                "LOG_LEVEL": "DEBUG",
            }
        }
        result = mask_config(config)
        assert result["environment_variables"]["DATABASE_PASSWORD"] == "[REDACTED]"
        assert result["environment_variables"]["LOG_LEVEL"] == "DEBUG"

    def test_does_not_mutate_original(self):
        config = {"environment_variables": {"DATABASE_PASSWORD": "secret"}}
        mask_config(config)
        assert config["environment_variables"]["DATABASE_PASSWORD"] == "secret"

    def test_masks_deeply_nested_keys(self):
        config = {"level1": {"level2": {"api_key": "hidden"}}}
        result = mask_config(config)
        assert result["level1"]["level2"]["api_key"] == "[REDACTED]"


class TestSensitiveKeyDetection:
    def test_password_is_sensitive(self):
        assert _is_sensitive_key("DATABASE_PASSWORD") is True
        assert _is_sensitive_key("password") is True

    def test_api_key_is_sensitive(self):
        assert _is_sensitive_key("API_KEY") is True
        assert _is_sensitive_key("STRIPE_API_KEY") is True

    def test_secret_is_sensitive(self):
        assert _is_sensitive_key("AWS_SECRET_ACCESS_KEY") is True

    def test_token_is_sensitive(self):
        assert _is_sensitive_key("AUTH_TOKEN") is True

    def test_log_level_is_safe(self):
        assert _is_sensitive_key("LOG_LEVEL") is False

    def test_environment_is_safe(self):
        assert _is_sensitive_key("ENVIRONMENT") is False

    def test_region_is_safe(self):
        assert _is_sensitive_key("AWS_REGION") is False


class TestMaskFindingEvidence:
    def test_truncates_long_values(self):
        long_val = "x" * 400
        result = mask_finding_evidence_for_ai(long_val)
        assert len(result) <= 320  # 300 chars + truncation marker

    def test_redacts_aws_key_in_evidence(self):
        evidence = "observed key: AKIAIOSFODNN7EXAMPLE123456"
        result = mask_finding_evidence_for_ai(evidence)
        assert "AKIAIOSFODNN7EXAMPLE123456" not in result
        assert "[AWS_KEY_REDACTED]" in result

    def test_preserves_safe_evidence(self):
        evidence = "public_access_block is empty"
        result = mask_finding_evidence_for_ai(evidence)
        assert "public_access_block is empty" in result


class TestAIServiceUsesTemplateWithoutKey:
    def test_no_api_key_uses_template(self):
        from core.ai.service import AIService
        from core.providers.demo.fixtures.s3_fixtures import _public_data_lake
        from core.security.rules.s3_rules import S3PublicAccessBlockMissing

        service = AIService(api_key=None)
        assert not service.is_ai_enabled

        resource = _public_data_lake()
        rule = S3PublicAccessBlockMissing()
        finding = rule.detect(resource)
        assert finding is not None

        explanation = service.explain_finding(finding)
        assert "developer_explanation" in explanation
        assert "manager_summary" in explanation
        assert "remediation_steps" in explanation
        assert explanation["ai_source"] == "template"

    def test_template_explanation_never_empty(self):
        from core.ai.service import AIService
        from core.providers.demo.fixtures.iam_fixtures import _admin_role
        from core.security.rules.iam_rules import IAMWildcardAction

        service = AIService(api_key=None)
        finding = IAMWildcardAction().detect(_admin_role())
        assert finding is not None

        explanation = service.explain_finding(finding)
        for key in ("developer_explanation", "manager_summary", "remediation_steps"):
            assert explanation[key], f"Key '{key}' is empty"
