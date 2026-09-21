"""
CloudGuard — CloudTrail Security Rule Tests

Tests for:
  CT-001  CloudTrail Logging Disabled
  CT-002  Log File Validation Disabled
  CT-003  Not Multi-Region
  CT-004  Not KMS Encrypted
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.rules.cloudtrail_rules import (
    CloudTrailLoggingDisabled,
    CloudTrailLogValidationDisabled,
    CloudTrailNotKMSEncrypted,
    CloudTrailNotMultiRegion,
    CLOUDTRAIL_RULES,
)

_ACCOUNT = "123456789012"
_REGION = "us-east-1"


def _trail(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.CLOUDTRAIL,
        provider="demo",
        service="cloudtrail",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config=config,
    )


# ──────────────────────────────────────────────────────────────────────────────
# CT-001 — Logging Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudTrailLoggingDisabled:
    rule = CloudTrailLoggingDisabled()

    def test_fires_when_logging_is_false(self):
        r = _trail("trail-001", {"is_logging": False, "trail_name": "main-trail"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "CT-001"

    def test_no_finding_when_logging_enabled(self):
        r = _trail("trail-002", {"is_logging": True})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        """Cannot determine logging state — skip."""
        r = _trail("trail-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_critical(self):
        r = _trail("trail-004", {"is_logging": False})
        assert self.rule.detect(r).severity.value == "critical"

    def test_category_is_logging(self):
        assert self.rule.metadata.category == "logging"

    def test_evidence_shows_false(self):
        r = _trail("trail-005", {"is_logging": False, "trail_name": "my-trail"})
        f = self.rule.detect(r)
        assert f.evidence.observed_value is False

    def test_only_applies_to_cloudtrail(self):
        r_ok = _trail("trail-006", {"is_logging": False})
        r_bad = CloudResource(
            resource_id="vpc-001", resource_type=ResourceType.VPC,
            provider="demo", service="vpc", account_id=_ACCOUNT,
            region=_REGION, name="vpc-001", config={},
        )
        assert self.rule.applies_to(r_ok) is True
        assert self.rule.applies_to(r_bad) is False


# ──────────────────────────────────────────────────────────────────────────────
# CT-002 — Log File Validation Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudTrailLogValidationDisabled:
    rule = CloudTrailLogValidationDisabled()

    def test_fires_when_validation_disabled(self):
        r = _trail("trail-val-001", {
            "log_file_validation_enabled": False,
            "trail_name": "audit-trail",
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "CT-002"

    def test_no_finding_when_validation_enabled(self):
        r = _trail("trail-val-002", {"log_file_validation_enabled": True})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        r = _trail("trail-val-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _trail("trail-val-004", {"log_file_validation_enabled": False})
        assert self.rule.detect(r).severity.value == "high"

    def test_category_is_logging(self):
        assert self.rule.metadata.category == "logging"

    def test_has_compliance_mappings(self):
        assert "CIS-3.2" in self.rule.metadata.compliance_mappings


# ──────────────────────────────────────────────────────────────────────────────
# CT-003 — Not Multi-Region
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudTrailNotMultiRegion:
    rule = CloudTrailNotMultiRegion()

    def test_fires_when_single_region(self):
        r = _trail("trail-mr-001", {"is_multi_region": False})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "CT-003"

    def test_no_finding_when_multi_region(self):
        r = _trail("trail-mr-002", {"is_multi_region": True})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        r = _trail("trail-mr-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _trail("trail-mr-004", {"is_multi_region": False})
        assert self.rule.detect(r).severity.value == "medium"

    def test_category_is_logging(self):
        assert self.rule.metadata.category == "logging"


# ──────────────────────────────────────────────────────────────────────────────
# CT-004 — Not KMS Encrypted
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudTrailNotKMSEncrypted:
    rule = CloudTrailNotKMSEncrypted()

    def test_fires_when_no_kms_key(self):
        r = _trail("trail-kms-001", {
            "kms_key_id": None,
            "is_logging": True,
            "trail_name": "main-trail",
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "CT-004"

    def test_no_finding_when_kms_key_set(self):
        r = _trail("trail-kms-002", {
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
            "is_logging": True,
        })
        assert self.rule.detect(r) is None

    def test_no_finding_when_incomplete_config(self):
        """If is_logging is missing, we can't be sure — skip."""
        r = _trail("trail-kms-003", {"kms_key_id": None})
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _trail("trail-kms-004", {"kms_key_id": None, "is_logging": True})
        assert self.rule.detect(r).severity.value == "medium"

    def test_category_is_encryption(self):
        assert self.rule.metadata.category == "encryption"

    def test_has_references(self):
        assert len(self.rule.metadata.references) > 0


# ──────────────────────────────────────────────────────────────────────────────
# CLOUDTRAIL_RULES registry
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudTrailRulesRegistry:
    def test_registry_has_4_rules(self):
        assert len(CLOUDTRAIL_RULES) == 4

    def test_all_have_unique_rule_ids(self):
        ids = [r.rule_id for r in CLOUDTRAIL_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_cloudtrail_resource_type(self):
        for rule in CLOUDTRAIL_RULES:
            assert rule.metadata.resource_type == "cloudtrail"

    def test_all_rules_have_category(self):
        for rule in CLOUDTRAIL_RULES:
            assert rule.metadata.category

    def test_rules_start_with_ct_prefix(self):
        for rule in CLOUDTRAIL_RULES:
            assert rule.rule_id.startswith("CT-")

    def test_all_have_remediation_template(self):
        for rule in CLOUDTRAIL_RULES:
            assert rule.metadata.remediation_template
