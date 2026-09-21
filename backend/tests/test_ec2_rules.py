"""
CloudGuard — EC2 Security Rule Tests

Tests for:
  EC2-001  IMDSv1 Enabled
  EC2-002  Public IP Exposed
  EC2-003  Monitoring Disabled
  EC2-004  No IAM Instance Profile
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.rules.ec2_rules import (
    EC2IMDSv1Enabled,
    EC2MonitoringDisabled,
    EC2NoInstanceProfile,
    EC2PublicIPExposed,
    EC2_RULES,
)

_ACCOUNT = "123456789012"
_REGION = "us-east-1"


def _ec2(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.EC2_INSTANCE,
        provider="demo",
        service="ec2",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config=config,
    )


# ──────────────────────────────────────────────────────────────────────────────
# EC2-001 — IMDSv1 Enabled
# ──────────────────────────────────────────────────────────────────────────────

class TestEC2IMDSv1Enabled:
    rule = EC2IMDSv1Enabled()

    def test_fires_when_imdsv2_false(self):
        r = _ec2("i-test-001", {"imdsv2_required": False})
        finding = self.rule.detect(r)
        assert finding is not None
        assert finding.rule_id == "EC2-001"

    def test_fires_when_imdsv2_missing(self):
        """Default EC2 allows IMDSv1 — should fire even with missing key."""
        r = _ec2("i-test-002", {})
        finding = self.rule.detect(r)
        assert finding is not None
        assert finding.rule_id == "EC2-001"

    def test_no_finding_when_imdsv2_required(self):
        r = _ec2("i-test-003", {"imdsv2_required": True})
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _ec2("i-test-004", {"imdsv2_required": False})
        f = self.rule.detect(r)
        assert f.severity.value == "high"

    def test_evidence_has_field_path(self):
        r = _ec2("i-test-005", {"imdsv2_required": False})
        f = self.rule.detect(r)
        assert "imdsv2_required" in f.evidence.field_path

    def test_privilege_escalation_risk_set(self):
        r = _ec2("i-test-006", {"imdsv2_required": False})
        f = self.rule.detect(r)
        assert f.privilege_escalation_risk is True

    def test_category_is_access_control(self):
        assert self.rule.metadata.category == "access-control"

    def test_only_applies_to_ec2_instances(self):
        from core.providers.base import ResourceType
        r = _ec2("i-test-007", {"imdsv2_required": False})
        r2 = CloudResource(
            resource_id="bucket", resource_type=ResourceType.S3_BUCKET,
            provider="demo", service="s3", account_id=_ACCOUNT,
            region=_REGION, name="bucket", config={},
        )
        assert self.rule.applies_to(r) is True
        assert self.rule.applies_to(r2) is False


# ──────────────────────────────────────────────────────────────────────────────
# EC2-002 — Public IP
# ──────────────────────────────────────────────────────────────────────────────

class TestEC2PublicIPExposed:
    rule = EC2PublicIPExposed()

    def test_fires_when_public_ip_present(self):
        r = _ec2("i-pub-001", {"public_ip": "54.1.2.3"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "EC2-002"
        assert "54.1.2.3" in str(f.evidence.observed_value)

    def test_no_finding_when_no_public_ip(self):
        r = _ec2("i-pub-002", {"public_ip": None})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        r = _ec2("i-pub-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _ec2("i-pub-004", {"public_ip": "1.2.3.4"})
        assert self.rule.detect(r).severity.value == "medium"

    def test_internet_exposure_risk_set(self):
        r = _ec2("i-pub-005", {"public_ip": "1.2.3.4"})
        assert self.rule.detect(r).internet_exposed is True

    def test_category_is_network(self):
        assert self.rule.metadata.category == "network"


# ──────────────────────────────────────────────────────────────────────────────
# EC2-003 — Monitoring Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestEC2MonitoringDisabled:
    rule = EC2MonitoringDisabled()

    def test_fires_when_monitoring_false(self):
        r = _ec2("i-mon-001", {"monitoring_enabled": False})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "EC2-003"

    def test_fires_when_monitoring_missing(self):
        r = _ec2("i-mon-002", {})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_monitoring_enabled(self):
        r = _ec2("i-mon-003", {"monitoring_enabled": True})
        assert self.rule.detect(r) is None

    def test_severity_is_low(self):
        r = _ec2("i-mon-004", {"monitoring_enabled": False})
        assert self.rule.detect(r).severity.value == "low"

    def test_category_is_monitoring(self):
        assert self.rule.metadata.category == "monitoring"


# ──────────────────────────────────────────────────────────────────────────────
# EC2-004 — No Instance Profile
# ──────────────────────────────────────────────────────────────────────────────

class TestEC2NoInstanceProfile:
    rule = EC2NoInstanceProfile()

    def test_fires_when_no_profile(self):
        r = _ec2("i-prof-001", {"iam_instance_profile": None})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "EC2-004"

    def test_fires_when_profile_key_missing(self):
        r = _ec2("i-prof-002", {})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_profile_present(self):
        r = _ec2("i-prof-003", {
            "iam_instance_profile": "arn:aws:iam::123456789012:instance-profile/my-profile"
        })
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _ec2("i-prof-004", {"iam_instance_profile": None})
        assert self.rule.detect(r).severity.value == "medium"

    def test_category_is_access_control(self):
        assert self.rule.metadata.category == "access-control"


# ──────────────────────────────────────────────────────────────────────────────
# EC2_RULES registry
# ──────────────────────────────────────────────────────────────────────────────

class TestEC2RulesRegistry:
    def test_registry_has_4_rules(self):
        assert len(EC2_RULES) == 4

    def test_all_have_unique_rule_ids(self):
        ids = [r.rule_id for r in EC2_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_ec2_resource_type(self):
        for rule in EC2_RULES:
            assert rule.metadata.resource_type == "ec2_instance"

    def test_all_rules_have_valid_remediation_safety(self):
        from core.security.rules.base import RemediationSafety
        valid = {v.value for v in RemediationSafety}
        for rule in EC2_RULES:
            assert rule.metadata.remediation_safety.value in valid

    def test_all_rules_have_category(self):
        for rule in EC2_RULES:
            assert rule.metadata.category, f"{rule.rule_id} missing category"

    def test_all_rules_have_version(self):
        for rule in EC2_RULES:
            assert rule.metadata.version

    def test_rules_start_with_ec2_prefix(self):
        for rule in EC2_RULES:
            assert rule.rule_id.startswith("EC2-")
