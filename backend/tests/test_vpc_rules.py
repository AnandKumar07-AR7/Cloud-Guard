"""
CloudGuard — VPC Security Rule Tests

Tests for:
  VPC-001  Flow Logs Disabled
  VPC-002  Default VPC In Use
  VPC-003  DNS Hostnames Disabled
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.rules.vpc_rules import (
    VPCDefaultVPCInUse,
    VPCDNSHostnamesDisabled,
    VPCFlowLogsDisabled,
    VPC_RULES,
)

_ACCOUNT = "123456789012"
_REGION = "us-east-1"


def _vpc(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.VPC,
        provider="demo",
        service="vpc",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config=config,
    )


# ──────────────────────────────────────────────────────────────────────────────
# VPC-001 — Flow Logs Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestVPCFlowLogsDisabled:
    rule = VPCFlowLogsDisabled()

    def test_fires_when_flow_logs_false(self):
        r = _vpc("vpc-001", {"flow_logs_enabled": False, "cidr_block": "10.0.0.0/16"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "VPC-001"

    def test_fires_when_flow_logs_missing(self):
        r = _vpc("vpc-002", {})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_flow_logs_enabled(self):
        r = _vpc("vpc-003", {"flow_logs_enabled": True})
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _vpc("vpc-004", {"flow_logs_enabled": False})
        assert self.rule.detect(r).severity.value == "high"

    def test_evidence_includes_cidr(self):
        r = _vpc("vpc-005", {"flow_logs_enabled": False, "cidr_block": "172.16.0.0/12"})
        f = self.rule.detect(r)
        assert f.evidence.details.get("cidr_block") == "172.16.0.0/12"

    def test_category_is_logging(self):
        assert self.rule.metadata.category == "logging"

    def test_only_applies_to_vpcs(self):
        r_ok = _vpc("vpc-006", {"flow_logs_enabled": False})
        r_bad = CloudResource(
            resource_id="i-ec2", resource_type=ResourceType.EC2_INSTANCE,
            provider="demo", service="ec2", account_id=_ACCOUNT,
            region=_REGION, name="i-ec2", config={},
        )
        assert self.rule.applies_to(r_ok) is True
        assert self.rule.applies_to(r_bad) is False


# ──────────────────────────────────────────────────────────────────────────────
# VPC-002 — Default VPC
# ──────────────────────────────────────────────────────────────────────────────

class TestVPCDefaultVPCInUse:
    rule = VPCDefaultVPCInUse()

    def test_fires_when_is_default_true(self):
        r = _vpc("vpc-default", {"is_default": True, "cidr_block": "172.31.0.0/16"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "VPC-002"

    def test_no_finding_when_not_default(self):
        r = _vpc("vpc-custom", {"is_default": False})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        r = _vpc("vpc-unknown", {})
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _vpc("vpc-def-sev", {"is_default": True})
        assert self.rule.detect(r).severity.value == "medium"

    def test_internet_exposure_risk_set(self):
        r = _vpc("vpc-def-exp", {"is_default": True})
        assert self.rule.detect(r).internet_exposed is True

    def test_category_is_network(self):
        assert self.rule.metadata.category == "network"


# ──────────────────────────────────────────────────────────────────────────────
# VPC-003 — DNS Hostnames Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestVPCDNSHostnamesDisabled:
    rule = VPCDNSHostnamesDisabled()

    def test_fires_when_dns_hostnames_false(self):
        r = _vpc("vpc-dns-001", {"enable_dns_hostnames": False, "enable_dns_support": True})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "VPC-003"

    def test_no_finding_when_dns_hostnames_enabled(self):
        r = _vpc("vpc-dns-002", {"enable_dns_hostnames": True, "enable_dns_support": True})
        assert self.rule.detect(r) is None

    def test_no_finding_when_both_keys_missing(self):
        """Without any DNS config data, skip — no evidence."""
        r = _vpc("vpc-dns-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_low(self):
        r = _vpc("vpc-dns-004", {"enable_dns_hostnames": False, "enable_dns_support": True})
        assert self.rule.detect(r).severity.value == "low"

    def test_category_is_configuration(self):
        assert self.rule.metadata.category == "configuration"

    def test_evidence_includes_dns_support(self):
        r = _vpc("vpc-dns-005", {"enable_dns_hostnames": False, "enable_dns_support": True})
        f = self.rule.detect(r)
        assert f.evidence.details.get("enable_dns_support") is True


# ──────────────────────────────────────────────────────────────────────────────
# VPC_RULES registry
# ──────────────────────────────────────────────────────────────────────────────

class TestVPCRulesRegistry:
    def test_registry_has_3_rules(self):
        assert len(VPC_RULES) == 3

    def test_all_have_unique_rule_ids(self):
        ids = [r.rule_id for r in VPC_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_vpc_resource_type(self):
        for rule in VPC_RULES:
            assert rule.metadata.resource_type == "vpc"

    def test_all_rules_have_category(self):
        for rule in VPC_RULES:
            assert rule.metadata.category

    def test_rules_start_with_vpc_prefix(self):
        for rule in VPC_RULES:
            assert rule.rule_id.startswith("VPC-")
