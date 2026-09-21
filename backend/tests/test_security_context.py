"""
CloudGuard Phase 4 Tests — Security Context

Tests for:
  - SecurityContext domain model
  - Finding.derive_security_context()
  - Accurate mapping of risk factors and evidence to security context
  - No hallucinated or ungrounded security properties
"""
from __future__ import annotations

import pytest
from core.security.models import Evidence, Finding, SecurityContext, Severity


def _make_finding(**overrides) -> Finding:
    default_ev = Evidence(
        rule_id="SG-001",
        observed_value="0.0.0.0/0",
        expected_value="specific CIDR",
        field_path="config.inbound_rules[0].cidr",
        source="security group configuration",
    )
    data = {
        "rule_id": "SG-001",
        "resource_id": "sg-test-001",
        "resource_type": "security_group",
        "service": "ec2",
        "account_id": "123456789012",
        "region": "us-east-1",
        "severity": Severity.HIGH,
        "title": "SSH Open to Internet",
        "description": "Security Group allows SSH from 0.0.0.0/0",
        "evidence": default_ev,
        "category": "network",
        "internet_exposed": True,
        "privilege_escalation_risk": False,
        "data_exposure_risk": False,
    }
    data.update(overrides)
    return Finding(**data)


class TestSecurityContext:
    def test_default_security_context(self):
        ctx = SecurityContext()
        assert ctx.internet_exposed is False
        assert ctx.publicly_accessible is False
        assert ctx.privileged is False
        assert ctx.contains_sensitive_data is False
        assert ctx.cross_account is False
        assert ctx.identity_related is False
        assert ctx.network_exposure is False
        assert ctx.data_exposure is False

    def test_derive_from_internet_exposed_finding(self):
        f = _make_finding(internet_exposed=True, category="network")
        ctx = f.derive_security_context()
        assert ctx.internet_exposed is True
        assert ctx.publicly_accessible is True
        assert ctx.network_exposure is True
        assert ctx.privileged is False

    def test_derive_from_iam_privilege_escalation(self):
        ev = Evidence(
            rule_id="IAM-004",
            observed_value=["iam:PutRolePolicy"],
            expected_value=[],
            field_path="config.inline_policies",
            source="IAM policy document",
        )
        f = _make_finding(
            rule_id="IAM-004",
            service="iam",
            category="access-control",
            privilege_escalation_risk=True,
            internet_exposed=False,
            evidence=ev,
        )
        ctx = f.derive_security_context()
        assert ctx.privileged is True
        assert ctx.identity_related is True
        assert ctx.persistence_risk is True
        assert ctx.lateral_movement_relevance is True
        assert ctx.internet_exposed is False

    def test_derive_from_cross_account_trust(self):
        f = _make_finding(
            rule_id="IAM-006",
            service="iam",
            title="IAM Role Trust Policy Allows Cross-Account Access",
            internet_exposed=False,
        )
        ctx = f.derive_security_context()
        assert ctx.cross_account is True
        assert ctx.identity_related is True

    def test_derive_from_data_exposure_finding(self):
        f = _make_finding(
            rule_id="RDS-002",
            service="rds",
            category="encryption",
            data_exposure_risk=True,
            internet_exposed=False,
        )
        ctx = f.derive_security_context()
        assert ctx.data_exposure is True
        assert ctx.contains_sensitive_data is True
        assert ctx.privileged is False

    def test_serialization_roundtrip(self):
        ctx = SecurityContext(
            internet_exposed=True,
            privileged=True,
            data_exposure=False,
        )
        d = ctx.model_dump()
        assert d["internet_exposed"] is True
        assert d["privileged"] is True
        assert d["data_exposure"] is False
        restored = SecurityContext(**d)
        assert restored == ctx
