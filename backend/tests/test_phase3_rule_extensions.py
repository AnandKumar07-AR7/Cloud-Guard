"""
CloudGuard — Phase 3 IAM and SG Rule Extension Tests

Tests for:
  IAM-006  Cross-Account Trust
  IAM-007  No Permissions Boundary
  IAM-008  PassRole on Wildcard Resource
  SG-007   MongoDB Open to Internet
  SG-008   Telnet Open to Internet
  S3-008   Server-Access Logging Not Enabled
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.rules.iam_rules import (
    IAMCrossAccountTrust,
    IAMNoPermissionsBoundary,
    IAMPassRolePermission,
    IAM_RULES,
)
from core.security.rules.sg_rules import (
    SGMongoDBOpenToInternet,
    SGTelnetOpenToInternet,
    SG_RULES,
)
from core.security.rules.s3_rules import S3LoggingDisabled, S3_RULES

_ACCOUNT = "123456789012"
_OTHER_ACCOUNT = "999999999999"
_REGION = "us-east-1"


def _iam_role(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.IAM_ROLE,
        provider="demo",
        service="iam",
        account_id=_ACCOUNT,
        region="global",
        name=resource_id,
        config=config,
    )


def _sg(resource_id: str, inbound_rules: list) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.SECURITY_GROUP,
        provider="demo",
        service="ec2",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config={"inbound_rules": inbound_rules},
    )


def _s3(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.S3_BUCKET,
        provider="demo",
        service="s3",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config=config,
    )


# ──────────────────────────────────────────────────────────────────────────────
# IAM-006 — Cross-Account Trust
# ──────────────────────────────────────────────────────────────────────────────

class TestIAMCrossAccountTrust:
    rule = IAMCrossAccountTrust()

    def test_fires_on_external_account_in_trust(self):
        r = _iam_role("role-xacct-001", {
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }]
            },
            "inline_policies": [],
            "managed_policies": [],
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "IAM-006"

    def test_no_finding_for_same_account(self):
        r = _iam_role("role-xacct-002", {
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }]
            },
        })
        assert self.rule.detect(r) is None

    def test_no_finding_for_service_principal(self):
        r = _iam_role("role-xacct-003", {
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }]
            },
        })
        assert self.rule.detect(r) is None

    def test_no_finding_for_empty_trust_policy(self):
        r = _iam_role("role-xacct-004", {"trust_policy": {}})
        assert self.rule.detect(r) is None

    def test_evidence_lists_external_principals(self):
        r = _iam_role("role-xacct-005", {
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }]
            },
        })
        f = self.rule.detect(r)
        assert isinstance(f.evidence.observed_value, list)
        assert any(_OTHER_ACCOUNT in str(v) for v in f.evidence.observed_value)

    def test_severity_is_medium(self):
        r = _iam_role("role-xacct-006", {
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }]
            },
        })
        assert self.rule.detect(r).severity.value == "medium"


# ──────────────────────────────────────────────────────────────────────────────
# IAM-007 — No Permissions Boundary
# ──────────────────────────────────────────────────────────────────────────────

class TestIAMNoPermissionsBoundary:
    rule = IAMNoPermissionsBoundary()

    def test_fires_when_policies_but_no_boundary(self):
        r = _iam_role("role-bound-001", {
            "inline_policies": [{"name": "SomePolicy", "document": {}}],
            "managed_policies": [],
            "permissions_boundary": None,
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "IAM-007"

    def test_no_finding_when_boundary_set(self):
        r = _iam_role("role-bound-002", {
            "inline_policies": [{"name": "SomePolicy", "document": {}}],
            "managed_policies": [],
            "permissions_boundary": "arn:aws:iam::123456789012:policy/Boundary",
        })
        assert self.rule.detect(r) is None

    def test_no_finding_when_no_policies_at_all(self):
        """No policies = nothing to bound — skip."""
        r = _iam_role("role-bound-003", {
            "inline_policies": [],
            "managed_policies": [],
            "permissions_boundary": None,
        })
        assert self.rule.detect(r) is None

    def test_evidence_shows_policy_counts(self):
        r = _iam_role("role-bound-004", {
            "inline_policies": [{"name": "P1"}, {"name": "P2"}],
            "managed_policies": [{"name": "M1"}],
            "permissions_boundary": None,
        })
        f = self.rule.detect(r)
        assert f.evidence.details["inline_policy_count"] == 2
        assert f.evidence.details["managed_policy_count"] == 1

    def test_severity_is_medium(self):
        r = _iam_role("role-bound-005", {
            "inline_policies": [{"name": "P"}],
            "managed_policies": [],
            "permissions_boundary": None,
        })
        assert self.rule.detect(r).severity.value == "medium"


# ──────────────────────────────────────────────────────────────────────────────
# IAM-008 — PassRole on Wildcard
# ──────────────────────────────────────────────────────────────────────────────

class TestIAMPassRolePermission:
    rule = IAMPassRolePermission()

    def test_fires_when_passrole_on_wildcard_resource(self):
        r = _iam_role("role-pr-001", {
            "inline_policies": [{
                "name": "PassPolicy",
                "document": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "*",
                    }]
                },
            }],
            "managed_policies": [],
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "IAM-008"

    def test_no_finding_when_passrole_scoped_to_specific_role(self):
        r = _iam_role("role-pr-002", {
            "inline_policies": [{
                "name": "ScopedPass",
                "document": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": f"arn:aws:iam::{_ACCOUNT}:role/specific-role",
                    }]
                },
            }],
            "managed_policies": [],
        })
        assert self.rule.detect(r) is None

    def test_fires_when_star_action_covers_passrole(self):
        r = _iam_role("role-pr-003", {
            "inline_policies": [{
                "name": "StarPolicy",
                "document": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }]
                },
            }],
            "managed_policies": [],
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "IAM-008"

    def test_no_finding_when_deny_effect(self):
        r = _iam_role("role-pr-004", {
            "inline_policies": [{
                "name": "DenyPass",
                "document": {
                    "Statement": [{
                        "Effect": "Deny",
                        "Action": "iam:PassRole",
                        "Resource": "*",
                    }]
                },
            }],
            "managed_policies": [],
        })
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _iam_role("role-pr-005", {
            "inline_policies": [{
                "name": "P",
                "document": {
                    "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]
                },
            }],
            "managed_policies": [],
        })
        assert self.rule.detect(r).severity.value == "high"


# ──────────────────────────────────────────────────────────────────────────────
# IAM_RULES registry
# ──────────────────────────────────────────────────────────────────────────────

class TestIAMRulesRegistryExpanded:
    def test_registry_has_8_rules(self):
        assert len(IAM_RULES) == 8

    def test_all_have_unique_ids(self):
        ids = [r.rule_id for r in IAM_RULES]
        assert len(ids) == len(set(ids))

    def test_new_rules_in_registry(self):
        ids = {r.rule_id for r in IAM_RULES}
        assert "IAM-006" in ids
        assert "IAM-007" in ids
        assert "IAM-008" in ids


# ──────────────────────────────────────────────────────────────────────────────
# SG-007 — MongoDB
# ──────────────────────────────────────────────────────────────────────────────

class TestSGMongoDBOpenToInternet:
    rule = SGMongoDBOpenToInternet()

    def test_fires_when_mongodb_open(self):
        r = _sg("sg-mongo-001", [
            {"protocol": "tcp", "from_port": 27017, "to_port": 27017, "cidr": "0.0.0.0/0"}
        ])
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "SG-007"

    def test_no_finding_when_mongodb_restricted(self):
        r = _sg("sg-mongo-002", [
            {"protocol": "tcp", "from_port": 27017, "to_port": 27017, "cidr": "10.0.0.0/8"}
        ])
        assert self.rule.detect(r) is None

    def test_severity_is_critical(self):
        r = _sg("sg-mongo-003", [
            {"protocol": "tcp", "from_port": 27017, "to_port": 27017, "cidr": "0.0.0.0/0"}
        ])
        assert self.rule.detect(r).severity.value == "critical"


# ──────────────────────────────────────────────────────────────────────────────
# SG-008 — Telnet
# ──────────────────────────────────────────────────────────────────────────────

class TestSGTelnetOpenToInternet:
    rule = SGTelnetOpenToInternet()

    def test_fires_when_telnet_open(self):
        r = _sg("sg-telnet-001", [
            {"protocol": "tcp", "from_port": 23, "to_port": 23, "cidr": "0.0.0.0/0"}
        ])
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "SG-008"

    def test_no_finding_when_telnet_restricted(self):
        r = _sg("sg-telnet-002", [
            {"protocol": "tcp", "from_port": 23, "to_port": 23, "cidr": "192.168.1.0/24"}
        ])
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _sg("sg-telnet-003", [
            {"protocol": "tcp", "from_port": 23, "to_port": 23, "cidr": "0.0.0.0/0"}
        ])
        assert self.rule.detect(r).severity.value == "high"


class TestSGRulesRegistryExpanded:
    def test_registry_has_8_rules(self):
        assert len(SG_RULES) == 8

    def test_sg007_and_sg008_in_registry(self):
        ids = {r.rule_id for r in SG_RULES}
        assert "SG-007" in ids
        assert "SG-008" in ids


# ──────────────────────────────────────────────────────────────────────────────
# S3-008 — Server-Access Logging
# ──────────────────────────────────────────────────────────────────────────────

class TestS3LoggingDisabled:
    rule = S3LoggingDisabled()

    def test_fires_when_logging_missing(self):
        r = _s3("bucket-log-001", {
            "public_access_block": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                     "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
        })
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "S3-008"

    def test_fires_when_logging_is_none(self):
        r = _s3("bucket-log-002", {"logging": None})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_logging_configured(self):
        r = _s3("bucket-log-003", {
            "logging": {"target_bucket": "my-logs", "target_prefix": "bucket/"}
        })
        assert self.rule.detect(r) is None

    def test_no_finding_when_logging_is_true(self):
        r = _s3("bucket-log-004", {"logging": True})
        assert self.rule.detect(r) is None

    def test_severity_is_low(self):
        r = _s3("bucket-log-005", {})
        assert self.rule.detect(r).severity.value == "low"

    def test_category_is_logging(self):
        assert self.rule.metadata.category == "logging"

    def test_s3_rules_has_8_rules(self):
        assert len(S3_RULES) == 8

    def test_s3_008_in_registry(self):
        ids = {r.rule_id for r in S3_RULES}
        assert "S3-008" in ids
