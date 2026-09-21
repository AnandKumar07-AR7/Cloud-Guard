"""
Tests for IAM security rules.
"""
import pytest
from core.providers.demo.fixtures.iam_fixtures import (
    _admin_role, _lambda_execution_role, _readonly_role, _dev_role
)
from core.security.models import Severity
from core.security.rules.iam_rules import (
    IAMWildcardAction, IAMWildcardResource, IAMAdministratorAccess,
    IAMWritePermissions, IAMTrustPolicyAllPrincipals,
)


class TestIAMWildcardAction:
    rule = IAMWildcardAction()

    def test_fires_on_wildcard_star_action(self):
        resource = _admin_role()  # has Action: "*"
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "IAM-001"
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_on_specific_actions(self):
        resource = _readonly_role()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_on_deny_statements(self):
        """Deny statements with wildcard should not trigger."""
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="arn:aws:iam::123:role/test-deny",
            resource_type=ResourceType.IAM_ROLE,
            provider="test", service="iam",
            account_id="123", region="global",
            name="test-deny",
            config={
                "inline_policies": [
                    {
                        "name": "DenyAll",
                        "document": {
                            "Statement": [
                                {"Effect": "Deny", "Action": "*", "Resource": "*"}
                            ]
                        },
                    }
                ],
                "managed_policies": [],
            },
        )
        finding = self.rule.detect(resource)
        assert finding is None


class TestIAMWildcardResource:
    rule = IAMWildcardResource()

    def test_fires_on_wildcard_resource(self):
        resource = _lambda_execution_role()  # has Resource: "*"
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "IAM-002"
        assert finding.severity == Severity.HIGH

    def test_no_fire_on_specific_resource(self):
        resource = _readonly_role()  # has specific ARNs
        finding = self.rule.detect(resource)
        assert finding is None


class TestIAMAdministratorAccess:
    rule = IAMAdministratorAccess()

    def test_fires_on_administrator_access_policy(self):
        resource = _dev_role()  # has AdministratorAccess managed policy
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "IAM-003"
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_on_readonly_policy(self):
        resource = _readonly_role()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_when_no_managed_policies(self):
        resource = _admin_role()  # only inline, no AdministratorAccess managed policy
        finding = self.rule.detect(resource)
        assert finding is None


class TestIAMWritePermissions:
    rule = IAMWritePermissions()

    def test_fires_on_iam_write_actions(self):
        resource = _lambda_execution_role()  # has iam:CreateUser, iam:AttachRolePolicy
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "IAM-004"

    def test_fires_on_wildcard_action(self):
        resource = _admin_role()  # wildcard implies all IAM actions
        finding = self.rule.detect(resource)
        assert finding is not None

    def test_no_fire_on_readonly(self):
        resource = _readonly_role()
        finding = self.rule.detect(resource)
        assert finding is None


class TestIAMTrustPolicyAllPrincipals:
    rule = IAMTrustPolicyAllPrincipals()

    def test_no_fire_on_specific_service(self):
        resource = _lambda_execution_role()  # Principal: lambda.amazonaws.com
        finding = self.rule.detect(resource)
        assert finding is None

    def test_fires_on_wildcard_principal(self):
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="arn:aws:iam::123:role/open-role",
            resource_type=ResourceType.IAM_ROLE,
            provider="test", service="iam",
            account_id="123", region="global",
            name="open-role",
            config={
                "trust_policy": {
                    "Statement": [
                        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
                    ]
                },
                "inline_policies": [],
                "managed_policies": [],
            },
        )
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
