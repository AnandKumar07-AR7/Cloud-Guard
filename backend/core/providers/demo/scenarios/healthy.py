"""
CloudGuard — Healthy Demo Scenario

All resources are correctly configured. This scenario is designed to
demonstrate what a well-hardened AWS environment looks like and to verify
that the security rules produce no false positives on compliant resources.

Expected findings: None (or very minimal LOW findings only).
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType
from core.providers.demo.scenarios.base import DemoScenario

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"


class HealthyScenario(DemoScenario):
    """All resources correctly configured — minimal or zero findings."""

    @property
    def name(self) -> str:
        return "healthy"

    @property
    def description(self) -> str:
        return (
            "Fully hardened AWS environment with all best practices applied. "
            "Demonstrates what a secure, well-configured cloud infrastructure "
            "looks like. Produces minimal or zero security findings."
        )

    def get_resources(self) -> List[CloudResource]:
        return [
            self._secure_s3_bucket(),
            self._clean_iam_role(),
            self._restricted_sg(),
            self._secure_lambda(),
        ]

    def _secure_s3_bucket(self) -> CloudResource:
        return CloudResource(
            resource_id="acme-secure-data-store",
            resource_type=ResourceType.S3_BUCKET,
            provider=_PROVIDER, service="s3",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-secure-data-store",
            tags={"Environment": "production", "DataClass": "restricted"},
            config={
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "acl": {"grants": [], "owner": {"ID": "abc123"}},
                "encryption": {"sse_algorithm": "aws:kms", "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/healthy-key"},
                "versioning": {"status": "Enabled", "mfa_delete": "Enabled"},
                "logging": {"target_bucket": "acme-access-logs", "target_prefix": "secure-logs/"},
                "location": "us-east-1",
            },
        )


    def _clean_iam_role(self) -> CloudResource:
        return CloudResource(
            resource_id="arn:aws:iam::123456789012:role/acme-healthy-role",
            resource_type=ResourceType.IAM_ROLE,
            provider=_PROVIDER, service="iam",
            account_id=_ACCOUNT_ID, region="global",
            name="acme-healthy-role",
            config={
                "role_name": "acme-healthy-role",
                "trust_policy": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }]
                },
                "inline_policies": [{
                    "name": "LeastPrivilege",
                    "document": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                            "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/acme-healthy-fn:*",
                        }]
                    },
                }],
                "managed_policies": [
                    {"name": "AWSXRayDaemonWriteAccess", "arn": "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess", "document": {}}
                ],
            },
        )

    def _restricted_sg(self) -> CloudResource:
        return CloudResource(
            resource_id="sg-healthy-001",
            resource_type=ResourceType.SECURITY_GROUP,
            provider=_PROVIDER, service="ec2",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-healthy-sg",
            tags={"Environment": "production"},
            config={
                "group_name": "acme-healthy-sg",
                "description": "Restricted SG — only internal traffic",
                "vpc_id": "vpc-0a1b2c3d4e5f",
                "inbound_rules": [
                    {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "10.0.0.0/8"},
                ],
                "outbound_rules": [
                    {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},
                ],
            },
        )

    def _secure_lambda(self) -> CloudResource:
        return CloudResource(
            resource_id="arn:aws:lambda:us-east-1:123456789012:function:acme-healthy-fn",
            resource_type=ResourceType.LAMBDA_FUNCTION,
            provider=_PROVIDER, service="lambda",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-healthy-fn",
            tags={"Environment": "production"},
            config={
                "function_name": "acme-healthy-fn",
                "runtime": "python3.12",
                "handler": "handler.main",
                "memory_size": 256,
                "timeout": 30,
                "environment_variables": {"LOG_LEVEL": "INFO", "ENVIRONMENT": "production"},
                "execution_role_arn": "arn:aws:iam::123456789012:role/acme-healthy-role",
                "execution_role_policies": [],
                "execution_role_inline_policies": [],
                "resource_policy": None,
                "tracing_mode": "Active",
                "vpc_config": None,
            },
        )
