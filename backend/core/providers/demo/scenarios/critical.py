"""
CloudGuard — Critical Demo Scenario

Maximum-severity misconfiguration environment designed for dramatic demos.
Every resource in this scenario has at least one CRITICAL or HIGH finding.
Useful for demonstrating the full power of CloudGuard's detection capabilities.

Expected findings:
  - S3: fully public bucket, WRITE ACL grant, no encryption, no versioning
  - IAM: admin inline policy + wildcard on all resources
  - SG: SSH, RDP, MySQL, all-traffic exposed to 0.0.0.0/0
  - Lambda: public resource policy + secrets in env + deprecated runtime + admin role
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType
from core.providers.demo.scenarios.base import DemoScenario

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"


class CriticalScenario(DemoScenario):
    """High-severity misconfiguration scenario for demo purposes."""

    @property
    def name(self) -> str:
        return "critical"

    @property
    def description(self) -> str:
        return (
            "Maximum-severity misconfiguration environment. Every resource has "
            "at least one CRITICAL or HIGH security finding. Designed for "
            "demonstrating CloudGuard's detection and remediation capabilities."
        )

    def get_resources(self) -> List[CloudResource]:
        return [
            self._critical_s3_bucket(),
            self._critical_iam_role(),
            self._critical_sg(),
            self._critical_lambda(),
        ]

    def _critical_s3_bucket(self) -> CloudResource:
        return CloudResource(
            resource_id="acme-critical-exposed-bucket",
            resource_type=ResourceType.S3_BUCKET,
            provider=_PROVIDER, service="s3",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-critical-exposed-bucket",
            tags={"Environment": "production", "DataClass": "confidential"},
            config={
                "public_access_block": {},                  # S3-001: No PAB
                "acl": {
                    "grants": [
                        {
                            "grantee": {
                                "type": "Group",
                                "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "permission": "WRITE",          # S3-002/003: WRITE to AllUsers
                        }
                    ],
                    "owner": {"ID": "abc"},
                },
                "encryption": None,                         # S3-004: No encryption
                "versioning": {"status": "Disabled", "mfa_delete": "Disabled"},  # S3-005
                "location": "us-east-1",
            },
        )

    def _critical_iam_role(self) -> CloudResource:
        return CloudResource(
            resource_id="arn:aws:iam::123456789012:role/acme-critical-role",
            resource_type=ResourceType.IAM_ROLE,
            provider=_PROVIDER, service="iam",
            account_id=_ACCOUNT_ID, region="global",
            name="acme-critical-role",
            config={
                "role_name": "acme-critical-role",
                "trust_policy": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",                   # IAM-005: wildcard principal
                        "Action": "sts:AssumeRole",
                    }]
                },
                "inline_policies": [{
                    "name": "FullAdmin",
                    "document": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "*",                  # IAM-001: wildcard action
                            "Resource": "*",                # IAM-002: wildcard resource
                        }]
                    },
                }],
                "managed_policies": [
                    {
                        "name": "AdministratorAccess",      # IAM-003
                        "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "document": {},
                    }
                ],
            },
        )

    def _critical_sg(self) -> CloudResource:
        return CloudResource(
            resource_id="sg-critical-001",
            resource_type=ResourceType.SECURITY_GROUP,
            provider=_PROVIDER, service="ec2",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-critical-sg",
            tags={"Environment": "production"},
            config={
                "group_name": "acme-critical-sg",
                "description": "Fully exposed SG",
                "vpc_id": "vpc-0a1b2c3d4e5f",
                "inbound_rules": [
                    {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},   # SG-003
                    {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},    # SG-001
                    {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},# SG-002
                    {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "cidr": "0.0.0.0/0"},# SG-004
                ],
                "outbound_rules": [],
            },
        )

    def _critical_lambda(self) -> CloudResource:
        return CloudResource(
            resource_id="arn:aws:lambda:us-east-1:123456789012:function:acme-critical-fn",
            resource_type=ResourceType.LAMBDA_FUNCTION,
            provider=_PROVIDER, service="lambda",
            account_id=_ACCOUNT_ID, region="us-east-1",
            name="acme-critical-fn",
            tags={"Environment": "production"},
            config={
                "function_name": "acme-critical-fn",
                "runtime": "python3.6",                     # LAM-003: very deprecated
                "handler": "handler.main",
                "memory_size": 128,
                "timeout": 3,
                "environment_variables": {
                    "DATABASE_PASSWORD": "SuperSecret123!",  # LAM-002
                    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                },
                "execution_role_arn": "arn:aws:iam::123456789012:role/acme-critical-role",
                "execution_role_policies": [
                    {"name": "AdministratorAccess", "arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                ],
                "execution_role_inline_policies": [],
                "resource_policy": {                         # LAM-001
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "lambda:InvokeFunction",
                    }]
                },
                "tracing_mode": "PassThrough",               # LAM-005
                "security_group_ids": ["sg-critical-001"],   # Cross-resource relationship to exposed SG
                "vpc_config": None,
            },
        )

