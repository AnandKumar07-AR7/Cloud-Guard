"""
CloudGuard Demo — Lambda Function Fixtures
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"


def get_lambda_fixtures() -> List[CloudResource]:
    return [
        _api_handler(),
        _data_processor(),
        _scheduler(),
    ]


def _api_handler() -> CloudResource:
    """
    acme-api-handler — deprecated python3.8 runtime + env secrets.
    Expected findings: LAM-002 (HIGH) secrets, LAM-003 (HIGH) deprecated runtime, LAM-005 (LOW) tracing
    """
    return CloudResource(
        resource_id="arn:aws:lambda:us-east-1:123456789012:function:acme-api-handler",
        resource_type=ResourceType.LAMBDA_FUNCTION,
        provider=_PROVIDER,
        service="lambda",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-api-handler",
        tags={"Environment": "production", "Team": "backend"},
        config={
            "function_name": "acme-api-handler",
            "runtime": "python3.8",                 # → LAM-003 deprecated
            "handler": "app.handler",
            "memory_size": 512,
            "timeout": 30,
            "environment_variables": {
                "DATABASE_PASSWORD": "s3cr3t-db-pass-12345",   # → LAM-002
                "API_KEY": "sk-live-abcdef1234567890",          # → LAM-002
                "LOG_LEVEL": "INFO",
                "REGION": "us-east-1",
            },
            "resource_policy": None,
            "execution_role_arn": "arn:aws:iam::123456789012:role/acme-lambda-execution",
            "execution_role_policies": [],
            "tracing_mode": "PassThrough",           # → LAM-005
            "vpc_config": None,
        },
    )


def _data_processor() -> CloudResource:
    """
    acme-data-processor — public resource policy + admin execution role.
    Expected findings: LAM-001 (CRITICAL) public policy, LAM-004 (CRITICAL) admin role
    """
    return CloudResource(
        resource_id="arn:aws:lambda:us-east-1:123456789012:function:acme-data-processor",
        resource_type=ResourceType.LAMBDA_FUNCTION,
        provider=_PROVIDER,
        service="lambda",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-data-processor",
        tags={"Environment": "production", "Team": "data"},
        config={
            "function_name": "acme-data-processor",
            "runtime": "python3.12",
            "handler": "processor.handler",
            "memory_size": 1024,
            "timeout": 300,
            "environment_variables": {
                "OUTPUT_BUCKET": "acme-public-data-lake",
            },
            "resource_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowPublicInvoke",
                        "Effect": "Allow",
                        "Principal": "*",              # → LAM-001 public policy
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:us-east-1:123456789012:function:acme-data-processor",
                    }
                ],
            },
            "execution_role_arn": "arn:aws:iam::123456789012:role/acme-admin-role",
            "execution_role_policies": [
                {
                    "name": "AdministratorAccess",
                    "arn": "arn:aws:iam::aws:policy/AdministratorAccess",  # → LAM-004
                }
            ],
            "execution_role_inline_policies": [],
            "tracing_mode": "Active",
            "vpc_config": None,
        },
    )


def _scheduler() -> CloudResource:
    """
    acme-scheduled-cleanup — properly configured, no violations.
    Expected findings: NONE (clean)
    """
    return CloudResource(
        resource_id="arn:aws:lambda:us-east-1:123456789012:function:acme-scheduled-cleanup",
        resource_type=ResourceType.LAMBDA_FUNCTION,
        provider=_PROVIDER,
        service="lambda",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-scheduled-cleanup",
        tags={"Environment": "production", "Team": "ops"},
        config={
            "function_name": "acme-scheduled-cleanup",
            "runtime": "python3.12",
            "handler": "cleanup.handler",
            "memory_size": 256,
            "timeout": 900,
            "environment_variables": {
                "LOG_LEVEL": "INFO",
                "TARGET_BUCKET": "acme-audit-logs",
            },
            "resource_policy": None,
            "execution_role_arn": "arn:aws:iam::123456789012:role/acme-readonly-role",
            "execution_role_policies": [
                {
                    "name": "ReadOnlyAccess",
                    "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                }
            ],
            "execution_role_inline_policies": [],
            "tracing_mode": "Active",
            "vpc_config": {
                "subnet_ids": ["subnet-abc123", "subnet-def456"],
                "security_group_ids": ["sg-2c3d4e5f6a7b8901"],
            },
        },
    )
