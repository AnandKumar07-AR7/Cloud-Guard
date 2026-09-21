"""
CloudGuard Demo — IAM Role Fixtures

Deterministic IAM resources for the 'Acme Corp' demo environment.
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_REGION = "us-east-1"
_PROVIDER = "demo"


def get_iam_fixtures() -> List[CloudResource]:
    return [
        _admin_role(),
        _lambda_execution_role(),
        _readonly_role(),
        _dev_role(),
    ]


def _admin_role() -> CloudResource:
    """
    acme-admin-role — wildcard Action + Resource in inline policy.
    Expected findings: IAM-001 (CRITICAL), IAM-002 (HIGH), IAM-004 (HIGH)
    """
    return CloudResource(
        resource_id="arn:aws:iam::123456789012:role/acme-admin-role",
        resource_type=ResourceType.IAM_ROLE,
        provider=_PROVIDER,
        service="iam",
        account_id=_ACCOUNT_ID,
        region="global",
        name="acme-admin-role",
        tags={"Environment": "production"},
        config={
            "role_name": "acme-admin-role",
            "trust_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "inline_policies": [
                {
                    "name": "AdminInlinePolicy",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "FullAccess",
                                "Effect": "Allow",
                                "Action": "*",        # → IAM-001 fires
                                "Resource": "*",      # → IAM-002 fires
                            }
                        ],
                    },
                }
            ],
            "managed_policies": [],
            "permissions_boundary": None,
        },
    )


def _lambda_execution_role() -> CloudResource:
    """
    acme-lambda-execution — specific actions but wildcard resource + IAM write.
    Expected findings: IAM-002 (HIGH), IAM-004 (HIGH)
    """
    return CloudResource(
        resource_id="arn:aws:iam::123456789012:role/acme-lambda-execution",
        resource_type=ResourceType.IAM_ROLE,
        provider=_PROVIDER,
        service="iam",
        account_id=_ACCOUNT_ID,
        region="global",
        name="acme-lambda-execution",
        tags={"Environment": "production", "Service": "lambda"},
        config={
            "role_name": "acme-lambda-execution",
            "trust_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "inline_policies": [
                {
                    "name": "LambdaPermissions",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "iam:CreateUser",      # → IAM-004 fires
                                    "iam:AttachRolePolicy",
                                ],
                                "Resource": "*",          # → IAM-002 fires
                            }
                        ],
                    },
                }
            ],
            "managed_policies": [],
            "permissions_boundary": None,
        },
    )


def _readonly_role() -> CloudResource:
    """
    acme-readonly-role — correctly scoped, specific actions, specific resources.
    Expected findings: NONE (clean resource)
    """
    return CloudResource(
        resource_id="arn:aws:iam::123456789012:role/acme-readonly-role",
        resource_type=ResourceType.IAM_ROLE,
        provider=_PROVIDER,
        service="iam",
        account_id=_ACCOUNT_ID,
        region="global",
        name="acme-readonly-role",
        tags={"Environment": "production"},
        config={
            "role_name": "acme-readonly-role",
            "trust_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "inline_policies": [],
            "managed_policies": [
                {
                    "name": "ReadOnlyAccess",
                    "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": [
                                    f"arn:aws:s3:::acme-audit-logs",
                                    f"arn:aws:s3:::acme-audit-logs/*",
                                ],
                            }
                        ],
                    },
                }
            ],
            "permissions_boundary": "arn:aws:iam::123456789012:policy/ReadOnlyBoundary",
        },
    )


def _dev_role() -> CloudResource:
    """
    acme-dev-role — has AdministratorAccess managed policy.
    Expected findings: IAM-003 (CRITICAL)
    """
    return CloudResource(
        resource_id="arn:aws:iam::123456789012:role/acme-dev-role",
        resource_type=ResourceType.IAM_ROLE,
        provider=_PROVIDER,
        service="iam",
        account_id=_ACCOUNT_ID,
        region="global",
        name="acme-dev-role",
        tags={"Environment": "development"},
        config={
            "role_name": "acme-dev-role",
            "trust_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:user/developer"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "inline_policies": [],
            "managed_policies": [
                {
                    "name": "AdministratorAccess",
                    "arn": "arn:aws:iam::aws:policy/AdministratorAccess",  # → IAM-003 fires
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    },
                }
            ],
            "permissions_boundary": None,
        },
    )
