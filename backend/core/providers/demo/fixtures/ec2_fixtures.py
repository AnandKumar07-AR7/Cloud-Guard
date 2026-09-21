"""CloudGuard Demo — EC2 Instance Fixtures"""
from __future__ import annotations
from typing import List
from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"

def get_ec2_fixtures() -> List[CloudResource]:
    return [_web_server_instance(), _private_instance()]

def _web_server_instance() -> CloudResource:
    """EC2 with IMDSv2 not enforced and public IP — MEDIUM finding."""
    return CloudResource(
        resource_id="i-0a1b2c3d4e5f67890",
        resource_type=ResourceType.EC2_INSTANCE,
        provider=_PROVIDER, service="ec2",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-web-server-01",
        tags={"Environment": "production", "Role": "web"},
        config={
            "instance_type": "t3.medium",
            "state": "running",
            "public_ip": "54.123.45.67",
            "private_ip": "10.0.1.10",
            "imdsv2_required": False,  # IMDSv2 not enforced
            "monitoring_enabled": False,
            "security_group_ids": ["sg-0a1b2c3d4e5f67890"],
            "iam_instance_profile": None,
            "ebs_optimized": True,
        },
    )

def _private_instance() -> CloudResource:
    """EC2 with IMDSv2 enforced, no public IP — clean."""
    return CloudResource(
        resource_id="i-1b2c3d4e5f678901",
        resource_type=ResourceType.EC2_INSTANCE,
        provider=_PROVIDER, service="ec2",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-worker-01",
        tags={"Environment": "production", "Role": "worker"},
        config={
            "instance_type": "c5.xlarge",
            "state": "running",
            "public_ip": None,
            "private_ip": "10.0.2.50",
            "imdsv2_required": True,
            "monitoring_enabled": True,
            "security_group_ids": ["sg-2c3d4e5f6a7b8901"],
            "iam_instance_profile": "arn:aws:iam::123456789012:instance-profile/worker-profile",
            "ebs_optimized": True,
        },
    )
