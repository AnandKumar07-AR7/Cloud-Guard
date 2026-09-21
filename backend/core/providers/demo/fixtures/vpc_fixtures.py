"""CloudGuard Demo — VPC Fixtures"""
from __future__ import annotations
from typing import List
from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"

def get_vpc_fixtures() -> List[CloudResource]:
    return [_production_vpc(), _dev_vpc()]

def _production_vpc() -> CloudResource:
    """Production VPC — flow logs disabled."""
    return CloudResource(
        resource_id="vpc-0a1b2c3d4e5f",
        resource_type=ResourceType.VPC,
        provider=_PROVIDER, service="vpc",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-production",
        tags={"Environment": "production"},
        config={
            "cidr_block": "10.0.0.0/16",
            "is_default": False,
            "flow_logs_enabled": False,  # Missing flow logs
            "dhcp_options_id": "dopt-abc123",
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
        },
    )

def _dev_vpc() -> CloudResource:
    """Dev VPC — flow logs enabled. Clean."""
    return CloudResource(
        resource_id="vpc-1b2c3d4e5f6a",
        resource_type=ResourceType.VPC,
        provider=_PROVIDER, service="vpc",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-development",
        tags={"Environment": "development"},
        config={
            "cidr_block": "10.1.0.0/16",
            "is_default": False,
            "flow_logs_enabled": True,
            "dhcp_options_id": "dopt-def456",
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
        },
    )
