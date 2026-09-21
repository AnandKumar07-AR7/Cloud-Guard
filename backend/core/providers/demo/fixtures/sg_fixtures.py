"""
CloudGuard Demo — Security Group Fixtures
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"


def get_sg_fixtures() -> List[CloudResource]:
    return [
        _web_servers_sg(),
        _database_sg(),
        _bastion_sg(),
        _redis_sg(),
    ]


def _web_servers_sg() -> CloudResource:
    """
    sg-web-servers — HTTP/HTTPS open (fine), SSH open to 0.0.0.0/0 (violation).
    Expected findings: SG-001 (HIGH) — SSH open to Internet
    """
    return CloudResource(
        resource_id="sg-0a1b2c3d4e5f67890",
        resource_type=ResourceType.SECURITY_GROUP,
        provider=_PROVIDER,
        service="ec2",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-web-servers",
        tags={"Environment": "production", "Service": "web"},
        config={
            "group_name": "acme-web-servers",
            "description": "Security group for web servers",
            "vpc_id": "vpc-0a1b2c3d4e5f",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 80,  "to_port": 80,  "cidr": "0.0.0.0/0", "description": "HTTP"},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0", "description": "HTTPS"},
                {"protocol": "tcp", "from_port": 22,  "to_port": 22,  "cidr": "0.0.0.0/0", "description": "SSH"},  # → SG-001
            ],
            "outbound_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},
            ],
        },
    )


def _database_sg() -> CloudResource:
    """
    sg-database — MySQL 3306 open to 0.0.0.0/0.
    Expected findings: SG-004 (CRITICAL) — MySQL exposed to Internet
    """
    return CloudResource(
        resource_id="sg-1b2c3d4e5f678901",
        resource_type=ResourceType.SECURITY_GROUP,
        provider=_PROVIDER,
        service="ec2",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-database",
        tags={"Environment": "production", "Service": "database"},
        config={
            "group_name": "acme-database",
            "description": "Security group for RDS databases",
            "vpc_id": "vpc-0a1b2c3d4e5f",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "cidr": "0.0.0.0/0", "description": "MySQL"},  # → SG-004
            ],
            "outbound_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},
            ],
        },
    )


def _bastion_sg() -> CloudResource:
    """
    sg-bastion — SSH restricted to internal VPN CIDR only.
    Expected findings: NONE (clean)
    """
    return CloudResource(
        resource_id="sg-2c3d4e5f6a7b8901",
        resource_type=ResourceType.SECURITY_GROUP,
        provider=_PROVIDER,
        service="ec2",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-bastion",
        tags={"Environment": "production", "Service": "bastion"},
        config={
            "group_name": "acme-bastion",
            "description": "Bastion host — SSH access from VPN only",
            "vpc_id": "vpc-0a1b2c3d4e5f",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/8", "description": "SSH from VPN"},
            ],
            "outbound_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},
            ],
        },
    )


def _redis_sg() -> CloudResource:
    """
    sg-redis — Redis 6379 open to Internet + RDP open.
    Expected findings: SG-002 (HIGH) — RDP open, SG-006 (HIGH) — Redis exposed
    """
    return CloudResource(
        resource_id="sg-3d4e5f6a7b8c9012",
        resource_type=ResourceType.SECURITY_GROUP,
        provider=_PROVIDER,
        service="ec2",
        account_id=_ACCOUNT_ID,
        region="us-east-1",
        name="acme-cache",
        tags={"Environment": "staging", "Service": "redis"},
        config={
            "group_name": "acme-cache",
            "description": "Cache cluster security group",
            "vpc_id": "vpc-0a1b2c3d4e5f",
            "inbound_rules": [
                {"protocol": "tcp", "from_port": 6379, "to_port": 6379, "cidr": "0.0.0.0/0", "description": "Redis"},  # → SG-006
                {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0", "description": "RDP"},    # → SG-002
            ],
            "outbound_rules": [
                {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"},
            ],
        },
    )
