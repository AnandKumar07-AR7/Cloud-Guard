"""CloudGuard Demo — RDS Instance Fixtures"""
from __future__ import annotations
from typing import List
from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"

def get_rds_fixtures() -> List[CloudResource]:
    return [_prod_db(), _dev_db()]

def _prod_db() -> CloudResource:
    """Production RDS — publicly accessible + no encryption. Critical violations."""
    return CloudResource(
        resource_id="acme-prod-db",
        resource_type=ResourceType.RDS_INSTANCE,
        provider=_PROVIDER, service="rds",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-prod-db",
        tags={"Environment": "production", "DataClass": "sensitive"},
        config={
            "engine": "mysql",
            "engine_version": "8.0.35",
            "instance_class": "db.t3.large",
            "publicly_accessible": True,   # Major violation
            "storage_encrypted": False,    # Encryption missing
            "multi_az": True,
            "backup_retention_period": 7,
            "deletion_protection": True,
            "security_group_ids": ["sg-1b2c3d4e5f678901"],
            "ca_certificate_identifier": "rds-ca-2019",
            "auto_minor_version_upgrade": True,
        },
    )

def _dev_db() -> CloudResource:
    """Dev RDS — not publicly accessible, encrypted. Clean."""
    return CloudResource(
        resource_id="acme-dev-db",
        resource_type=ResourceType.RDS_INSTANCE,
        provider=_PROVIDER, service="rds",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-dev-db",
        tags={"Environment": "development"},
        config={
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": "db.t3.micro",
            "publicly_accessible": False,
            "storage_encrypted": True,
            "multi_az": False,
            "backup_retention_period": 1,
            "deletion_protection": False,
            "security_group_ids": ["sg-2c3d4e5f6a7b8901"],
            "ca_certificate_identifier": "rds-ca-rsa2048-g1",
            "auto_minor_version_upgrade": True,
        },
    )
