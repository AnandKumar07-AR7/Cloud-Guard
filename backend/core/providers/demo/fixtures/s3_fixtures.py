"""
CloudGuard Demo — S3 Bucket Fixtures

Deterministic S3 resources representing a fictional 'Acme Corp' AWS environment.
Every resource is intentional: some are deliberately misconfigured for demo purposes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_REGION = "us-east-1"
_PROVIDER = "demo"


def get_s3_fixtures() -> List[CloudResource]:
    """Return all demo S3 bucket resources."""
    return [
        _public_data_lake(),
        _website_assets(),
        _audit_logs(),
        _dev_scratch(),
        _backup_store(),
    ]


def _public_data_lake() -> CloudResource:
    """
    acme-public-data-lake — NO public access block, NO encryption, NO versioning.
    Expected findings: S3-001 (HIGH), S3-004 (MEDIUM), S3-005 (LOW)
    """
    return CloudResource(
        resource_id="acme-public-data-lake",
        resource_type=ResourceType.S3_BUCKET,
        provider=_PROVIDER,
        service="s3",
        account_id=_ACCOUNT_ID,
        region=_REGION,
        name="acme-public-data-lake",
        tags={"Environment": "production", "Team": "data"},
        config={
            "public_access_block": {},   # empty → S3-001 fires
            "acl": {
                "grants": [],
                "owner": {"display_name": "acme-corp", "id": "abc123"},
            },
            "encryption": None,          # → S3-004 fires
            "versioning": {"status": "Disabled", "mfa_delete": "Disabled"},  # → S3-005 fires
            "location": _REGION,
        },
    )


def _website_assets() -> CloudResource:
    """
    acme-website-assets — public ACL READ grant, encrypted, versioned.
    Expected findings: S3-002 (HIGH) — ACL grants AllUsers READ
    """
    return CloudResource(
        resource_id="acme-website-assets",
        resource_type=ResourceType.S3_BUCKET,
        provider=_PROVIDER,
        service="s3",
        account_id=_ACCOUNT_ID,
        region=_REGION,
        name="acme-website-assets",
        tags={"Environment": "production", "Purpose": "static-website"},
        config={
            "public_access_block": {
                "BlockPublicAcls": False,   # intentionally disabled for website
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "acl": {
                "grants": [
                    {
                        "grantee": {
                            "type": "Group",
                            "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "permission": "READ",
                    }
                ],
                "owner": {"display_name": "acme-corp", "id": "abc123"},
            },
            "encryption": {"sse_algorithm": "AES256"},
            "versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
            "location": _REGION,
        },
    )


def _audit_logs() -> CloudResource:
    """
    acme-audit-logs — private, encrypted, versioning enabled, MFA delete on, logging enabled.
    Expected findings: NONE (clean resource)
    """
    return CloudResource(
        resource_id="acme-audit-logs",
        resource_type=ResourceType.S3_BUCKET,
        provider=_PROVIDER,
        service="s3",
        account_id=_ACCOUNT_ID,
        region=_REGION,
        name="acme-audit-logs",
        tags={"Environment": "production", "DataClass": "confidential"},
        config={
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "acl": {
                "grants": [],
                "owner": {"display_name": "acme-corp", "id": "abc123"},
            },
            "encryption": {"sse_algorithm": "aws:kms", "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/demo-key"},
            "versioning": {"status": "Enabled", "mfa_delete": "Enabled"},
            "logging": {"target_bucket": "acme-access-logs", "target_prefix": "audit-logs/"},  # S3-008: logging enabled
            "location": _REGION,
        },
    )



def _dev_scratch() -> CloudResource:
    """
    acme-dev-scratch — private, NO encryption, NO versioning.
    Expected findings: S3-004 (MEDIUM), S3-005 (LOW)
    """
    return CloudResource(
        resource_id="acme-dev-scratch",
        resource_type=ResourceType.S3_BUCKET,
        provider=_PROVIDER,
        service="s3",
        account_id=_ACCOUNT_ID,
        region="us-west-2",
        name="acme-dev-scratch",
        tags={"Environment": "development", "Team": "engineering"},
        config={
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "acl": {"grants": [], "owner": {"display_name": "acme-corp", "id": "abc123"}},
            "encryption": None,           # → S3-004 fires
            "versioning": {"status": "Disabled", "mfa_delete": "Disabled"},  # → S3-005 fires
            "location": "us-west-2",
        },
    )


def _backup_store() -> CloudResource:
    """
    acme-backup-store — private, versioning suspended (was enabled, now off).
    Expected findings: S3-006 (MEDIUM) — versioning suspended
    """
    return CloudResource(
        resource_id="acme-backup-store",
        resource_type=ResourceType.S3_BUCKET,
        provider=_PROVIDER,
        service="s3",
        account_id=_ACCOUNT_ID,
        region=_REGION,
        name="acme-backup-store",
        tags={"Environment": "production", "Purpose": "backup"},
        config={
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "acl": {"grants": [], "owner": {"display_name": "acme-corp", "id": "abc123"}},
            "encryption": {"sse_algorithm": "AES256"},
            "versioning": {"status": "Suspended", "mfa_delete": "Disabled"},  # → S3-006 fires
            "location": _REGION,
        },
    )
