"""CloudGuard Demo — CloudTrail Fixtures"""
from __future__ import annotations
from typing import List
from core.providers.base import CloudResource, ResourceType

_ACCOUNT_ID = "123456789012"
_PROVIDER = "demo"

def get_cloudtrail_fixtures() -> List[CloudResource]:
    return [_main_trail(), _regional_trail()]

def _main_trail() -> CloudResource:
    """Main CloudTrail — log validation disabled."""
    return CloudResource(
        resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/acme-audit-trail",
        resource_type=ResourceType.CLOUDTRAIL,
        provider=_PROVIDER, service="cloudtrail",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-audit-trail",
        tags={"Environment": "production"},
        config={
            "trail_name": "acme-audit-trail",
            "is_multi_region": True,
            "is_logging": True,
            "log_file_validation_enabled": False,  # Missing validation
            "include_global_service_events": True,
            "s3_bucket_name": "acme-audit-logs",
            "cloud_watch_logs_log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs",
            "kms_key_id": None,
        },
    )

def _regional_trail() -> CloudResource:
    """Regional CloudTrail — properly configured. Clean."""
    return CloudResource(
        resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/acme-regional-trail",
        resource_type=ResourceType.CLOUDTRAIL,
        provider=_PROVIDER, service="cloudtrail",
        account_id=_ACCOUNT_ID, region="us-east-1",
        name="acme-regional-trail",
        tags={"Environment": "production"},
        config={
            "trail_name": "acme-regional-trail",
            "is_multi_region": False,
            "is_logging": True,
            "log_file_validation_enabled": True,
            "include_global_service_events": False,
            "s3_bucket_name": "acme-audit-logs",
            "cloud_watch_logs_log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs",
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/demo-key",
        },
    )
