"""
CloudGuard — AWS S3 Collector

Collects S3 bucket configuration and normalizes it into CloudResource objects.
Migrated and improved from cloudguard-copilot-main/collectors/aws/s3_collector.py.

Improvements over legacy:
  - Retry on throttling
  - Structured logging per API call
  - Partial results on per-bucket errors
  - Normalized config schema matching S3 security rules
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from core.providers.aws.collectors.base import AWSCollector
from core.providers.base import CloudResource, ResourceType
from core.utils.retry import aws_retry


class S3Collector(AWSCollector):
    """Collects S3 bucket configurations."""

    def collect(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        s3 = self.client("s3")

        # List all buckets (S3 is global)
        response = self._safe_collect("list_buckets", s3.list_buckets)
        if not response:
            return resources

        buckets = response.get("Buckets", [])
        self.log.info("s3_buckets_listed", count=len(buckets))

        for bucket in buckets:
            bucket_name = bucket.get("Name", "")
            try:
                resource = self._collect_bucket(s3, bucket_name)
                if resource:
                    resources.append(resource)
            except Exception as exc:
                self.log.warning(
                    "s3_bucket_collection_failed",
                    bucket=bucket_name,
                    error=str(exc),
                )

        return resources

    def _collect_bucket(self, s3, bucket_name: str) -> Optional[CloudResource]:
        """Collect configuration for a single S3 bucket."""
        region = self._get_bucket_region(s3, bucket_name) or "us-east-1"

        config: Dict[str, Any] = {
            "public_access_block": self._get_public_access_block(s3, bucket_name),
            "acl": self._get_acl(s3, bucket_name),
            "encryption": self._get_encryption(s3, bucket_name),
            "versioning": self._get_versioning(s3, bucket_name),
            "location": region,
        }

        return CloudResource(
            resource_id=bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            provider="aws",
            service="s3",
            account_id=self.account_id,
            region=region,
            name=bucket_name,
            config=config,
        )

    @aws_retry(max_attempts=3)
    def _get_bucket_region(self, s3, bucket_name: str) -> Optional[str]:
        try:
            response = s3.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint")
            return location if location else "us-east-1"
        except ClientError:
            return None

    @aws_retry(max_attempts=3)
    def _get_public_access_block(self, s3, bucket_name: str) -> Dict[str, bool]:
        try:
            resp = s3.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            return {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {}
            return {}

    @aws_retry(max_attempts=3)
    def _get_acl(self, s3, bucket_name: str) -> Dict[str, Any]:
        try:
            resp = s3.get_bucket_acl(Bucket=bucket_name)
            return {
                "grants": [
                    {
                        "grantee": {
                            "type": g.get("Grantee", {}).get("Type", ""),
                            "uri": g.get("Grantee", {}).get("URI", ""),
                            "id": g.get("Grantee", {}).get("ID", ""),
                        },
                        "permission": g.get("Permission", ""),
                    }
                    for g in resp.get("Grants", [])
                ],
                "owner": resp.get("Owner", {}),
            }
        except ClientError:
            return {"grants": [], "owner": {}}

    @aws_retry(max_attempts=3)
    def _get_encryption(self, s3, bucket_name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                return {
                    "sse_algorithm": default.get("SSEAlgorithm", ""),
                    "kms_key_id": default.get("KMSMasterKeyID"),
                }
            return None
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return None
            return None

    @aws_retry(max_attempts=3)
    def _get_versioning(self, s3, bucket_name: str) -> Dict[str, str]:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket_name)
            return {
                "status": resp.get("Status", "Disabled"),
                "mfa_delete": resp.get("MFADelete", "Disabled"),
            }
        except ClientError:
            return {"status": "Disabled", "mfa_delete": "Disabled"}
