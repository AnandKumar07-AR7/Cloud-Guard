"""
S3 bucket collector for AWS.
"""

from typing import List, Dict, Any
import logging
import boto3
from botocore.exceptions import ClientError

from cloudguard_copilot.collectors.base import BaseCollector
from cloudguard_copilot.utils.debug_logger import get_debug_logger

logger = logging.getLogger(__name__)
debug = get_debug_logger()


class S3Collector(BaseCollector):
    """
    Collector for S3 bucket configurations.

    Gathers bucket ACLs, public access blocks, encryption, and versioning settings.
    """

    def __init__(self, session: boto3.Session = None):
        """
        Initialize S3 collector.

        Args:
            session: boto3 Session object. If None, uses default credentials.
        """
        super().__init__(session)
        if session:
            self.s3_client = session.client('s3')
        else:
            self.s3_client = boto3.client('s3')

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all S3 bucket configurations.

        Returns:
            List of normalized S3 bucket resources
        """
        if debug:
            debug.log_section_start("S3 Bucket Collection")
            debug.log_aws_api_call("s3", "list_buckets")

        resources = []

        try:
            # List all buckets
            response = self.s3_client.list_buckets()

            if debug:
                debug.log_aws_api_response("s3", "list_buckets", response)

            buckets = response.get('Buckets', [])

            logger.info(f"Found {len(buckets)} S3 buckets")
            if debug:
                debug.log_custom(f"Found {len(buckets)} S3 buckets to process")

            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    bucket_config = self._get_bucket_config(bucket_name)
                    normalized = self._normalize_resource(
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        config=bucket_config
                    )
                    resources.append(normalized)

                except Exception as e:
                    self._handle_error(e, f"s3_bucket:{bucket_name}")

        except Exception as e:
            self._handle_error(e, "s3_buckets")

        return resources

    def _get_bucket_config(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get detailed configuration for a specific bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Dictionary containing bucket configuration
        """
        config = {
            "bucket_name": bucket_name,
            "acl": None,
            "public_access_block": None,
            "encryption": None,
            "versioning": None,
            "region": None
        }

        # Get bucket location
        try:
            location = self.s3_client.get_bucket_location(Bucket=bucket_name)
            config["region"] = location.get('LocationConstraint') or 'us-east-1'
        except ClientError as e:
            logger.warning(f"Could not get location for {bucket_name}: {e}")

        # Get bucket ACL
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            config["acl"] = {
                "grants": acl.get('Grants', []),
                "owner": acl.get('Owner', {})
            }
        except ClientError as e:
            logger.warning(f"Could not get ACL for {bucket_name}: {e}")

        # Get public access block configuration
        try:
            public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config["public_access_block"] = public_access.get('PublicAccessBlockConfiguration', {})
        except ClientError as e:
            # If no public access block is configured, it means it's not set (potentially public)
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                config["public_access_block"] = {}
            else:
                logger.warning(f"Could not get public access block for {bucket_name}: {e}")

        # Get bucket encryption
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            config["encryption"] = encryption.get('ServerSideEncryptionConfiguration', {})
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                config["encryption"] = None
            else:
                logger.warning(f"Could not get encryption for {bucket_name}: {e}")

        # Get bucket versioning
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            config["versioning"] = {
                "status": versioning.get('Status', 'Disabled'),
                "mfa_delete": versioning.get('MFADelete', 'Disabled')
            }
        except ClientError as e:
            logger.warning(f"Could not get versioning for {bucket_name}: {e}")

        return config
