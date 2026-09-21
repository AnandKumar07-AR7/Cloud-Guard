"""
S3 misconfiguration detector.
"""

from typing import List, Dict, Any
import uuid
import logging

logger = logging.getLogger(__name__)


def detect_s3_misconfigurations(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect misconfigurations in S3 bucket resources.

    Args:
        resources: List of normalized S3 bucket resources

    Returns:
        List of findings
    """
    findings = []

    for resource in resources:
        if resource.get("resource_type") != "s3_bucket":
            continue

        config = resource.get("config", {})
        bucket_name = config.get("bucket_name")

        # Check for public access
        public_finding = _check_public_bucket(resource)
        if public_finding:
            findings.append(public_finding)

        # Check for missing encryption
        encryption_finding = _check_encryption(resource)
        if encryption_finding:
            findings.append(encryption_finding)

        # Check for disabled versioning
        versioning_finding = _check_versioning(resource)
        if versioning_finding:
            findings.append(versioning_finding)

    logger.info(f"Found {len(findings)} S3 misconfigurations")
    return findings


def _check_public_bucket(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if an S3 bucket is publicly accessible.

    Args:
        resource: Normalized S3 bucket resource

    Returns:
        Finding dictionary if bucket is public, None otherwise
    """
    config = resource.get("config", {})
    bucket_name = config.get("bucket_name")
    acl = config.get("acl", {})
    public_access_block = config.get("public_access_block", {})

    is_public = False
    reason = []

    # Check if public access block is disabled or not configured
    if not public_access_block:
        is_public = True
        reason.append("No PublicAccessBlock configuration")
    else:
        # Check individual settings
        if not public_access_block.get("BlockPublicAcls", False):
            is_public = True
            reason.append("BlockPublicAcls is False")

        if not public_access_block.get("BlockPublicPolicy", False):
            is_public = True
            reason.append("BlockPublicPolicy is False")

        if not public_access_block.get("IgnorePublicAcls", False):
            is_public = True
            reason.append("IgnorePublicAcls is False")

        if not public_access_block.get("RestrictPublicBuckets", False):
            is_public = True
            reason.append("RestrictPublicBuckets is False")

    # Check ACL for public grants
    grants = acl.get("grants", [])
    for grant in grants:
        grantee = grant.get("Grantee", {})
        grantee_uri = grantee.get("URI", "")

        if "AllUsers" in grantee_uri or "AuthenticatedUsers" in grantee_uri:
            is_public = True
            permission = grant.get("Permission", "UNKNOWN")
            reason.append(f"ACL grants {permission} to {grantee_uri}")

    if is_public:
        return {
            "id": str(uuid.uuid4()),
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "issue": f"S3 bucket is publicly accessible: {', '.join(reason)}",
            "severity": "high",
            "raw_config": config
        }

    return None


def _check_encryption(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if S3 bucket has encryption enabled.

    Args:
        resource: Normalized S3 bucket resource

    Returns:
        Finding dictionary if encryption is missing, None otherwise
    """
    config = resource.get("config", {})
    bucket_name = config.get("bucket_name")
    encryption = config.get("encryption")

    if not encryption:
        return {
            "id": str(uuid.uuid4()),
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "issue": "S3 bucket does not have server-side encryption enabled",
            "severity": "medium",
            "raw_config": config
        }

    return None


def _check_versioning(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if S3 bucket has versioning enabled.

    Args:
        resource: Normalized S3 bucket resource

    Returns:
        Finding dictionary if versioning is disabled, None otherwise
    """
    config = resource.get("config", {})
    bucket_name = config.get("bucket_name")
    versioning = config.get("versioning", {})
    status = versioning.get("status", "Disabled")

    if status != "Enabled":
        return {
            "id": str(uuid.uuid4()),
            "resource_id": bucket_name,
            "resource_type": "s3_bucket",
            "issue": "S3 bucket does not have versioning enabled",
            "severity": "low",
            "raw_config": config
        }

    return None
