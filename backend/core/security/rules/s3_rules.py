"""
CloudGuard — S3 Security Rules

Migrated and expanded from cloudguard-copilot-main detectors/s3_detector.py.
All rules are pure Python — no AWS API calls.

Rules implemented:
  S3-001  S3 public access block not configured                  HIGH
  S3-002  S3 bucket publicly accessible via ACL                  HIGH
  S3-003  S3 bucket ACL grants public READ access                HIGH
  S3-004  S3 bucket ACL grants public WRITE access               CRITICAL
  S3-005  S3 server-side encryption not enabled                  MEDIUM
  S3-006  S3 bucket versioning not enabled                       LOW
  S3-007  S3 bucket versioning suspended                         MEDIUM
  S3-008  S3 MFA delete not enabled on versioned bucket          MEDIUM
  S3-009  S3 bucket allows public authenticated access via ACL   MEDIUM
"""
from __future__ import annotations

from typing import Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule



# ==============================================================================
# S3-001 — Public Access Block Not Configured
# ==============================================================================

class S3PublicAccessBlockMissing(SecurityRule):
    """
    Detects S3 buckets where the PublicAccessBlock configuration is absent
    or has any block setting disabled. Without PublicAccessBlock, a bucket
    can become publicly accessible through ACLs or bucket policies.
    """

    metadata = RuleMetadata(
        rule_id="S3-001",
        name="S3 Public Access Block Not Fully Configured",
        description=(
            "The S3 bucket does not have all four PublicAccessBlock settings enabled. "
            "This increases the risk of unintentional public exposure."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.HIGH,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["CIS-2.1.5", "NIST-AC-3", "ISO-A.9.4.1"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Permissions → Block public access.\n"
            "3. Enable all four settings:\n"
            "   - Block all public ACLs\n"
            "   - Ignore public ACLs\n"
            "   - Block all public bucket policies\n"
            "   - Restrict public bucket policies\n"
            "4. Save changes.\n\n"
            "CLI: aws s3api put-public-access-block \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        pab = resource.get_config("public_access_block", {})

        required_keys = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        if not pab:
            # No configuration at all
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' has no Public Access Block",
                description=(
                    f"The S3 bucket '{resource.display_name}' has no PublicAccessBlock "
                    "configuration. This means public access is not explicitly blocked "
                    "and the bucket may be accessible via ACLs or bucket policies."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=None,
                    expected_value=required_keys,
                    field_path="config.public_access_block",
                    details={"bucket": resource.resource_id},
                ),
            )

        # Check each key
        disabled_settings = [
            key for key, expected in required_keys.items()
            if not pab.get(key, False)
        ]

        if disabled_settings:
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' has incomplete Public Access Block",
                description=(
                    f"The S3 bucket '{resource.display_name}' has the following public "
                    f"access block settings disabled: {', '.join(disabled_settings)}. "
                    "Disabling any of these settings may allow public access."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value={k: pab.get(k, False) for k in required_keys},
                    expected_value=required_keys,
                    field_path="config.public_access_block",
                    details={"disabled_settings": disabled_settings},
                ),
            )

        return None  # Compliant


# ==============================================================================
# S3-002 — Public ACL (Canned Grants)
# ==============================================================================

class S3PublicACLGrant(SecurityRule):
    """
    Detects S3 buckets where the ACL includes a grant to the 'AllUsers'
    (public internet) or 'AuthenticatedUsers' (all AWS accounts) groups.
    """

    metadata = RuleMetadata(
        rule_id="S3-002",
        name="S3 Bucket ACL Grants Public Access",
        description=(
            "The S3 bucket ACL grants READ or READ_ACP/WRITE access to AllUsers "
            "(public internet) or AuthenticatedUsers (all AWS accounts)."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.HIGH,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["CIS-2.1.5", "NIST-AC-3"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Permissions → Access control list (ACL).\n"
            "3. Remove any grants to 'Everyone (public access)' or "
            "'Authenticated users group (all AWS accounts)'.\n"
            "4. Save changes.\n\n"
            "CLI: aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private"
        ),
    )

    _PUBLIC_GRANTEES = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        acl = resource.get_config("acl", {})
        grants = acl.get("grants", [])

        public_grants = []
        for grant in grants:
            grantee = grant.get("grantee", {})
            uri = grantee.get("uri", "")
            if uri in self._PUBLIC_GRANTEES:
                public_grants.append({
                    "grantee_uri": uri,
                    "permission": grant.get("permission", "UNKNOWN"),
                })

        if public_grants:
            uris = [g["grantee_uri"] for g in public_grants]
            permissions = [g["permission"] for g in public_grants]
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' ACL grants public access",
                description=(
                    f"The S3 bucket '{resource.display_name}' has ACL grants that "
                    f"allow access to: {', '.join(set(uris))}. "
                    f"Permissions granted: {', '.join(set(permissions))}. "
                    "This can expose bucket contents to the public internet."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=public_grants,
                    expected_value=[],
                    field_path="config.acl.grants",
                    details={"public_grant_count": len(public_grants)},
                ),
            )
        return None


# ==============================================================================
# S3-003 — Write ACL Grant (CRITICAL)
# ==============================================================================

class S3WriteACLGrant(SecurityRule):
    """
    Detects S3 buckets where the ACL grants WRITE or FULL_CONTROL to public
    groups. This is more severe than read access — it allows data modification.
    """

    metadata = RuleMetadata(
        rule_id="S3-003",
        name="S3 Bucket ACL Grants Public WRITE Access",
        description=(
            "The S3 bucket ACL grants WRITE or FULL_CONTROL to AllUsers or "
            "AuthenticatedUsers. This allows anyone to upload, modify, or delete objects."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.CRITICAL,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["CIS-2.1.5", "NIST-AC-3", "ISO-A.9.4.1"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Permissions → Access control list (ACL).\n"
            "3. Remove WRITE and FULL_CONTROL grants from all public grantees.\n"
            "4. Set bucket ACL to private.\n\n"
            "CLI: aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private"
        ),
    )

    _PUBLIC_GRANTEES = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    _WRITE_PERMISSIONS = {"WRITE", "FULL_CONTROL", "WRITE_ACP"}

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        acl = resource.get_config("acl", {})
        grants = acl.get("grants", [])

        write_grants = []
        for grant in grants:
            grantee = grant.get("grantee", {})
            uri = grantee.get("uri", "")
            permission = grant.get("permission", "")
            if uri in self._PUBLIC_GRANTEES and permission in self._WRITE_PERMISSIONS:
                write_grants.append({"grantee_uri": uri, "permission": permission})

        if write_grants:
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' allows public WRITE access",
                description=(
                    f"CRITICAL: The S3 bucket '{resource.display_name}' grants WRITE "
                    "or FULL_CONTROL to public groups. Attackers can upload malicious "
                    "content, modify data, or delete objects."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=write_grants,
                    expected_value=[],
                    field_path="config.acl.grants",
                    details={"write_grant_count": len(write_grants)},
                ),
            )
        return None


# ==============================================================================
# S3-004 — Server-Side Encryption Missing
# ==============================================================================

class S3EncryptionMissing(SecurityRule):
    """
    Detects S3 buckets that do not have default server-side encryption
    configured. Without encryption, data at rest is not protected.
    """

    metadata = RuleMetadata(
        rule_id="S3-004",
        name="S3 Bucket Default Encryption Not Enabled",
        description=(
            "The S3 bucket does not have default server-side encryption configured. "
            "Data stored in the bucket is not encrypted at rest."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.MEDIUM,
        data_exposure_risk=True,
        compliance_mappings=["CIS-2.1.1", "NIST-SC-28", "ISO-A.10.1.1", "PCI-DSS-3.4"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Properties → Default encryption.\n"
            "3. Enable server-side encryption.\n"
            "4. Choose SSE-S3 (AES-256) or SSE-KMS for KMS-managed keys.\n"
            "5. Save changes.\n\n"
            "CLI: aws s3api put-bucket-encryption \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --server-side-encryption-configuration "
            "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
            "{\"SSEAlgorithm\":\"AES256\"}}]}'"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        encryption = resource.get_config("encryption")

        if not encryption:
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' has no default encryption",
                description=(
                    f"The S3 bucket '{resource.display_name}' does not have default "
                    "server-side encryption configured. Objects stored in this bucket "
                    "are not encrypted at rest, which may violate compliance requirements."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=None,
                    expected_value={"SSEAlgorithm": "AES256 or aws:kms"},
                    field_path="config.encryption",
                    details={"bucket": resource.resource_id},
                ),
            )
        return None


# ==============================================================================
# S3-005 — Versioning Disabled
# ==============================================================================

class S3VersioningDisabled(SecurityRule):
    """
    Detects S3 buckets that do not have versioning enabled. Without versioning,
    accidental deletion or overwriting of objects is not recoverable.
    """

    metadata = RuleMetadata(
        rule_id="S3-005",
        name="S3 Bucket Versioning Not Enabled",
        description=(
            "The S3 bucket does not have versioning enabled. "
            "Versioning protects against accidental deletion and overwrites."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.LOW,
        compliance_mappings=["CIS-2.1.3", "NIST-SI-12"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Properties → Bucket Versioning.\n"
            "3. Click 'Edit' and enable versioning.\n"
            "4. Save changes.\n\n"
            "CLI: aws s3api put-bucket-versioning \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --versioning-configuration Status=Enabled"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        versioning = resource.get_config("versioning", {})
        status = versioning.get("status", "Disabled") if versioning else "Disabled"

        if status in ("Disabled", "", None):
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' versioning is disabled",
                description=(
                    f"The S3 bucket '{resource.display_name}' does not have versioning "
                    "enabled. Without versioning, accidentally deleted or overwritten "
                    "objects cannot be recovered."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=status,
                    expected_value="Enabled",
                    field_path="config.versioning.status",
                    details={"mfa_delete": versioning.get("mfa_delete", "Disabled") if versioning else "N/A"},
                ),
            )
        return None


# ==============================================================================
# S3-006 — Versioning Suspended
# ==============================================================================

class S3VersioningSuspended(SecurityRule):
    """
    Detects S3 buckets where versioning has been explicitly suspended.
    A suspended state is more concerning than never-enabled because it
    suggests someone deliberately turned off a protection control.
    """

    metadata = RuleMetadata(
        rule_id="S3-006",
        name="S3 Bucket Versioning Suspended",
        description=(
            "The S3 bucket versioning is in a Suspended state. "
            "New objects will not be versioned, and prior protections are reduced."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.MEDIUM,
        compliance_mappings=["CIS-2.1.3", "NIST-SI-12"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Properties → Bucket Versioning.\n"
            "3. Re-enable versioning.\n\n"
            "CLI: aws s3api put-bucket-versioning \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --versioning-configuration Status=Enabled"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        versioning = resource.get_config("versioning", {})
        status = versioning.get("status", "") if versioning else ""

        if status == "Suspended":
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' versioning is suspended",
                description=(
                    f"The S3 bucket '{resource.display_name}' versioning was previously "
                    "enabled but has been suspended. New objects are not versioned, "
                    "and the protection against data loss is reduced."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value="Suspended",
                    expected_value="Enabled",
                    field_path="config.versioning.status",
                ),
            )
        return None


# ==============================================================================
# S3-007 — MFA Delete Not Enabled on Versioned Bucket
# ==============================================================================

class S3MFADeleteDisabled(SecurityRule):
    """
    Detects versioned S3 buckets that do not have MFA Delete enabled.
    Without MFA Delete, an attacker with write access can permanently
    delete versioned objects without MFA confirmation.
    """

    metadata = RuleMetadata(
        rule_id="S3-007",
        name="S3 Bucket MFA Delete Not Enabled",
        description=(
            "The versioned S3 bucket does not have MFA Delete enabled. "
            "MFA Delete prevents permanent deletion of versioned objects without MFA."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.MEDIUM,
        compliance_mappings=["CIS-2.1.2", "NIST-CP-9"],
        remediation_template=(
            "MFA Delete requires root account credentials to enable.\n\n"
            "CLI (must use root credentials):\n"
            "aws s3api put-bucket-versioning \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --versioning-configuration "
            "Status=Enabled,MFADelete=Enabled \\\n"
            "  --mfa 'arn:aws:iam::ACCOUNT_ID:mfa/DEVICE_SERIAL MFA_CODE'"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        versioning = resource.get_config("versioning", {})
        if not versioning:
            return None  # Not versioned — other rules cover that

        status = versioning.get("status", "")
        mfa_delete = versioning.get("mfa_delete", "Disabled")

        if status == "Enabled" and mfa_delete != "Enabled":
            return self._make_finding(
                resource,
                title=f"S3 Bucket '{resource.display_name}' MFA Delete disabled",
                description=(
                    f"The S3 bucket '{resource.display_name}' has versioning enabled "
                    "but MFA Delete is not enabled. Without MFA Delete, permanent "
                    "deletion of object versions does not require MFA verification."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=mfa_delete,
                    expected_value="Enabled",
                    field_path="config.versioning.mfa_delete",
                    details={"versioning_status": status},
                ),
            )
        return None


# ==============================================================================
# S3-008 — Server-Access Logging Not Enabled
# ==============================================================================

class S3LoggingDisabled(SecurityRule):
    """
    Detects S3 buckets that do not have server-access logging enabled.

    Server-access logging records all requests made to a bucket. Without logging,
    unauthorized access, data exfiltration, or bucket policy changes cannot be
    detected or investigated post-incident.
    """

    metadata = RuleMetadata(
        rule_id="S3-008",
        name="S3 Bucket Server-Access Logging Not Enabled",
        description=(
            "The S3 bucket does not have server-access logging enabled. "
            "Without access logs, requests to the bucket (including unauthorized "
            "access attempts and data downloads) cannot be audited or investigated."
        ),
        provider="aws",
        service="s3",
        resource_type="s3_bucket",
        severity=Severity.LOW,
        category="logging",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-3.6", "NIST-AU-2", "ISO-A.12.4.1"],
        remediation_template=(
            "1. Open the AWS S3 console.\n"
            "2. Select the bucket → Properties → Server access logging.\n"
            "3. Enable logging, specify a target bucket for log storage.\n\n"
            "CLI: aws s3api put-bucket-logging \\\n"
            "  --bucket BUCKET_NAME \\\n"
            "  --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\"}}'"
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        logging_config = resource.get_config("logging")

        # If logging config is present and has a target bucket, it's enabled
        if isinstance(logging_config, dict) and logging_config.get("target_bucket"):
            return None

        # If logging is True, it's enabled
        if logging_config is True:
            return None

        # If field is missing entirely, we can still flag — absence of logging is the default
        # But only flag if we have enough config data to know this is a real bucket
        bucket_name = resource.name or resource.resource_id
        if not bucket_name:
            return None

        return self._make_finding(
            resource,
            title=f"S3 Bucket '{resource.display_name}' does not have access logging enabled",
            description=(
                f"S3 bucket '{resource.display_name}' does not have server-access logging enabled. "
                "All bucket requests including GET, PUT, DELETE operations are not being recorded. "
                "Enable server-access logging to a separate bucket to maintain an audit trail of "
                "all access to this bucket's data."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.logging",
                observed_value=logging_config,
                expected_value={"target_bucket": "log-bucket-name", "target_prefix": "bucket-name/"},
                source="S3 bucket logging configuration",
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

S3_RULES: list[SecurityRule] = [
    S3PublicAccessBlockMissing(),
    S3PublicACLGrant(),
    S3WriteACLGrant(),
    S3EncryptionMissing(),
    S3VersioningDisabled(),
    S3VersioningSuspended(),
    S3MFADeleteDisabled(),
    S3LoggingDisabled(),
]

