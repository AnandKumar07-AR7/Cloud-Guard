"""
CloudGuard — CloudTrail Security Rules

All rules are pure Python — no AWS API calls.

Rules implemented:
  CT-001  CloudTrail logging is disabled                          CRITICAL
  CT-002  CloudTrail log file validation disabled                 HIGH
  CT-003  CloudTrail trail is not multi-region                    MEDIUM
  CT-004  CloudTrail logs not encrypted with KMS                  MEDIUM
"""
from __future__ import annotations

from typing import Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule


# ==============================================================================
# CT-001 — CloudTrail Logging Disabled
# ==============================================================================

class CloudTrailLoggingDisabled(SecurityRule):
    """
    Detects CloudTrail trails that are not actively logging.

    If CloudTrail logging is disabled, API activity in the AWS account
    is not being recorded. This eliminates the audit trail needed to detect
    unauthorized access, data exfiltration, and configuration changes.
    """

    metadata = RuleMetadata(
        rule_id="CT-001",
        name="CloudTrail Logging Is Disabled",
        description=(
            "The CloudTrail trail is not actively logging. All API activity in the "
            "AWS account is unrecorded, eliminating the audit trail required for "
            "security incident investigation, compliance, and breach detection."
        ),
        provider="aws",
        service="cloudtrail",
        resource_type="cloudtrail",
        severity=Severity.CRITICAL,
        category="logging",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-3.1", "NIST-AU-2", "ISO-A.12.4.1"],
        remediation_template=(
            "CLI: aws cloudtrail start-logging --name TRAIL_NAME\n\n"
            "Console: CloudTrail → Trails → select trail → Start Logging."
        ),
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        is_logging = resource.get_config("is_logging")

        if is_logging is None:
            return None  # Cannot determine without data

        if is_logging is True:
            return None

        trail_name = resource.get_config("trail_name", resource.display_name)
        return self._make_finding(
            resource,
            title=f"CloudTrail trail '{trail_name}' has logging disabled",
            description=(
                f"CloudTrail trail '{trail_name}' is not actively logging. "
                "AWS API calls, console sign-ins, and service events are not being "
                "recorded. This creates a blind spot for security incident detection "
                "and prevents post-incident forensic analysis."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.is_logging",
                observed_value=False,
                expected_value=True,
                source="CloudTrail trail configuration",
                details={"trail_name": trail_name},
            ),
        )


# ==============================================================================
# CT-002 — Log File Validation Disabled
# ==============================================================================

class CloudTrailLogValidationDisabled(SecurityRule):
    """
    Detects CloudTrail trails without log file integrity validation.

    Log file validation uses SHA-256 hashing and digital signatures to verify
    that CloudTrail log files have not been modified or deleted after delivery.
    Without this, an attacker who gains access to the log storage could tamper
    with evidence without detection.
    """

    metadata = RuleMetadata(
        rule_id="CT-002",
        name="CloudTrail Log File Integrity Validation Disabled",
        description=(
            "CloudTrail log file integrity validation is not enabled for this trail. "
            "Without validation, log files can be modified or deleted after delivery "
            "to S3 without detection, undermining the forensic value of audit logs."
        ),
        provider="aws",
        service="cloudtrail",
        resource_type="cloudtrail",
        severity=Severity.HIGH,
        category="logging",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-3.2", "NIST-AU-10", "ISO-A.12.4.3"],
        remediation_template=(
            "CLI: aws cloudtrail update-trail \\\n"
            "  --name TRAIL_NAME \\\n"
            "  --enable-log-file-validation\n\n"
            "Console: CloudTrail → Trails → select trail → Edit → Enable log file validation."
        ),
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        validation_enabled = resource.get_config("log_file_validation_enabled")

        if validation_enabled is None:
            return None  # Cannot determine

        if validation_enabled is True:
            return None

        trail_name = resource.get_config("trail_name", resource.display_name)
        return self._make_finding(
            resource,
            title=f"CloudTrail trail '{trail_name}' log file validation is disabled",
            description=(
                f"CloudTrail trail '{trail_name}' does not have log file integrity validation "
                "enabled. An attacker with write access to the S3 bucket could modify or "
                "delete log files to cover their tracks. Enable validation to detect tampering."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.log_file_validation_enabled",
                observed_value=False,
                expected_value=True,
                source="CloudTrail trail configuration",
                details={"trail_name": trail_name},
            ),
        )


# ==============================================================================
# CT-003 — Trail Is Not Multi-Region
# ==============================================================================

class CloudTrailNotMultiRegion(SecurityRule):
    """
    Detects CloudTrail trails that only cover a single region.

    A single-region trail only captures activity in its configured region.
    Multi-region trails capture API activity across all regions including
    global services (IAM, STS, CloudFront), providing complete coverage.
    """

    metadata = RuleMetadata(
        rule_id="CT-003",
        name="CloudTrail Trail Does Not Cover All Regions",
        description=(
            "The CloudTrail trail is not configured as a multi-region trail. "
            "Single-region trails only capture API activity in one region, "
            "leaving activity in other regions unlogged. Global services "
            "(IAM, STS, Route53) may not be captured."
        ),
        provider="aws",
        service="cloudtrail",
        resource_type="cloudtrail",
        severity=Severity.MEDIUM,
        category="logging",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-3.1", "NIST-AU-2"],
        remediation_template=(
            "CLI: aws cloudtrail update-trail \\\n"
            "  --name TRAIL_NAME \\\n"
            "  --is-multi-region-trail\n\n"
            "Note: Multi-region trails may increase storage costs."
        ),
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        is_multi_region = resource.get_config("is_multi_region")

        if is_multi_region is None:
            return None  # Cannot determine

        if is_multi_region is True:
            return None

        trail_name = resource.get_config("trail_name", resource.display_name)
        return self._make_finding(
            resource,
            title=f"CloudTrail trail '{trail_name}' does not cover all regions",
            description=(
                f"CloudTrail trail '{trail_name}' is not a multi-region trail. "
                "API activity in regions other than the trail's home region is not "
                "being captured. An attacker could perform actions in other regions "
                "without generating an audit trail."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.is_multi_region",
                observed_value=False,
                expected_value=True,
                source="CloudTrail trail configuration",
                details={"trail_name": trail_name},
            ),
        )


# ==============================================================================
# CT-004 — CloudTrail Logs Not KMS Encrypted
# ==============================================================================

class CloudTrailNotKMSEncrypted(SecurityRule):
    """
    Detects CloudTrail trails whose S3 log delivery is not encrypted with KMS.

    By default, CloudTrail log files are encrypted with SSE-S3 (AES-256).
    Using a KMS CMK provides additional control: key rotation, access policies,
    CloudTrail events for key usage, and the ability to revoke access.
    """

    metadata = RuleMetadata(
        rule_id="CT-004",
        name="CloudTrail Logs Not Encrypted with KMS Customer-Managed Key",
        description=(
            "The CloudTrail trail does not use a KMS Customer-Managed Key (CMK) "
            "to encrypt log files. While S3 server-side encryption is applied by default, "
            "KMS CMK encryption provides additional audit controls, key rotation, "
            "and fine-grained access management."
        ),
        provider="aws",
        service="cloudtrail",
        resource_type="cloudtrail",
        severity=Severity.MEDIUM,
        category="encryption",
        remediation_safety=RemediationSafety.REVIEW_REQUIRED,
        compliance_mappings=["CIS-3.7", "NIST-SC-28", "ISO-A.10.1.1"],
        remediation_template=(
            "1. Create or identify an existing KMS CMK for CloudTrail.\n"
            "2. Update the KMS key policy to allow CloudTrail access.\n\n"
            "CLI: aws cloudtrail update-trail \\\n"
            "  --name TRAIL_NAME \\\n"
            "  --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
        ),
        references=[
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        kms_key_id = resource.get_config("kms_key_id")

        # If KMS key is configured, trail is compliant
        if kms_key_id:
            return None

        # Only flag if we can confirm KMS is absent (not if config is missing)
        is_logging = resource.get_config("is_logging")
        if is_logging is None:
            return None  # Incomplete config — skip

        trail_name = resource.get_config("trail_name", resource.display_name)
        return self._make_finding(
            resource,
            title=f"CloudTrail trail '{trail_name}' logs are not KMS encrypted",
            description=(
                f"CloudTrail trail '{trail_name}' does not use a KMS Customer-Managed Key "
                "to encrypt log files. While S3 SSE is applied by default, using a CMK "
                "provides key rotation, audit logging of key usage, and explicit access "
                "control over who can decrypt the audit trail."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.kms_key_id",
                observed_value=None,
                expected_value="KMS CMK ARN (arn:aws:kms:...)",
                source="CloudTrail encryption configuration",
                details={"trail_name": trail_name},
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

CLOUDTRAIL_RULES: list[SecurityRule] = [
    CloudTrailLoggingDisabled(),
    CloudTrailLogValidationDisabled(),
    CloudTrailNotMultiRegion(),
    CloudTrailNotKMSEncrypted(),
]
