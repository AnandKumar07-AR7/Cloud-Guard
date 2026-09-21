"""
CloudGuard — RDS Security Rules

All rules are pure Python — no AWS API calls.

Rules implemented:
  RDS-001  RDS instance is publicly accessible                    CRITICAL
  RDS-002  RDS storage encryption disabled                        HIGH
  RDS-003  RDS backup retention period too short                  MEDIUM
  RDS-004  RDS deletion protection disabled                       MEDIUM
"""
from __future__ import annotations

from typing import Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule


# ==============================================================================
# RDS-001 — Publicly Accessible
# ==============================================================================

class RDSPubliclyAccessible(SecurityRule):
    """
    Detects RDS instances with publicly_accessible=True.

    A publicly accessible RDS instance has a DNS endpoint that resolves
    to a public IP, making the database directly reachable from the Internet.
    Databases should never be publicly accessible without a WAF/proxy layer.
    """

    metadata = RuleMetadata(
        rule_id="RDS-001",
        name="RDS Instance Is Publicly Accessible",
        description=(
            "The RDS database instance is configured as publicly accessible. "
            "This means the instance has a DNS endpoint that can resolve to a "
            "public IP address, making it potentially reachable from the Internet. "
            "Databases should only be accessible within a VPC."
        ),
        provider="aws",
        service="rds",
        resource_type="rds_instance",
        severity=Severity.CRITICAL,
        category="network",
        internet_exposure_risk=True,
        data_exposure_risk=True,
        remediation_safety=RemediationSafety.HIGH_IMPACT,
        compliance_mappings=["CIS-2.3.2", "NIST-SC-7", "ISO-A.13.1.3"],
        remediation_template=(
            "1. Open the AWS RDS console.\n"
            "2. Select the instance → Modify.\n"
            "3. Under 'Connectivity', set 'Publicly accessible' to 'No'.\n"
            "4. Apply immediately or during next maintenance window.\n\n"
            "CLI: aws rds modify-db-instance \\\n"
            "  --db-instance-identifier INSTANCE_ID \\\n"
            "  --no-publicly-accessible \\\n"
            "  --apply-immediately\n\n"
            "WARNING: This change may require updating application connection strings."
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
            "https://aws.amazon.com/premiumsupport/knowledge-center/rds-publicly-accessible/",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        publicly_accessible = resource.get_config("publicly_accessible")

        if not publicly_accessible:
            return None

        engine = resource.get_config("engine", "unknown")
        return self._make_finding(
            resource,
            title=f"RDS Instance '{resource.display_name}' is publicly accessible",
            description=(
                f"RDS {engine} instance '{resource.display_name}' is configured with "
                "'publicly_accessible=True'. The database endpoint may resolve to a "
                "public IP address, exposing it to the Internet. Place the database "
                "in a private subnet and set 'Publicly accessible' to No."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.publicly_accessible",
                observed_value=True,
                expected_value=False,
                source="RDS instance configuration",
                details={"engine": engine, "instance_class": resource.get_config("instance_class")},
            ),
        )


# ==============================================================================
# RDS-002 — Storage Encryption Disabled
# ==============================================================================

class RDSEncryptionDisabled(SecurityRule):
    """
    Detects RDS instances with storage encryption disabled.

    Unencrypted RDS storage means that the underlying EBS volumes and
    automated backups are stored in plaintext. Encryption must be enabled
    at creation time; existing instances must be migrated via snapshot.
    """

    metadata = RuleMetadata(
        rule_id="RDS-002",
        name="RDS Instance Storage Encryption Disabled",
        description=(
            "The RDS instance does not have storage encryption enabled. "
            "Unencrypted storage exposes database contents and automated backups "
            "in plaintext, violating data-at-rest encryption requirements."
        ),
        provider="aws",
        service="rds",
        resource_type="rds_instance",
        severity=Severity.HIGH,
        category="encryption",
        data_exposure_risk=True,
        remediation_safety=RemediationSafety.HIGH_IMPACT,
        compliance_mappings=["CIS-2.3.1", "NIST-SC-28", "ISO-A.10.1.1"],
        remediation_template=(
            "Note: Storage encryption cannot be enabled on a running RDS instance.\n\n"
            "Migration steps:\n"
            "1. Create an encrypted snapshot of the current instance.\n"
            "2. Restore a new instance from the encrypted snapshot.\n"
            "3. Update application connection strings to point to the new instance.\n"
            "4. Decommission the unencrypted instance.\n\n"
            "CLI: aws rds create-db-snapshot --db-instance-identifier INSTANCE_ID \\\n"
            "  --db-snapshot-identifier SNAPSHOT_ID"
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        encrypted = resource.get_config("storage_encrypted")

        if encrypted is True:
            return None

        engine = resource.get_config("engine", "unknown")
        return self._make_finding(
            resource,
            title=f"RDS Instance '{resource.display_name}' storage is not encrypted",
            description=(
                f"RDS {engine} instance '{resource.display_name}' does not have "
                "storage encryption enabled. Database data, automated backups, and "
                "read replicas are stored in plaintext on the underlying EBS volumes."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.storage_encrypted",
                observed_value=encrypted,
                expected_value=True,
                source="RDS instance configuration",
                details={"engine": engine},
            ),
        )


# ==============================================================================
# RDS-003 — Insufficient Backup Retention
# ==============================================================================

class RDSBackupRetentionInsufficient(SecurityRule):
    """
    Detects RDS instances with backup retention shorter than 7 days.

    Short backup retention limits recovery options after a security incident
    (e.g., ransomware, accidental deletion). AWS recommends at least 7 days.
    """

    _MIN_RETENTION_DAYS = 7

    metadata = RuleMetadata(
        rule_id="RDS-003",
        name="RDS Instance Backup Retention Period Is Insufficient",
        description=(
            f"The RDS instance has a backup retention period of fewer than 7 days. "
            "Insufficient backup retention limits recovery options after a security "
            "incident, accidental deletion, or data corruption event."
        ),
        provider="aws",
        service="rds",
        resource_type="rds_instance",
        severity=Severity.MEDIUM,
        category="configuration",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-2.3.3", "NIST-CP-9", "ISO-A.12.3.1"],
        remediation_template=(
            "CLI: aws rds modify-db-instance \\\n"
            "  --db-instance-identifier INSTANCE_ID \\\n"
            "  --backup-retention-period 7 \\\n"
            "  --apply-immediately"
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        retention = resource.get_config("backup_retention_period")

        # If not collected or 0 (disabled), flag it
        if retention is None:
            return None  # Cannot determine — don't flag without evidence

        if retention >= self._MIN_RETENTION_DAYS:
            return None

        return self._make_finding(
            resource,
            title=f"RDS Instance '{resource.display_name}' has insufficient backup retention ({retention} days)",
            description=(
                f"RDS instance '{resource.display_name}' has automated backup retention "
                f"set to {retention} day(s), which is below the recommended minimum of "
                f"{self._MIN_RETENTION_DAYS} days. Increase retention to support security "
                "incident investigations and point-in-time recovery."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.backup_retention_period",
                observed_value=retention,
                expected_value=f">= {self._MIN_RETENTION_DAYS} days",
                source="RDS backup configuration",
                details={"min_required": self._MIN_RETENTION_DAYS},
            ),
        )


# ==============================================================================
# RDS-004 — Deletion Protection Disabled
# ==============================================================================

class RDSDeletionProtectionDisabled(SecurityRule):
    """
    Detects RDS instances with deletion protection disabled.

    Without deletion protection, a database can be accidentally or maliciously
    deleted with a single API call. Deletion protection is a simple safeguard
    that requires explicit disabling before the instance can be removed.
    """

    metadata = RuleMetadata(
        rule_id="RDS-004",
        name="RDS Instance Deletion Protection Disabled",
        description=(
            "The RDS instance does not have deletion protection enabled. "
            "Without this safeguard, the database can be accidentally or "
            "maliciously deleted without an additional confirmation step."
        ),
        provider="aws",
        service="rds",
        resource_type="rds_instance",
        severity=Severity.MEDIUM,
        category="configuration",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["NIST-CP-10", "ISO-A.12.3.1"],
        remediation_template=(
            "CLI: aws rds modify-db-instance \\\n"
            "  --db-instance-identifier INSTANCE_ID \\\n"
            "  --deletion-protection \\\n"
            "  --apply-immediately"
        ),
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        deletion_protection = resource.get_config("deletion_protection")

        if deletion_protection is True:
            return None

        return self._make_finding(
            resource,
            title=f"RDS Instance '{resource.display_name}' has deletion protection disabled",
            description=(
                f"RDS instance '{resource.display_name}' does not have deletion protection "
                "enabled. This means the instance can be deleted with a single API call or "
                "console action. Enable deletion protection to prevent accidental or "
                "unauthorized database removal."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.deletion_protection",
                observed_value=deletion_protection,
                expected_value=True,
                source="RDS instance configuration",
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

RDS_RULES: list[SecurityRule] = [
    RDSPubliclyAccessible(),
    RDSEncryptionDisabled(),
    RDSBackupRetentionInsufficient(),
    RDSDeletionProtectionDisabled(),
]
