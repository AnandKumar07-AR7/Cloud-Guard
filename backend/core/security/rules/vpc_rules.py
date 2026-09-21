"""
CloudGuard — VPC Security Rules

All rules are pure Python — no AWS API calls.

Rules implemented:
  VPC-001  VPC flow logs not enabled                              HIGH
  VPC-002  Default VPC in use                                     MEDIUM
  VPC-003  VPC DNS hostnames disabled                             LOW
"""
from __future__ import annotations

from typing import Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule


# ==============================================================================
# VPC-001 — Flow Logs Not Enabled
# ==============================================================================

class VPCFlowLogsDisabled(SecurityRule):
    """
    Detects VPCs that do not have flow logs enabled.

    VPC flow logs capture IP traffic information for network interfaces.
    Without flow logs, network-based attacks (reconnaissance, lateral movement,
    exfiltration) leave no audit trail. Flow logs are essential for incident
    response and compliance.
    """

    metadata = RuleMetadata(
        rule_id="VPC-001",
        name="VPC Flow Logs Not Enabled",
        description=(
            "VPC flow logs are not enabled for this VPC. Flow logs capture network "
            "traffic metadata for all interfaces within the VPC, enabling detection "
            "of anomalous traffic patterns, data exfiltration, and lateral movement. "
            "Without flow logs, network-based security incidents cannot be investigated."
        ),
        provider="aws",
        service="vpc",
        resource_type="vpc",
        severity=Severity.HIGH,
        category="logging",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-3.9", "NIST-AU-2", "ISO-A.12.4.1"],
        remediation_template=(
            "1. Open the AWS VPC console.\n"
            "2. Select the VPC → Flow Logs → Create Flow Log.\n"
            "3. Configure destination (CloudWatch Logs or S3).\n"
            "4. Select 'All' traffic type.\n\n"
            "CLI: aws ec2 create-flow-logs \\\n"
            "  --resource-type VPC \\\n"
            "  --resource-ids VPC_ID \\\n"
            "  --traffic-type ALL \\\n"
            "  --log-destination-type cloud-watch-logs \\\n"
            "  --log-group-name /aws/vpc/flowlogs \\\n"
            "  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT:role/flowlogsrole"
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        flow_logs_enabled = resource.get_config("flow_logs_enabled")

        if flow_logs_enabled is True:
            return None

        return self._make_finding(
            resource,
            title=f"VPC '{resource.display_name}' does not have flow logs enabled",
            description=(
                f"VPC '{resource.display_name}' ({resource.resource_id}) does not have "
                "VPC flow logs enabled. Network traffic within this VPC is not being "
                "logged. Enable flow logs to CloudWatch Logs or S3 to capture traffic "
                "metadata for security monitoring and incident investigation."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.flow_logs_enabled",
                observed_value=flow_logs_enabled,
                expected_value=True,
                source="VPC configuration",
                details={"cidr_block": resource.get_config("cidr_block")},
            ),
        )


# ==============================================================================
# VPC-002 — Default VPC In Use
# ==============================================================================

class VPCDefaultVPCInUse(SecurityRule):
    """
    Detects that the default VPC exists and is potentially in use.

    The default VPC has permissive settings created for convenience,
    not security. All subnets in the default VPC auto-assign public IPs.
    Production workloads should use custom VPCs with explicit configurations.
    """

    metadata = RuleMetadata(
        rule_id="VPC-002",
        name="Default VPC Is Present and May Be In Use",
        description=(
            "This is the AWS default VPC. Default VPCs have permissive network "
            "settings including auto-assign public IPs for all subnets. Production "
            "workloads should not use the default VPC. Custom VPCs provide explicit "
            "control over network topology and routing."
        ),
        provider="aws",
        service="vpc",
        resource_type="vpc",
        severity=Severity.MEDIUM,
        category="network",
        internet_exposure_risk=True,
        remediation_safety=RemediationSafety.HIGH_IMPACT,
        compliance_mappings=["CIS-5.4", "NIST-SC-7"],
        remediation_template=(
            "1. Ensure no production workloads are deployed in the default VPC.\n"
            "2. Migrate all resources to a custom VPC.\n"
            "3. Delete the default VPC (optional, irreversible):\n\n"
            "CLI: aws ec2 delete-vpc --vpc-id VPC_ID\n\n"
            "WARNING: Deleting the default VPC is not easily reversible."
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        is_default = resource.get_config("is_default")

        if not is_default:
            return None

        return self._make_finding(
            resource,
            title=f"Default VPC '{resource.display_name}' is present",
            description=(
                f"VPC '{resource.display_name}' ({resource.resource_id}) is the default VPC. "
                "Default VPCs have all subnets configured to auto-assign public IPv4 addresses, "
                "which increases exposure risk. Production workloads should use purpose-built "
                "VPCs with explicit network access controls."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.is_default",
                observed_value=True,
                expected_value=False,
                source="VPC configuration",
                details={"cidr_block": resource.get_config("cidr_block")},
            ),
        )


# ==============================================================================
# VPC-003 — DNS Hostnames Disabled
# ==============================================================================

class VPCDNSHostnamesDisabled(SecurityRule):
    """
    Detects VPCs with DNS hostname support disabled.

    While not directly a security vulnerability, disabling DNS hostnames
    hinders audit logging quality (logs show IP addresses instead of hostnames)
    and can complicate security tooling that relies on hostname-based filtering.
    """

    metadata = RuleMetadata(
        rule_id="VPC-003",
        name="VPC DNS Hostname Support Disabled",
        description=(
            "DNS hostname support is disabled for this VPC. This means EC2 instances "
            "will not receive public DNS hostnames, which can complicate network "
            "visibility, security monitoring, and audit logging."
        ),
        provider="aws",
        service="vpc",
        resource_type="vpc",
        severity=Severity.LOW,
        category="configuration",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=[],
        remediation_template=(
            "CLI: aws ec2 modify-vpc-attribute \\\n"
            "  --vpc-id VPC_ID \\\n"
            "  --enable-dns-hostnames"
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        dns_hostnames = resource.get_config("enable_dns_hostnames")
        dns_support = resource.get_config("enable_dns_support")

        # Only flag if DNS is explicitly disabled (not missing data)
        if dns_hostnames is None and dns_support is None:
            return None  # Cannot determine — no evidence

        if dns_hostnames is True:
            return None

        return self._make_finding(
            resource,
            title=f"VPC '{resource.display_name}' has DNS hostname support disabled",
            description=(
                f"VPC '{resource.display_name}' does not have DNS hostname support enabled. "
                "Instances in this VPC will not have DNS hostnames assigned, which reduces "
                "network visibility and can complicate security monitoring."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.enable_dns_hostnames",
                observed_value=dns_hostnames,
                expected_value=True,
                source="VPC DNS configuration",
                details={"enable_dns_support": dns_support},
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

VPC_RULES: list[SecurityRule] = [
    VPCFlowLogsDisabled(),
    VPCDefaultVPCInUse(),
    VPCDNSHostnamesDisabled(),
]
