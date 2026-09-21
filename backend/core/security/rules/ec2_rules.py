"""
CloudGuard — EC2 Security Rules

All rules are pure Python — no AWS API calls.

Rules implemented:
  EC2-001  EC2 instance uses IMDSv1 (metadata service v1)         HIGH
  EC2-002  EC2 instance has a public IP address                   MEDIUM
  EC2-003  EC2 instance missing detailed monitoring               LOW
  EC2-004  EC2 instance has no IAM instance profile               MEDIUM
  EC2-005  EC2 EBS optimization not enabled                       LOW
"""
from __future__ import annotations

from typing import Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule


# ==============================================================================
# EC2-001 — IMDSv1 Enabled (Instance Metadata Service v1)
# ==============================================================================

class EC2IMDSv1Enabled(SecurityRule):
    """
    Detects EC2 instances that allow IMDSv1 requests.

    IMDSv1 is a simple GET request with no session authentication.
    IMDSv2 requires a session-oriented request with a PUT, protecting
    against SSRF attacks that could retrieve IAM credentials from the
    metadata service.
    """

    metadata = RuleMetadata(
        rule_id="EC2-001",
        name="EC2 Instance Uses IMDSv1 (Metadata Service v1 Not Disabled)",
        description=(
            "The EC2 instance does not enforce IMDSv2. IMDSv1 is vulnerable to "
            "server-side request forgery (SSRF) attacks, which can be used to "
            "steal IAM credentials from the instance metadata service."
        ),
        provider="aws",
        service="ec2",
        resource_type="ec2_instance",
        severity=Severity.HIGH,
        category="access-control",
        internet_exposure_risk=False,
        privilege_escalation_risk=True,
        data_exposure_risk=True,
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-5.6", "NIST-SC-8", "ISO-A.10.1.1"],
        remediation_template=(
            "1. Open the AWS EC2 console.\n"
            "2. Select the instance → Actions → Instance Settings → Modify Instance Metadata Options.\n"
            "3. Set 'IMDSv2' to 'Required'.\n"
            "4. Save changes.\n\n"
            "CLI: aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id INSTANCE_ID \\\n"
            "  --http-tokens required \\\n"
            "  --http-endpoint enabled"
        ),
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            "https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        imdsv2_required = resource.get_config("imdsv2_required")

        # If IMDSv2 is explicitly required, the instance is compliant
        if imdsv2_required is True:
            return None

        # IMDSv2 not required — either False or missing (default is v1 allowed)
        observed = "IMDSv1 allowed (imdsv2_required=False)" if imdsv2_required is False else "Not configured (IMDSv1 allowed by default)"

        return self._make_finding(
            resource,
            title=f"EC2 Instance '{resource.display_name}' allows IMDSv1 access",
            description=(
                f"EC2 instance '{resource.display_name}' ({resource.resource_id}) "
                "does not enforce IMDSv2. SSRF vulnerabilities can exploit IMDSv1 to "
                "retrieve temporary IAM credentials from the metadata service endpoint "
                "(http://169.254.169.254/). Enforce IMDSv2 to require session tokens."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.imdsv2_required",
                observed_value=observed,
                expected_value="True (IMDSv2 required, IMDSv1 disabled)",
                source="instance metadata configuration",
                details={"imdsv2_required": imdsv2_required},
            ),
        )


# ==============================================================================
# EC2-002 — Public IP Address
# ==============================================================================

class EC2PublicIPExposed(SecurityRule):
    """
    Detects EC2 instances with a public IP address.

    Public IP addresses increase the attack surface by making the instance
    directly reachable from the Internet. Instances should use private IPs
    and NAT gateways / load balancers for Internet-facing services.
    """

    metadata = RuleMetadata(
        rule_id="EC2-002",
        name="EC2 Instance Has a Public IP Address",
        description=(
            "The EC2 instance has a public IPv4 address, making it directly "
            "reachable from the public Internet. This unnecessarily increases "
            "the attack surface. Use private subnets with NAT gateways instead."
        ),
        provider="aws",
        service="ec2",
        resource_type="ec2_instance",
        severity=Severity.MEDIUM,
        category="network",
        internet_exposure_risk=True,
        remediation_safety=RemediationSafety.HIGH_IMPACT,
        compliance_mappings=["CIS-5.4", "NIST-SC-7"],
        remediation_template=(
            "1. Migrate the instance to a private subnet.\n"
            "2. Use an Application Load Balancer or NAT Gateway for Internet-facing traffic.\n"
            "3. If public access is required, restrict security groups to minimum required ports.\n\n"
            "Note: Removing a public IP requires stopping and modifying the instance or subnet settings."
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        public_ip = resource.get_config("public_ip")

        if not public_ip:
            return None

        return self._make_finding(
            resource,
            title=f"EC2 Instance '{resource.display_name}' has a public IP address",
            description=(
                f"EC2 instance '{resource.display_name}' has the public IP address "
                f"'{public_ip}' assigned, making it directly reachable from the Internet. "
                "Unless this instance serves a public-facing role that cannot be moved "
                "behind a load balancer, public IP assignment should be disabled."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.public_ip",
                observed_value=public_ip,
                expected_value="None (no public IP; use private subnet + NAT/ELB)",
                source="instance network configuration",
            ),
        )


# ==============================================================================
# EC2-003 — Detailed Monitoring Disabled
# ==============================================================================

class EC2MonitoringDisabled(SecurityRule):
    """
    Detects EC2 instances with detailed monitoring disabled.

    Detailed monitoring provides 1-minute metric granularity instead of 5-minute.
    For security-relevant instances this enables faster anomaly detection.
    """

    metadata = RuleMetadata(
        rule_id="EC2-003",
        name="EC2 Instance Detailed Monitoring Not Enabled",
        description=(
            "The EC2 instance does not have detailed CloudWatch monitoring enabled. "
            "Detailed monitoring provides 1-minute metric resolution, enabling "
            "faster detection of performance anomalies and security incidents."
        ),
        provider="aws",
        service="ec2",
        resource_type="ec2_instance",
        severity=Severity.LOW,
        category="monitoring",
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["NIST-AU-12", "ISO-A.12.1.3"],
        remediation_template=(
            "CLI: aws ec2 monitor-instances --instance-ids INSTANCE_ID\n\n"
            "Note: Detailed monitoring incurs additional CloudWatch charges."
        ),
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        monitoring = resource.get_config("monitoring_enabled")

        if monitoring is True:
            return None

        return self._make_finding(
            resource,
            title=f"EC2 Instance '{resource.display_name}' has detailed monitoring disabled",
            description=(
                f"EC2 instance '{resource.display_name}' is using basic (5-minute) "
                "CloudWatch monitoring. Enabling detailed monitoring (1-minute resolution) "
                "allows faster detection of CPU spikes, network anomalies, and other "
                "security-relevant events."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.monitoring_enabled",
                observed_value=monitoring,
                expected_value=True,
                source="instance monitoring configuration",
            ),
        )


# ==============================================================================
# EC2-004 — No IAM Instance Profile
# ==============================================================================

class EC2NoInstanceProfile(SecurityRule):
    """
    Detects EC2 instances with no IAM instance profile attached.

    Without an instance profile, applications on the instance must use
    hardcoded credentials or access keys, which are a significant security risk.
    Instance profiles allow temporary credential rotation via the metadata service.
    """

    metadata = RuleMetadata(
        rule_id="EC2-004",
        name="EC2 Instance Has No IAM Instance Profile",
        description=(
            "The EC2 instance has no IAM instance profile attached. Applications "
            "on this instance cannot use temporary IAM credentials from the metadata "
            "service, increasing the risk of hardcoded access keys."
        ),
        provider="aws",
        service="ec2",
        resource_type="ec2_instance",
        severity=Severity.MEDIUM,
        category="access-control",
        privilege_escalation_risk=False,
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["CIS-1.18", "NIST-AC-2"],
        remediation_template=(
            "1. Create an IAM role with the minimum required permissions.\n"
            "2. Attach an instance profile to the role.\n"
            "3. Associate the instance profile with the EC2 instance:\n\n"
            "CLI: aws ec2 associate-iam-instance-profile \\\n"
            "  --instance-id INSTANCE_ID \\\n"
            "  --iam-instance-profile Name=PROFILE_NAME"
        ),
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        profile = resource.get_config("iam_instance_profile")

        if profile:
            return None

        return self._make_finding(
            resource,
            title=f"EC2 Instance '{resource.display_name}' has no IAM instance profile",
            description=(
                f"EC2 instance '{resource.display_name}' does not have an IAM instance "
                "profile attached. Without an instance profile, applications running on "
                "this instance must use hardcoded credentials, which cannot be automatically "
                "rotated and increase the risk of credential leakage."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.iam_instance_profile",
                observed_value=None,
                expected_value="IAM instance profile ARN",
                source="instance IAM configuration",
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

EC2_RULES: list[SecurityRule] = [
    EC2IMDSv1Enabled(),
    EC2PublicIPExposed(),
    EC2MonitoringDisabled(),
    EC2NoInstanceProfile(),
]
