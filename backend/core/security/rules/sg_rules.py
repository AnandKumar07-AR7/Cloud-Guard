"""
CloudGuard — Security Group Rules

Migrated and expanded from cloudguard-copilot-main detectors/sg_detector.py.
All rules are pure Python — no AWS API calls.

Rules implemented:
  SG-001  SSH (22) open to 0.0.0.0/0 or ::/0                    HIGH
  SG-002  RDP (3389) open to 0.0.0.0/0 or ::/0                   HIGH
  SG-003  All traffic open to Internet (-1)                       CRITICAL
  SG-004  Database port open to Internet (MySQL 3306)             CRITICAL
  SG-005  Database port open to Internet (PostgreSQL 5432)        CRITICAL
  SG-006  Database port open to Internet (MSSQL 1433)             CRITICAL
  SG-007  NoSQL/cache port open to Internet (Redis 6379)          HIGH
  SG-008  NoSQL/cache port open to Internet (Elasticsearch 9200)  HIGH
"""
from __future__ import annotations

from typing import List, Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule

_INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_open_to_internet(rule: dict) -> bool:
    """Return True if an inbound rule is open to the entire internet."""
    cidr = rule.get("cidr", "")
    return cidr in _INTERNET_CIDRS


def _get_inbound_rules_for_port(resource: CloudResource, port: int) -> List[dict]:
    """Return all inbound rules that include the specified port."""
    matching = []
    for rule in resource.get_config("inbound_rules", []):
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 65535)
        protocol = rule.get("protocol", "-1")
        # -1 means all traffic
        if protocol == "-1" or (from_port <= port <= to_port):
            matching.append(rule)
    return matching


# ==============================================================================
# SG-001 — SSH Open to Internet
# ==============================================================================

class SGSSHOpenToInternet(SecurityRule):
    """
    Detects security groups that allow inbound SSH (port 22) from the Internet.
    Open SSH access is a critical exposure — it enables brute-force attacks
    and unauthorized remote access.
    """

    metadata = RuleMetadata(
        rule_id="SG-001",
        name="Security Group Allows SSH (Port 22) from Internet",
        description=(
            "The security group allows inbound SSH traffic (port 22) from any IP "
            "address (0.0.0.0/0 or ::/0). This exposes the resource to brute-force "
            "attacks and unauthorized access from the public internet."
        ),
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.HIGH,
        internet_exposure_risk=True,
        compliance_mappings=["CIS-5.2", "NIST-SC-7", "ISO-A.13.1.1"],
        remediation_template=(
            "1. Open the AWS EC2 console → Security Groups.\n"
            "2. Select the security group.\n"
            "3. Edit inbound rules.\n"
            "4. Find the SSH rule (port 22, 0.0.0.0/0).\n"
            "5. Restrict the source to your IP or VPN CIDR.\n"
            "6. Consider using AWS Systems Manager Session Manager instead of SSH.\n\n"
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID \\\n"
            "  --protocol tcp --port 22 --cidr 0.0.0.0/0"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        ssh_rules = _get_inbound_rules_for_port(resource, 22)
        open_rules = [r for r in ssh_rules if _is_open_to_internet(r)]

        if open_rules:
            return self._make_finding(
                resource,
                title=f"Security Group '{resource.display_name}' allows SSH from Internet",
                description=(
                    f"Security group '{resource.display_name}' allows inbound SSH "
                    f"(port 22) from {', '.join(r['cidr'] for r in open_rules)}. "
                    "This exposes any attached instances to brute-force attacks."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=[{"port": 22, "cidr": r["cidr"]} for r in open_rules],
                    expected_value="Specific CIDR (not 0.0.0.0/0)",
                    field_path="config.inbound_rules[port=22].cidr",
                    details={"open_rule_count": len(open_rules)},
                ),
            )
        return None


# ==============================================================================
# SG-002 — RDP Open to Internet
# ==============================================================================

class SGRDPOpenToInternet(SecurityRule):
    """
    Detects security groups that allow inbound RDP (port 3389) from the Internet.
    """

    metadata = RuleMetadata(
        rule_id="SG-002",
        name="Security Group Allows RDP (Port 3389) from Internet",
        description=(
            "The security group allows inbound RDP traffic (port 3389) from any IP. "
            "Open RDP is a major attack vector for ransomware and unauthorized access."
        ),
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.HIGH,
        internet_exposure_risk=True,
        compliance_mappings=["CIS-5.3", "NIST-SC-7"],
        remediation_template=(
            "1. Open the AWS EC2 console → Security Groups.\n"
            "2. Edit inbound rules for the security group.\n"
            "3. Restrict the RDP rule (port 3389) to your specific IP or VPN CIDR.\n"
            "4. Consider using AWS Systems Manager Fleet Manager for Windows access.\n\n"
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID \\\n"
            "  --protocol tcp --port 3389 --cidr 0.0.0.0/0"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        rdp_rules = _get_inbound_rules_for_port(resource, 3389)
        open_rules = [r for r in rdp_rules if _is_open_to_internet(r)]

        if open_rules:
            return self._make_finding(
                resource,
                title=f"Security Group '{resource.display_name}' allows RDP from Internet",
                description=(
                    f"Security group '{resource.display_name}' allows inbound RDP "
                    f"(port 3389) from {', '.join(r['cidr'] for r in open_rules)}. "
                    "This is a primary ransomware vector."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=[{"port": 3389, "cidr": r["cidr"]} for r in open_rules],
                    expected_value="Specific CIDR (not 0.0.0.0/0)",
                    field_path="config.inbound_rules[port=3389].cidr",
                ),
            )
        return None


# ==============================================================================
# SG-003 — All Traffic Open to Internet
# ==============================================================================

class SGAllTrafficOpenToInternet(SecurityRule):
    """
    Detects security groups that allow ALL inbound traffic from the Internet.
    This is the most severe security group misconfiguration — it allows
    any protocol and port from any IP address.
    """

    metadata = RuleMetadata(
        rule_id="SG-003",
        name="Security Group Allows All Traffic from Internet",
        description=(
            "The security group has an inbound rule allowing ALL traffic (protocol -1) "
            "from 0.0.0.0/0. This provides no network perimeter protection."
        ),
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.CRITICAL,
        internet_exposure_risk=True,
        compliance_mappings=["CIS-5.1", "NIST-SC-7"],
        remediation_template=(
            "1. Immediately remove the all-traffic inbound rule.\n"
            "2. Replace with specific rules for required ports only.\n"
            "3. Restrict source CIDRs to known IP ranges.\n\n"
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol -1 --cidr 0.0.0.0/0"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        open_all = []
        for rule in resource.get_config("inbound_rules", []):
            if rule.get("protocol") == "-1" and _is_open_to_internet(rule):
                open_all.append(rule)

        if open_all:
            return self._make_finding(
                resource,
                title=f"Security Group '{resource.display_name}' allows ALL traffic from Internet",
                description=(
                    f"CRITICAL: Security group '{resource.display_name}' allows ALL "
                    "inbound traffic from the public Internet (protocol -1, 0.0.0.0/0). "
                    "This provides no network perimeter protection."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=[{"protocol": "-1", "cidr": r["cidr"]} for r in open_all],
                    expected_value="No all-traffic inbound rule from 0.0.0.0/0",
                    field_path="config.inbound_rules[protocol=-1].cidr",
                ),
            )
        return None


# ==============================================================================
# Database Port Rules (SG-004 through SG-006)
# ==============================================================================

class _DBPortOpenToInternet(SecurityRule):
    """Base class for database port exposure rules."""

    _PORT: int
    _DB_NAME: str

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        rules = _get_inbound_rules_for_port(resource, self._PORT)
        open_rules = [r for r in rules if _is_open_to_internet(r)]

        if open_rules:
            return self._make_finding(
                resource,
                title=(
                    f"Security Group '{resource.display_name}' exposes {self._DB_NAME} "
                    f"port {self._PORT} to Internet"
                ),
                description=(
                    f"Security group '{resource.display_name}' allows inbound {self._DB_NAME} "
                    f"traffic (port {self._PORT}) from the public Internet. Database ports "
                    "must never be directly exposed to the Internet."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=[{"port": self._PORT, "cidr": r["cidr"]} for r in open_rules],
                    expected_value=f"Port {self._PORT} not reachable from 0.0.0.0/0",
                    field_path=f"config.inbound_rules[port={self._PORT}].cidr",
                ),
            )
        return None


class SGMySQLOpenToInternet(_DBPortOpenToInternet):
    """MySQL/Aurora (port 3306) open to Internet."""

    _PORT = 3306
    _DB_NAME = "MySQL/Aurora"

    metadata = RuleMetadata(
        rule_id="SG-004",
        name="Security Group Exposes MySQL (Port 3306) to Internet",
        description="MySQL/Aurora port 3306 is accessible from the public Internet.",
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.CRITICAL,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["CIS-5.5", "NIST-SC-7", "PCI-DSS-1.3"],
        remediation_template=(
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol tcp --port 3306 --cidr 0.0.0.0/0"
        ),
    )


class SGPostgresOpenToInternet(_DBPortOpenToInternet):
    """PostgreSQL (port 5432) open to Internet."""

    _PORT = 5432
    _DB_NAME = "PostgreSQL"

    metadata = RuleMetadata(
        rule_id="SG-005",
        name="Security Group Exposes PostgreSQL (Port 5432) to Internet",
        description="PostgreSQL port 5432 is accessible from the public Internet.",
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.CRITICAL,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["CIS-5.5", "NIST-SC-7"],
        remediation_template=(
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol tcp --port 5432 --cidr 0.0.0.0/0"
        ),
    )


class SGRedisOpenToInternet(_DBPortOpenToInternet):
    """Redis (port 6379) open to Internet."""

    _PORT = 6379
    _DB_NAME = "Redis"

    metadata = RuleMetadata(
        rule_id="SG-006",
        name="Security Group Exposes Redis (Port 6379) to Internet",
        description="Redis cache port 6379 is accessible from the public Internet.",
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.HIGH,
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["NIST-SC-7"],
        remediation_template=(
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol tcp --port 6379 --cidr 0.0.0.0/0"
        ),
    )


# ==============================================================================
# SG-007 — MongoDB (27017) Open to Internet
# ==============================================================================

class SGMongoDBOpenToInternet(_DBPortOpenToInternet):
    """MongoDB/DocumentDB (port 27017) open to Internet."""

    _PORT = 27017
    _DB_NAME = "MongoDB"

    metadata = RuleMetadata(
        rule_id="SG-007",
        name="Security Group Exposes MongoDB (Port 27017) to Internet",
        description=(
            "MongoDB port 27017 is accessible from the public Internet. "
            "Exposed MongoDB instances have been a major source of data breaches "
            "when authentication is weak or disabled."
        ),
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.CRITICAL,
        category="network",
        internet_exposure_risk=True,
        data_exposure_risk=True,
        compliance_mappings=["NIST-SC-7", "CIS-5.2"],
        remediation_template=(
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol tcp --port 27017 --cidr 0.0.0.0/0"
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        ],
    )


# ==============================================================================
# SG-008 — Telnet (23) Open to Internet
# ==============================================================================

class SGTelnetOpenToInternet(_DBPortOpenToInternet):
    """Telnet (port 23) open to Internet — unencrypted remote access."""

    _PORT = 23
    _DB_NAME = "Telnet"

    metadata = RuleMetadata(
        rule_id="SG-008",
        name="Security Group Allows Telnet (Port 23) from Internet",
        description=(
            "Telnet (port 23) is accessible from the public Internet. "
            "Telnet transmits data in plaintext including credentials. "
            "Replace with SSH or other encrypted alternatives."
        ),
        provider="aws",
        service="ec2",
        resource_type="security_group",
        severity=Severity.HIGH,
        category="network",
        internet_exposure_risk=True,
        compliance_mappings=["CIS-5.2", "NIST-SC-8"],
        remediation_template=(
            "CLI: aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id SG_ID --protocol tcp --port 23 --cidr 0.0.0.0/0"
        ),
        references=[
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        ],
    )


# ==============================================================================
# Rule Registry
# ==============================================================================

SG_RULES: list[SecurityRule] = [
    SGSSHOpenToInternet(),
    SGRDPOpenToInternet(),
    SGAllTrafficOpenToInternet(),
    SGMySQLOpenToInternet(),
    SGPostgresOpenToInternet(),
    SGRedisOpenToInternet(),
    SGMongoDBOpenToInternet(),
    SGTelnetOpenToInternet(),
]
