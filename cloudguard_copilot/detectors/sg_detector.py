"""
Security Group misconfiguration detector.
"""

from typing import List, Dict, Any
import uuid
import logging

from cloudguard_copilot.utils.normalization import is_public_cidr

logger = logging.getLogger(__name__)


# High-risk ports that should not be exposed to the internet
HIGH_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana"
}


def detect_sg_misconfigurations(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect misconfigurations in Security Group resources.

    Args:
        resources: List of normalized security group resources

    Returns:
        List of findings
    """
    findings = []

    for resource in resources:
        if resource.get("resource_type") != "security_group":
            continue

        config = resource.get("config", {})

        # Check inbound rules for public access
        inbound_findings = _check_inbound_rules(resource)
        findings.extend(inbound_findings)

    logger.info(f"Found {len(findings)} Security Group misconfigurations")
    return findings


def _check_inbound_rules(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check inbound rules for public internet access.

    Args:
        resource: Normalized security group resource

    Returns:
        List of findings
    """
    findings = []
    config = resource.get("config", {})
    group_id = config.get("group_id")
    group_name = config.get("group_name")
    region = config.get("region")
    inbound_rules = config.get("inbound_rules", [])

    for rule in inbound_rules:
        # Only check CIDR-based rules (not security group references)
        if rule.get("type") not in ["ipv4", "ipv6"]:
            continue

        cidr = rule.get("cidr")

        # Check if rule allows public access
        if not is_public_cidr(cidr):
            continue

        protocol = rule.get("protocol", "all")
        from_port = rule.get("from_port", "all")
        to_port = rule.get("to_port", "all")

        # Determine severity based on port
        severity = _determine_severity(protocol, from_port, to_port)
        issue_desc = _build_issue_description(group_name, protocol, from_port, to_port, cidr)

        findings.append({
            "id": str(uuid.uuid4()),
            "resource_id": group_id,
            "resource_type": "security_group",
            "issue": issue_desc,
            "severity": severity,
            "raw_config": {
                "group_id": group_id,
                "group_name": group_name,
                "region": region,
                "rule": rule
            }
        })

    return findings


def _determine_severity(protocol: str, from_port: Any, to_port: Any) -> str:
    """
    Determine the severity of a public security group rule.

    Args:
        protocol: Network protocol
        from_port: Starting port number
        to_port: Ending port number

    Returns:
        Severity level: "critical", "high", "medium", or "low"
    """
    # If all protocols/ports are open, it's critical
    if protocol == "-1" or from_port == "all":
        return "critical"

    # Check if any high-risk port is exposed
    try:
        from_port_int = int(from_port)
        to_port_int = int(to_port)

        for high_risk_port in HIGH_RISK_PORTS.keys():
            if from_port_int <= high_risk_port <= to_port_int:
                return "high"

    except (ValueError, TypeError):
        pass

    return "medium"


def _build_issue_description(
    group_name: str,
    protocol: str,
    from_port: Any,
    to_port: Any,
    cidr: str
) -> str:
    """
    Build a human-readable description of the security issue.

    Args:
        group_name: Security group name
        protocol: Network protocol
        from_port: Starting port number
        to_port: Ending port number
        cidr: CIDR block

    Returns:
        Issue description string
    """
    protocol_map = {
        "-1": "all protocols",
        "tcp": "TCP",
        "udp": "UDP",
        "icmp": "ICMP",
        "icmpv6": "ICMPv6"
    }

    protocol_name = protocol_map.get(str(protocol).lower(), protocol)

    # Check for specific high-risk ports
    port_description = ""
    if from_port != "all":
        try:
            from_port_int = int(from_port)
            to_port_int = int(to_port)

            if from_port_int == to_port_int and from_port_int in HIGH_RISK_PORTS:
                service_name = HIGH_RISK_PORTS[from_port_int]
                port_description = f"port {from_port_int} ({service_name})"
            elif from_port_int == to_port_int:
                port_description = f"port {from_port_int}"
            else:
                port_description = f"ports {from_port_int}-{to_port_int}"

        except (ValueError, TypeError):
            port_description = "all ports"
    else:
        port_description = "all ports"

    return (
        f"Security group '{group_name}' allows inbound traffic from the internet "
        f"({cidr}) on {protocol_name} {port_description}"
    )
