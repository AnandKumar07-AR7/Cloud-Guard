"""CloudGuard — AWS Security Group Collector"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from core.providers.aws.collectors.base import AWSCollector
from core.providers.base import CloudResource, ResourceType
from core.utils.retry import aws_retry


class SecurityGroupCollector(AWSCollector):
    """Collects EC2 Security Group configurations across specified regions."""

    def collect(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        scan_regions = self.regions or [self.session.region_name or "us-east-1"]

        for region in scan_regions:
            try:
                region_resources = self._collect_region(region)
                resources.extend(region_resources)
                self.log.info("sg_region_collected", region=region, count=len(region_resources))
            except Exception as exc:
                self.log.warning("sg_region_failed", region=region, error=str(exc))

        return resources

    @aws_retry(max_attempts=3)
    def _collect_region(self, region: str) -> List[CloudResource]:
        resources = []
        ec2 = self.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                resource = self._normalize_sg(sg, region)
                resources.append(resource)

        return resources

    def _normalize_sg(self, sg: Dict[str, Any], region: str) -> CloudResource:
        def _normalize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "-1")

            normalized_rules = []
            for ip_range in rule.get("IpRanges", []):
                normalized_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": ip_range.get("CidrIp", ""),
                    "description": ip_range.get("Description", ""),
                })
            for ipv6_range in rule.get("Ipv6Ranges", []):
                normalized_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": ipv6_range.get("CidrIpv6", ""),
                    "description": ipv6_range.get("Description", ""),
                })
            return normalized_rules

        inbound = []
        for rule in sg.get("IpPermissions", []):
            inbound.extend(_normalize_rule(rule))

        outbound = []
        for rule in sg.get("IpPermissionsEgress", []):
            outbound.extend(_normalize_rule(rule))

        name = sg.get("GroupName", sg["GroupId"])
        tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
        friendly_name = tags.get("Name", name)

        return CloudResource(
            resource_id=sg["GroupId"],
            resource_type=ResourceType.SECURITY_GROUP,
            provider="aws",
            service="ec2",
            account_id=self.account_id,
            region=region,
            name=friendly_name,
            tags=tags,
            config={
                "group_name": name,
                "description": sg.get("Description", ""),
                "vpc_id": sg.get("VpcId", ""),
                "inbound_rules": inbound,
                "outbound_rules": outbound,
            },
        )
