"""
Security Group collector for AWS.
"""

from typing import List, Dict, Any
import logging
import boto3
from botocore.exceptions import ClientError

from cloudguard_copilot.collectors.base import BaseCollector
from cloudguard_copilot.utils.debug_logger import get_debug_logger

logger = logging.getLogger(__name__)
debug = get_debug_logger()


class SecurityGroupCollector(BaseCollector):
    """
    Collector for EC2 Security Group configurations.

    Gathers inbound and outbound rules for all security groups.
    """

    def __init__(self, session: boto3.Session = None, regions: List[str] = None):
        """
        Initialize Security Group collector.

        Args:
            session: boto3 Session object. If None, uses default credentials.
            regions: List of AWS regions to scan. If None, scans all available regions.
        """
        super().__init__(session)
        self.session = session or boto3.Session()

        if regions:
            self.regions = regions
        else:
            # Get all available regions for EC2
            ec2_client = self.session.client('ec2', region_name='us-east-1')
            try:
                region_response = ec2_client.describe_regions()
                self.regions = [r['RegionName'] for r in region_response['Regions']]
            except ClientError as e:
                logger.warning(f"Could not list regions, defaulting to us-east-1: {e}")
                self.regions = ['us-east-1']

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all Security Group configurations across regions.

        Returns:
            List of normalized security group resources
        """
        if debug:
            debug.log_section_start("Security Group Collection")
            debug.log_custom(f"Scanning {len(self.regions)} regions: {', '.join(self.regions)}")

        resources = []

        for region in self.regions:
            try:
                if debug:
                    debug.log_custom(f"Processing region: {region}")
                    debug.log_aws_api_call("ec2", "describe_security_groups", {"region": region})

                ec2_client = self.session.client('ec2', region_name=region)

                # Describe all security groups in this region
                paginator = ec2_client.get_paginator('describe_security_groups')

                for page in paginator.paginate():
                    security_groups = page.get('SecurityGroups', [])

                    if debug:
                        debug.log_aws_api_response("ec2", "describe_security_groups", {"SecurityGroupsCount": len(security_groups), "region": region})

                    if security_groups:
                        logger.info(f"Found {len(security_groups)} security groups in {region}")
                        if debug:
                            debug.log_custom(f"Found {len(security_groups)} security groups in {region}")

                    for sg in security_groups:
                        try:
                            sg_config = self._get_sg_config(sg, region)
                            normalized = self._normalize_resource(
                                resource_id=sg['GroupId'],
                                resource_type="security_group",
                                config=sg_config
                            )
                            resources.append(normalized)

                        except Exception as e:
                            self._handle_error(e, f"security_group:{sg.get('GroupId')}")

            except Exception as e:
                self._handle_error(e, f"security_groups in region {region}")

        return resources

    def _get_sg_config(self, sg: Dict[str, Any], region: str) -> Dict[str, Any]:
        """
        Get detailed configuration for a specific security group.

        Args:
            sg: Security group data from describe_security_groups
            region: AWS region name

        Returns:
            Dictionary containing security group configuration
        """
        config = {
            "group_id": sg.get('GroupId'),
            "group_name": sg.get('GroupName'),
            "description": sg.get('Description'),
            "vpc_id": sg.get('VpcId'),
            "region": region,
            "inbound_rules": self._normalize_ip_permissions(sg.get('IpPermissions', [])),
            "outbound_rules": self._normalize_ip_permissions(sg.get('IpPermissionsEgress', [])),
            "tags": sg.get('Tags', [])
        }

        return config

    def _normalize_ip_permissions(self, permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize IP permissions (rules) into a simpler format.

        Args:
            permissions: List of IP permissions from AWS API

        Returns:
            List of normalized rule dictionaries
        """
        normalized_rules = []

        for perm in permissions:
            protocol = perm.get('IpProtocol', 'all')
            from_port = perm.get('FromPort', 'all')
            to_port = perm.get('ToPort', 'all')

            # Process IPv4 ranges
            for ip_range in perm.get('IpRanges', []):
                normalized_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": ip_range.get('CidrIp'),
                    "description": ip_range.get('Description', ''),
                    "type": "ipv4"
                })

            # Process IPv6 ranges
            for ipv6_range in perm.get('Ipv6Ranges', []):
                normalized_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": ipv6_range.get('CidrIpv6'),
                    "description": ipv6_range.get('Description', ''),
                    "type": "ipv6"
                })

            # Process security group references
            for sg_ref in perm.get('UserIdGroupPairs', []):
                normalized_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "source_security_group": sg_ref.get('GroupId'),
                    "description": sg_ref.get('Description', ''),
                    "type": "security_group"
                })

        return normalized_rules
