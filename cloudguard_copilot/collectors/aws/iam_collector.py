"""
IAM role and policy collector for AWS.
"""

from typing import List, Dict, Any
import logging
import boto3
import json
from botocore.exceptions import ClientError

from cloudguard_copilot.collectors.base import BaseCollector
from cloudguard_copilot.utils.debug_logger import get_debug_logger

logger = logging.getLogger(__name__)
debug = get_debug_logger()


class IAMCollector(BaseCollector):
    """
    Collector for IAM roles and their attached policies.

    Gathers inline policies, managed policies, and trust relationships.
    """

    def __init__(self, session: boto3.Session = None):
        """
        Initialize IAM collector.

        Args:
            session: boto3 Session object. If None, uses default credentials.
        """
        super().__init__(session)
        if session:
            self.iam_client = session.client('iam')
        else:
            self.iam_client = boto3.client('iam')

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all IAM role configurations.

        Returns:
            List of normalized IAM role resources
        """
        if debug:
            debug.log_section_start("IAM Role Collection")
            debug.log_aws_api_call("iam", "list_roles")

        resources = []

        try:
            # List all roles
            paginator = self.iam_client.get_paginator('list_roles')

            for page in paginator.paginate():
                roles = page.get('Roles', [])

                if debug:
                    debug.log_aws_api_response("iam", "list_roles", {"RolesCount": len(roles)})

                logger.info(f"Processing {len(roles)} IAM roles from current page")

                if debug:
                    debug.log_custom(f"Found {len(roles)} IAM roles to process")

                for role in roles:
                    role_name = role['RoleName']

                    try:
                        role_config = self._get_role_config(role_name, role)
                        normalized = self._normalize_resource(
                            resource_id=role['Arn'],
                            resource_type="iam_role",
                            config=role_config
                        )
                        resources.append(normalized)

                    except Exception as e:
                        self._handle_error(e, f"iam_role:{role_name}")

        except Exception as e:
            self._handle_error(e, "iam_roles")

        return resources

    def _get_role_config(self, role_name: str, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed configuration for a specific IAM role.

        Args:
            role_name: Name of the IAM role
            role_data: Basic role data from list_roles

        Returns:
            Dictionary containing role configuration
        """
        config = {
            "role_name": role_name,
            "arn": role_data.get('Arn'),
            "assume_role_policy": role_data.get('AssumeRolePolicyDocument'),
            "inline_policies": [],
            "attached_policies": [],
            "max_session_duration": role_data.get('MaxSessionDuration'),
            "creation_date": str(role_data.get('CreateDate'))
        }

        # Get inline policies
        try:
            inline_response = self.iam_client.list_role_policies(RoleName=role_name)
            policy_names = inline_response.get('PolicyNames', [])

            for policy_name in policy_names:
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                config["inline_policies"].append({
                    "policy_name": policy_name,
                    "policy_document": policy_doc.get('PolicyDocument')
                })

        except ClientError as e:
            logger.warning(f"Could not get inline policies for {role_name}: {e}")

        # Get attached managed policies
        try:
            attached_response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = attached_response.get('AttachedPolicies', [])

            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_name = policy['PolicyName']

                # Get policy version to retrieve document
                try:
                    policy_details = self.iam_client.get_policy(PolicyArn=policy_arn)
                    default_version = policy_details['Policy']['DefaultVersionId']

                    policy_version = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )

                    config["attached_policies"].append({
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "policy_document": policy_version['PolicyVersion']['Document']
                    })

                except ClientError as e:
                    logger.warning(f"Could not get policy document for {policy_arn}: {e}")
                    config["attached_policies"].append({
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "policy_document": None
                    })

        except ClientError as e:
            logger.warning(f"Could not get attached policies for {role_name}: {e}")

        return config
