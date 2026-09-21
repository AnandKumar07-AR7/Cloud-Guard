"""
Lambda function collector for AWS.
"""

from typing import List, Dict, Any
import logging
import boto3
from botocore.exceptions import ClientError

from cloudguard_copilot.collectors.base import BaseCollector
from cloudguard_copilot.utils.debug_logger import get_debug_logger

logger = logging.getLogger(__name__)
debug = get_debug_logger()


class LambdaCollector(BaseCollector):
    """
    Collector for AWS Lambda function configurations.

    Gathers function settings, environment variables, VPC config, IAM roles, and resource policies.
    """

    def __init__(self, session: boto3.Session = None, regions: List[str] = None):
        """
        Initialize Lambda collector.

        Args:
            session: boto3 Session object. If None, uses default credentials.
            regions: List of AWS regions to scan. If None, scans all available regions.
        """
        super().__init__(session)

        if session:
            self.lambda_client = session.client('lambda')
            self.ec2_client = session.client('ec2')
        else:
            self.lambda_client = boto3.client('lambda')
            self.ec2_client = boto3.client('ec2')

        # Get regions to scan
        if regions:
            self.regions = regions
        else:
            self.regions = self._get_all_regions()

    def _get_all_regions(self) -> List[str]:
        """Get all available AWS regions."""
        try:
            response = self.ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.warning(f"Failed to get regions, using default: {e}")
            return ['us-east-1']

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect all Lambda function configurations across regions.

        Returns:
            List of normalized Lambda function resources
        """
        if debug:
            debug.log_section_start("Lambda Function Collection")
            debug.log_custom(f"Scanning {len(self.regions)} regions: {', '.join(self.regions)}")

        resources = []

        for region in self.regions:
            logger.debug(f"Scanning Lambda functions in region: {region}")

            if debug:
                debug.log_custom(f"Processing region: {region}")

            try:
                # Create regional client
                if self.session:
                    lambda_client = self.session.client('lambda', region_name=region)
                else:
                    lambda_client = boto3.client('lambda', region_name=region)

                if debug:
                    debug.log_aws_api_call("lambda", "list_functions", {"region": region})

                # List all functions in this region
                paginator = lambda_client.get_paginator('list_functions')

                for page in paginator.paginate():
                    functions = page.get('Functions', [])

                    if debug:
                        debug.log_aws_api_response("lambda", "list_functions", {"FunctionsCount": len(functions), "region": region})
                        if functions:
                            debug.log_custom(f"Found {len(functions)} Lambda functions in {region}")

                    for function in functions:
                        function_name = function['FunctionName']

                        try:
                            function_config = self._get_function_config(
                                lambda_client,
                                function_name,
                                region,
                                function
                            )

                            normalized = self._normalize_resource(
                                resource_id=function_name,
                                resource_type="lambda_function",
                                config=function_config
                            )
                            resources.append(normalized)

                        except Exception as e:
                            self._handle_error(e, f"lambda_function:{region}:{function_name}")

            except Exception as e:
                logger.warning(f"Failed to list Lambda functions in {region}: {e}")

        logger.info(f"Collected {len(resources)} Lambda functions across {len(self.regions)} regions")
        return resources

    def _get_function_config(
        self,
        lambda_client: Any,
        function_name: str,
        region: str,
        function_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get detailed configuration for a specific Lambda function.

        Args:
            lambda_client: Regional Lambda client
            function_name: Name of the Lambda function
            region: AWS region
            function_data: Basic function data from list_functions

        Returns:
            Dictionary containing function configuration
        """
        config = {
            "function_name": function_name,
            "function_arn": function_data.get('FunctionArn'),
            "region": region,
            "runtime": function_data.get('Runtime'),
            "role": function_data.get('Role'),
            "handler": function_data.get('Handler'),
            "code_size": function_data.get('CodeSize'),
            "timeout": function_data.get('Timeout'),
            "memory_size": function_data.get('MemorySize'),
            "last_modified": function_data.get('LastModified'),
            "environment_variables": None,
            "vpc_config": None,
            "tracing_config": None,
            "reserved_concurrent_executions": None,
            "resource_policy": None,
            "tags": None
        }

        # Get function configuration details
        try:
            func_config = lambda_client.get_function_configuration(FunctionName=function_name)

            config["environment_variables"] = func_config.get('Environment', {}).get('Variables', {})
            config["vpc_config"] = func_config.get('VpcConfig', {})
            config["tracing_config"] = func_config.get('TracingConfig', {})
            config["reserved_concurrent_executions"] = func_config.get('ReservedConcurrentExecutions')

        except ClientError as e:
            logger.warning(f"Could not get configuration for {function_name}: {e}")

        # Get resource-based policy
        try:
            policy_response = lambda_client.get_policy(FunctionName=function_name)
            config["resource_policy"] = policy_response.get('Policy')
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.warning(f"Could not get policy for {function_name}: {e}")

        # Get tags
        try:
            if config.get("function_arn"):
                tags_response = lambda_client.list_tags(Resource=config["function_arn"])
                config["tags"] = tags_response.get('Tags', {})
        except ClientError as e:
            logger.warning(f"Could not get tags for {function_name}: {e}")

        return config
