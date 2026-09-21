"""CloudGuard — AWS Lambda Collector"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from core.providers.aws.collectors.base import AWSCollector
from core.providers.base import CloudResource, ResourceType
from core.utils.retry import aws_retry


class LambdaCollector(AWSCollector):
    """Collects Lambda function configurations across specified regions."""

    def collect(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        scan_regions = self.regions or [self.session.region_name or "us-east-1"]

        for region in scan_regions:
            try:
                region_resources = self._collect_region(region)
                resources.extend(region_resources)
                self.log.info("lambda_region_collected", region=region, count=len(region_resources))
            except Exception as exc:
                self.log.warning("lambda_region_failed", region=region, error=str(exc))

        return resources

    def _collect_region(self, region: str) -> List[CloudResource]:
        resources = []
        lam = self.client("lambda", region=region)
        paginator = lam.get_paginator("list_functions")

        for page in paginator.paginate():
            for func in page.get("Functions", []):
                try:
                    resource = self._collect_function(lam, func, region)
                    if resource:
                        resources.append(resource)
                except Exception as exc:
                    self.log.warning(
                        "lambda_function_failed",
                        function=func.get("FunctionName", ""),
                        error=str(exc),
                    )

        return resources

    def _collect_function(self, lam, func: Dict[str, Any], region: str) -> CloudResource:
        name = func["FunctionName"]
        arn = func["FunctionArn"]

        resource_policy = self._get_resource_policy(lam, name)
        tags = self._get_tags(lam, arn)
        env_vars = func.get("Environment", {}).get("Variables", {})

        return CloudResource(
            resource_id=arn,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            provider="aws",
            service="lambda",
            account_id=self.account_id,
            region=region,
            name=name,
            tags=tags,
            config={
                "function_name": name,
                "runtime": func.get("Runtime", ""),
                "handler": func.get("Handler", ""),
                "memory_size": func.get("MemorySize", 128),
                "timeout": func.get("Timeout", 3),
                "environment_variables": env_vars,
                "execution_role_arn": func.get("Role", ""),
                "execution_role_policies": [],  # Would require additional IAM calls
                "execution_role_inline_policies": [],
                "resource_policy": resource_policy,
                "tracing_mode": func.get("TracingConfig", {}).get("Mode", "PassThrough"),
                "vpc_config": func.get("VpcConfig"),
            },
        )

    @aws_retry(max_attempts=3)
    def _get_resource_policy(self, lam, function_name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = lam.get_policy(FunctionName=function_name)
            policy_str = resp.get("Policy", "{}")
            return json.loads(policy_str) if policy_str else None
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            return None

    @aws_retry(max_attempts=3)
    def _get_tags(self, lam, function_arn: str) -> Dict[str, str]:
        try:
            resp = lam.list_tags(Resource=function_arn)
            return resp.get("Tags", {})
        except ClientError:
            return {}
