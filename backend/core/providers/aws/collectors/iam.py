"""CloudGuard — AWS IAM Collector"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from core.providers.aws.collectors.base import AWSCollector
from core.providers.base import CloudResource, ResourceType
from core.utils.retry import aws_retry


class IAMCollector(AWSCollector):
    """Collects IAM role configurations."""

    def collect(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        iam = self.client("iam")
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                try:
                    resource = self._collect_role(iam, role)
                    if resource:
                        resources.append(resource)
                except Exception as exc:
                    self.log.warning(
                        "iam_role_collection_failed",
                        role=role.get("RoleName", ""),
                        error=str(exc),
                    )

        self.log.info("iam_roles_collected", count=len(resources))
        return resources

    def _collect_role(self, iam, role: Dict[str, Any]) -> CloudResource:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        inline_policies = self._get_inline_policies(iam, role_name)
        managed_policies = self._get_managed_policies(iam, role_name)

        trust_policy_doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_policy_doc, str):
            try:
                trust_policy_doc = json.loads(trust_policy_doc)
            except (json.JSONDecodeError, TypeError):
                trust_policy_doc = {}

        return CloudResource(
            resource_id=role_arn,
            resource_type=ResourceType.IAM_ROLE,
            provider="aws",
            service="iam",
            account_id=self.account_id,
            region="global",
            name=role_name,
            config={
                "role_name": role_name,
                "trust_policy": trust_policy_doc,
                "inline_policies": inline_policies,
                "managed_policies": managed_policies,
                "permissions_boundary": role.get("PermissionsBoundary"),
                "path": role.get("Path", "/"),
                "max_session_duration": role.get("MaxSessionDuration", 3600),
            },
        )

    @aws_retry(max_attempts=3)
    def _get_inline_policies(self, iam, role_name: str) -> List[Dict[str, Any]]:
        policies = []
        try:
            paginator = iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get("PolicyNames", []):
                    try:
                        resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        doc = resp.get("PolicyDocument", {})
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        policies.append({"name": policy_name, "document": doc})
                    except ClientError:
                        pass
        except ClientError:
            pass
        return policies

    @aws_retry(max_attempts=3)
    def _get_managed_policies(self, iam, role_name: str) -> List[Dict[str, Any]]:
        policies = []
        try:
            paginator = iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    policy_arn = policy["PolicyArn"]
                    doc = self._get_policy_document(iam, policy_arn)
                    policies.append({
                        "name": policy["PolicyName"],
                        "arn": policy_arn,
                        "document": doc or {},
                    })
        except ClientError:
            pass
        return policies

    @aws_retry(max_attempts=3)
    def _get_policy_document(self, iam, policy_arn: str) -> Optional[Dict[str, Any]]:
        try:
            policy_resp = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy_resp["Policy"]["DefaultVersionId"]
            version_resp = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            doc = version_resp["PolicyVersion"].get("Document", {})
            if isinstance(doc, str):
                doc = json.loads(doc)
            return doc
        except ClientError:
            return None
