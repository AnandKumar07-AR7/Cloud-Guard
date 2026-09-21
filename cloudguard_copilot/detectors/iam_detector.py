"""
IAM misconfiguration detector.
"""

from typing import List, Dict, Any
import uuid
import logging

from cloudguard_copilot.utils.normalization import (
    extract_policy_statements,
    has_wildcard_action,
    has_wildcard_resource,
    is_allow_statement
)

logger = logging.getLogger(__name__)


# Known overly permissive managed policies
ADMIN_POLICIES = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess"
]


def detect_iam_misconfigurations(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect misconfigurations in IAM role resources.

    Args:
        resources: List of normalized IAM role resources

    Returns:
        List of findings
    """
    findings = []

    for resource in resources:
        if resource.get("resource_type") != "iam_role":
            continue

        config = resource.get("config", {})

        # Check inline policies for wildcard permissions
        inline_findings = _check_inline_policies(resource)
        findings.extend(inline_findings)

        # Check attached policies for admin access
        attached_findings = _check_attached_policies(resource)
        findings.extend(attached_findings)

    logger.info(f"Found {len(findings)} IAM misconfigurations")
    return findings


def _check_inline_policies(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check inline policies for overly permissive configurations.

    Args:
        resource: Normalized IAM role resource

    Returns:
        List of findings
    """
    findings = []
    config = resource.get("config", {})
    role_name = config.get("role_name")
    role_arn = config.get("arn")
    inline_policies = config.get("inline_policies", [])

    for policy in inline_policies:
        policy_name = policy.get("policy_name")
        policy_doc = policy.get("policy_document")

        statements = extract_policy_statements(policy_doc)

        for statement in statements:
            if not is_allow_statement(statement):
                continue

            # Check for wildcard action
            if has_wildcard_action(statement):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "resource_id": role_arn,
                    "resource_type": "iam_role",
                    "issue": f"IAM role '{role_name}' has inline policy '{policy_name}' with wildcard Action ('*')",
                    "severity": "high",
                    "raw_config": {
                        "role_name": role_name,
                        "policy_name": policy_name,
                        "statement": statement
                    }
                })

            # Check for wildcard action with wildcard resource
            if has_wildcard_action(statement) and has_wildcard_resource(statement):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "resource_id": role_arn,
                    "resource_type": "iam_role",
                    "issue": f"IAM role '{role_name}' has inline policy '{policy_name}' with wildcard Action ('*') and Resource ('*') - full admin access",
                    "severity": "critical",
                    "raw_config": {
                        "role_name": role_name,
                        "policy_name": policy_name,
                        "statement": statement
                    }
                })

            # Check for wildcard resource only
            elif has_wildcard_resource(statement):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "resource_id": role_arn,
                    "resource_type": "iam_role",
                    "issue": f"IAM role '{role_name}' has inline policy '{policy_name}' with wildcard Resource ('*')",
                    "severity": "medium",
                    "raw_config": {
                        "role_name": role_name,
                        "policy_name": policy_name,
                        "statement": statement
                    }
                })

    return findings


def _check_attached_policies(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check attached managed policies for admin access.

    Args:
        resource: Normalized IAM role resource

    Returns:
        List of findings
    """
    findings = []
    config = resource.get("config", {})
    role_name = config.get("role_name")
    role_arn = config.get("arn")
    attached_policies = config.get("attached_policies", [])

    for policy in attached_policies:
        policy_arn = policy.get("policy_arn")
        policy_name = policy.get("policy_name")

        # Check if it's a known admin policy
        if policy_arn in ADMIN_POLICIES:
            findings.append({
                "id": str(uuid.uuid4()),
                "resource_id": role_arn,
                "resource_type": "iam_role",
                "issue": f"IAM role '{role_name}' has overly permissive managed policy '{policy_name}' attached",
                "severity": "high",
                "raw_config": {
                    "role_name": role_name,
                    "policy_name": policy_name,
                    "policy_arn": policy_arn
                }
            })
            continue

        # Check policy document for wildcards
        policy_doc = policy.get("policy_document")
        if not policy_doc:
            continue

        statements = extract_policy_statements(policy_doc)

        for statement in statements:
            if not is_allow_statement(statement):
                continue

            # Check for full admin permissions
            if has_wildcard_action(statement) and has_wildcard_resource(statement):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "resource_id": role_arn,
                    "resource_type": "iam_role",
                    "issue": f"IAM role '{role_name}' has attached policy '{policy_name}' with wildcard Action ('*') and Resource ('*') - full admin access",
                    "severity": "critical",
                    "raw_config": {
                        "role_name": role_name,
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "statement": statement
                    }
                })

    return findings
