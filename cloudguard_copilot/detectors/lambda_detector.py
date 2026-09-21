"""
Lambda function misconfiguration detector.
"""

from typing import List, Dict, Any
import uuid
import logging
import json

logger = logging.getLogger(__name__)


def detect_lambda_misconfigurations(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect misconfigurations in Lambda function resources.

    Args:
        resources: List of normalized Lambda function resources

    Returns:
        List of findings
    """
    findings = []

    for resource in resources:
        if resource.get("resource_type") != "lambda_function":
            continue

        config = resource.get("config", {})

        # Check for public access via resource policy
        public_finding = _check_public_access(resource)
        if public_finding:
            findings.append(public_finding)

        # Check for overly permissive execution role
        role_finding = _check_execution_role(resource)
        if role_finding:
            findings.append(role_finding)

        # Check for environment variables containing secrets
        secrets_finding = _check_environment_secrets(resource)
        if secrets_finding:
            findings.append(secrets_finding)

        # Check for outdated runtime
        runtime_finding = _check_runtime_version(resource)
        if runtime_finding:
            findings.append(runtime_finding)

        # Check for missing VPC configuration (for functions needing private resources)
        # Note: This is informational, not all functions need VPC

        # Check for tracing disabled
        tracing_finding = _check_tracing(resource)
        if tracing_finding:
            findings.append(tracing_finding)

        # Check for excessive timeout
        timeout_finding = _check_timeout(resource)
        if timeout_finding:
            findings.append(timeout_finding)

    logger.info(f"Found {len(findings)} Lambda misconfigurations")
    return findings


def _check_public_access(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if Lambda function is publicly accessible.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if function is public, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    resource_policy = config.get("resource_policy")

    if not resource_policy:
        return None

    try:
        policy_doc = json.loads(resource_policy)
        statements = policy_doc.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Allow":
                principal = statement.get("Principal", {})

                # Check for wildcard principal
                if principal == "*" or principal.get("AWS") == "*":
                    return {
                        "id": str(uuid.uuid4()),
                        "resource_id": function_name,
                        "resource_type": "lambda_function",
                        "issue": "Lambda function has a resource policy allowing public access (Principal: *)",
                        "severity": "critical",
                        "raw_config": config
                    }

                # Check for service principal without conditions
                service = principal.get("Service")
                condition = statement.get("Condition")

                if service and not condition:
                    # Services without conditions might be overly permissive
                    if service in ["*", "*.amazonaws.com"]:
                        return {
                            "id": str(uuid.uuid4()),
                            "resource_id": function_name,
                            "resource_type": "lambda_function",
                            "issue": f"Lambda function allows access from broad service principal: {service}",
                            "severity": "high",
                            "raw_config": config
                        }

    except json.JSONDecodeError:
        logger.warning(f"Failed to parse resource policy for {function_name}")

    return None


def _check_execution_role(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if Lambda execution role has appropriate permissions.

    Note: This is a basic check. Full role analysis requires IAM policy examination.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if role appears problematic, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    role_arn = config.get("role")

    # Check if role contains "admin" or overly permissive patterns
    if role_arn and ("admin" in role_arn.lower() or "poweruser" in role_arn.lower()):
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": f"Lambda function uses potentially overly permissive IAM role: {role_arn}",
            "severity": "medium",
            "raw_config": config
        }

    return None


def _check_environment_secrets(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check for potential secrets in environment variables.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if potential secrets found, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    env_vars = config.get("environment_variables", {})

    if not env_vars:
        return None

    # Keywords that suggest secrets
    secret_keywords = [
        'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
        'access_key', 'accesskey', 'private_key', 'privatekey',
        'token', 'auth', 'credentials', 'creds'
    ]

    suspicious_vars = []
    for key in env_vars.keys():
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in secret_keywords):
            suspicious_vars.append(key)

    if suspicious_vars:
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": f"Lambda function has environment variables that may contain secrets: {', '.join(suspicious_vars)}. Consider using AWS Secrets Manager or Parameter Store.",
            "severity": "high",
            "raw_config": config
        }

    return None


def _check_runtime_version(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if Lambda runtime is deprecated or outdated.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if runtime is deprecated, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    runtime = config.get("runtime")

    if not runtime:
        return None

    # Deprecated or end-of-life runtimes
    deprecated_runtimes = [
        'python2.7', 'python3.6', 'python3.7',
        'nodejs4.3', 'nodejs6.10', 'nodejs8.10', 'nodejs10.x', 'nodejs12.x',
        'dotnetcore2.1', 'dotnetcore3.1',
        'ruby2.5', 'ruby2.7',
        'java8', 'go1.x'
    ]

    # Older but still supported runtimes (informational)
    older_runtimes = [
        'python3.8', 'python3.9',
        'nodejs14.x', 'nodejs16.x',
        'java11'
    ]

    if runtime in deprecated_runtimes:
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": f"Lambda function uses deprecated runtime: {runtime}. Update to a supported runtime version.",
            "severity": "high",
            "raw_config": config
        }

    if runtime in older_runtimes:
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": f"Lambda function uses older runtime: {runtime}. Consider upgrading to the latest version for security updates and new features.",
            "severity": "low",
            "raw_config": config
        }

    return None


def _check_tracing(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if AWS X-Ray tracing is enabled.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if tracing is disabled, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    tracing_config = config.get("tracing_config", {})
    tracing_mode = tracing_config.get("Mode", "PassThrough")

    if tracing_mode == "PassThrough":
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": "Lambda function does not have AWS X-Ray tracing enabled. Enable Active tracing for better observability.",
            "severity": "low",
            "raw_config": config
        }

    return None


def _check_timeout(resource: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Check if Lambda timeout is excessively high.

    Args:
        resource: Normalized Lambda function resource

    Returns:
        Finding dictionary if timeout is too high, None otherwise
    """
    config = resource.get("config", {})
    function_name = config.get("function_name")
    timeout = config.get("timeout", 3)

    # Maximum Lambda timeout is 900 seconds (15 minutes)
    # Flag functions with very high timeouts as they may indicate issues
    if timeout >= 600:  # 10 minutes or more
        return {
            "id": str(uuid.uuid4()),
            "resource_id": function_name,
            "resource_type": "lambda_function",
            "issue": f"Lambda function has very high timeout value: {timeout} seconds. Consider optimizing function performance or breaking into smaller functions.",
            "severity": "low",
            "raw_config": config
        }

    return None
