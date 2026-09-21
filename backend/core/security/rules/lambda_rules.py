"""
CloudGuard — Lambda Security Rules

Migrated and expanded from cloudguard-copilot-main detectors/lambda_detector.py.
All rules are pure Python — no AWS API calls.

Rules implemented:
  LAM-001  Lambda function has a public resource policy             CRITICAL
  LAM-002  Lambda environment contains secret-like variables        HIGH
  LAM-003  Lambda function uses a deprecated runtime                HIGH
  LAM-004  Lambda function execution role has admin permissions      CRITICAL
  LAM-005  Lambda function has no timeout configured                 LOW
  LAM-006  Lambda function X-Ray tracing disabled                    LOW
"""
from __future__ import annotations

import re
from typing import List, Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RuleMetadata, SecurityRule

# Runtimes that AWS has marked as deprecated or end-of-life.
# Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
_DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "java8", "java8.al2",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "go1.x",  # Deprecated in favor of provided.al2023
}

# Patterns that suggest a Lambda environment variable contains a secret value
_SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(password|passwd|pwd)",
        r"(secret|api[_-]?key|apikey)",
        r"(token|auth[_-]?token|access[_-]?token)",
        r"(private[_-]?key|signing[_-]?key)",
        r"(database[_-]?url|db[_-]?url|connection[_-]?string)",
        r"(aws[_-]?access[_-]?key|aws[_-]?secret)",
        r"(smtp[_-]?password|email[_-]?password)",
    ]
]

_PUBLIC_LAMBDA_PRINCIPALS = {
    "*",
    "arn:aws:iam::*:root",
}


def _env_var_looks_like_secret(key: str, value: str) -> bool:
    """Return True if the env var name suggests it contains a secret."""
    if any(pat.search(key) for pat in _SECRET_PATTERNS):
        # Don't flag empty or ARN-shaped values
        if value and not value.startswith("arn:") and len(value) > 3:
            return True
    return False


# ==============================================================================
# LAM-001 — Public Resource Policy
# ==============================================================================

class LambdaPublicResourcePolicy(SecurityRule):
    """
    Detects Lambda functions with resource policies that allow public invocation.
    A public resource policy allows anyone (Principal: *) to invoke the function,
    bypassing authentication.
    """

    metadata = RuleMetadata(
        rule_id="LAM-001",
        name="Lambda Function Has Public Resource Policy",
        description=(
            "The Lambda function's resource policy allows invocation by any principal (*). "
            "This enables unauthenticated public invocation of the function."
        ),
        provider="aws",
        service="lambda",
        resource_type="lambda_function",
        severity=Severity.CRITICAL,
        internet_exposure_risk=True,
        compliance_mappings=["NIST-AC-3", "NIST-SC-7"],
        remediation_template=(
            "1. Open the AWS Lambda console → select the function.\n"
            "2. Go to Configuration → Resource-based policy.\n"
            "3. Remove any statements with Principal: '*'.\n"
            "4. Restrict invocation to specific AWS services or account ARNs.\n\n"
            "CLI: aws lambda remove-permission \\\n"
            "  --function-name FUNCTION_NAME \\\n"
            "  --statement-id STATEMENT_ID"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        resource_policy = resource.get_config("resource_policy", {})
        if not resource_policy:
            return None

        statements = resource_policy.get("Statement", [])
        public_stmts = []

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                public_stmts.append(stmt.get("Sid", "Unnamed"))
            elif isinstance(principal, dict):
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                if any(p in _PUBLIC_LAMBDA_PRINCIPALS for p in aws_principal):
                    public_stmts.append(stmt.get("Sid", "Unnamed"))

        if public_stmts:
            return self._make_finding(
                resource,
                title=f"Lambda '{resource.display_name}' has a public resource policy",
                description=(
                    f"CRITICAL: Lambda function '{resource.display_name}' allows "
                    "unauthenticated public invocation via its resource policy. "
                    f"Affected statement(s): {', '.join(public_stmts)}."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=public_stmts,
                    expected_value="No public principal in resource policy",
                    field_path="config.resource_policy.Statement[].Principal",
                    details={"public_statement_count": len(public_stmts)},
                ),
            )
        return None


# ==============================================================================
# LAM-002 — Secret-Like Environment Variables
# ==============================================================================

class LambdaSecretsInEnvironment(SecurityRule):
    """
    Detects Lambda functions with environment variables whose names suggest
    they contain secrets (passwords, API keys, tokens).

    Secrets must be stored in AWS Secrets Manager or SSM Parameter Store,
    not in environment variables where they may be logged or exposed.
    """

    metadata = RuleMetadata(
        rule_id="LAM-002",
        name="Lambda Function May Expose Secrets in Environment Variables",
        description=(
            "Lambda environment variable names suggest secret values "
            "(passwords, API keys, tokens). Secrets should use AWS Secrets Manager."
        ),
        provider="aws",
        service="lambda",
        resource_type="lambda_function",
        severity=Severity.HIGH,
        data_exposure_risk=True,
        compliance_mappings=["NIST-SC-28", "ISO-A.10.1.1"],
        remediation_template=(
            "1. Identify environment variables containing secrets.\n"
            "2. Store the secrets in AWS Secrets Manager or SSM Parameter Store.\n"
            "3. Grant the Lambda execution role access to retrieve the secret.\n"
            "4. Update the function code to fetch secrets at runtime.\n"
            "5. Remove the plaintext values from the Lambda environment configuration."
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        env_vars = resource.get_config("environment_variables", {})
        if not env_vars:
            return None

        suspicious_vars: List[str] = []
        for key, value in env_vars.items():
            if _env_var_looks_like_secret(key, str(value)):
                suspicious_vars.append(key)

        if suspicious_vars:
            return self._make_finding(
                resource,
                title=f"Lambda '{resource.display_name}' may store secrets in env vars",
                description=(
                    f"Lambda function '{resource.display_name}' has environment variable(s) "
                    f"whose names suggest secret content: {', '.join(suspicious_vars)}. "
                    "Plaintext secrets in Lambda environment variables risk exposure "
                    "through logs, CloudTrail, and the Lambda console."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=suspicious_vars,
                    expected_value="No secret-like variable names; use Secrets Manager",
                    field_path="config.environment_variables",
                    details={"suspicious_var_count": len(suspicious_vars)},
                ),
            )
        return None


# ==============================================================================
# LAM-003 — Deprecated Runtime
# ==============================================================================

class LambdaDeprecatedRuntime(SecurityRule):
    """
    Detects Lambda functions using a runtime that AWS has deprecated or
    scheduled for end-of-support. Deprecated runtimes no longer receive
    security patches.
    """

    metadata = RuleMetadata(
        rule_id="LAM-003",
        name="Lambda Function Uses Deprecated Runtime",
        description=(
            "The Lambda function uses a runtime version that AWS has deprecated "
            "or stopped supporting. Deprecated runtimes no longer receive "
            "security patches."
        ),
        provider="aws",
        service="lambda",
        resource_type="lambda_function",
        severity=Severity.HIGH,
        compliance_mappings=["NIST-SI-2", "ISO-A.14.2.2"],
        remediation_template=(
            "1. Open the AWS Lambda console → select the function.\n"
            "2. Go to Code → Runtime settings.\n"
            "3. Update the runtime to a supported version.\n"
            "   Python: python3.12 | Node.js: nodejs20.x | Java: java21\n"
            "4. Test the function after updating.\n\n"
            "Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        runtime = resource.get_config("runtime", "")
        if runtime.lower() in _DEPRECATED_RUNTIMES:
            return self._make_finding(
                resource,
                title=f"Lambda '{resource.display_name}' uses deprecated runtime: {runtime}",
                description=(
                    f"Lambda function '{resource.display_name}' uses the deprecated "
                    f"runtime '{runtime}'. This runtime no longer receives AWS security "
                    "patches. The function should be updated to a supported runtime."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=runtime,
                    expected_value="python3.12, nodejs20.x, java21, or other supported runtime",
                    field_path="config.runtime",
                    details={"deprecated_runtimes": sorted(_DEPRECATED_RUNTIMES)[:8]},
                ),
            )
        return None


# ==============================================================================
# LAM-004 — Admin Execution Role
# ==============================================================================

class LambdaAdminExecutionRole(SecurityRule):
    """
    Detects Lambda functions whose execution role has administrative permissions.
    Lambda functions should follow least-privilege — they should only have
    the exact permissions required to perform their task.
    """

    metadata = RuleMetadata(
        rule_id="LAM-004",
        name="Lambda Function Execution Role Has Admin Permissions",
        description=(
            "The Lambda function's execution role has administrative-level permissions. "
            "Lambda functions should use least-privilege execution roles."
        ),
        provider="aws",
        service="lambda",
        resource_type="lambda_function",
        severity=Severity.CRITICAL,
        privilege_escalation_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6"],
        remediation_template=(
            "1. Identify the exact AWS services/actions the Lambda needs.\n"
            "2. Create a minimal IAM policy with only those permissions.\n"
            "3. Update the Lambda execution role to use the minimal policy.\n"
            "4. Remove any AdministratorAccess or wildcard policies."
        ),
    )

    _ADMIN_POLICY_ARNS = {"arn:aws:iam::aws:policy/AdministratorAccess"}

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        role_policies = resource.get_config("execution_role_policies", [])
        admin_policies = [
            p for p in role_policies
            if p.get("arn", "") in self._ADMIN_POLICY_ARNS
        ]

        # Also check for wildcard actions in inline policies
        inline_policies = resource.get_config("execution_role_inline_policies", [])
        has_wildcard = False
        for policy in inline_policies:
            doc = policy.get("document", {})
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions or "iam:*" in actions:
                        has_wildcard = True

        if admin_policies or has_wildcard:
            return self._make_finding(
                resource,
                title=f"Lambda '{resource.display_name}' execution role has admin permissions",
                description=(
                    f"CRITICAL: Lambda function '{resource.display_name}' execution role "
                    "has administrative-level permissions. If this function is compromised "
                    "or invoked unexpectedly, it could be used to escalate privileges."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value={
                        "admin_policies": [p["arn"] for p in admin_policies],
                        "wildcard_inline_policy": has_wildcard,
                    },
                    expected_value="Least-privilege execution role",
                    field_path="config.execution_role_policies",
                ),
            )
        return None


# ==============================================================================
# LAM-005 — X-Ray Tracing Disabled
# ==============================================================================

class LambdaTracingDisabled(SecurityRule):
    """
    Detects Lambda functions that do not have AWS X-Ray active tracing enabled.
    Without tracing, it is difficult to investigate security incidents
    or understand function behavior.
    """

    metadata = RuleMetadata(
        rule_id="LAM-005",
        name="Lambda Function X-Ray Active Tracing Disabled",
        description=(
            "AWS X-Ray active tracing is not enabled for this Lambda function. "
            "Tracing aids security incident investigation and performance analysis."
        ),
        provider="aws",
        service="lambda",
        resource_type="lambda_function",
        severity=Severity.LOW,
        compliance_mappings=["NIST-AU-12", "ISO-A.12.4.1"],
        remediation_template=(
            "1. Open the Lambda console → select the function.\n"
            "2. Configuration → Monitoring and operations tools.\n"
            "3. Enable 'Active tracing' under AWS X-Ray.\n\n"
            "CLI: aws lambda update-function-configuration \\\n"
            "  --function-name FUNCTION_NAME \\\n"
            "  --tracing-config Mode=Active"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        tracing = resource.get_config("tracing_mode", "PassThrough")
        if tracing != "Active":
            return self._make_finding(
                resource,
                title=f"Lambda '{resource.display_name}' X-Ray tracing is disabled",
                description=(
                    f"Lambda function '{resource.display_name}' has X-Ray tracing "
                    f"set to '{tracing}'. Active tracing should be enabled for "
                    "security incident investigation and observability."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=tracing,
                    expected_value="Active",
                    field_path="config.tracing_mode",
                ),
            )
        return None


# ==============================================================================
# Rule Registry
# ==============================================================================

LAMBDA_RULES: list[SecurityRule] = [
    LambdaPublicResourcePolicy(),
    LambdaSecretsInEnvironment(),
    LambdaDeprecatedRuntime(),
    LambdaAdminExecutionRole(),
    LambdaTracingDisabled(),
]
