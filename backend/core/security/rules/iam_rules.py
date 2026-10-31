"""
CloudGuard — IAM Security Rules

Migrated and expanded from cloudguard-copilot-main detectors/iam_detector.py.
All rules are pure Python — no AWS API calls.

Rules implemented:
  IAM-001  IAM role has wildcard action (*) in policy             CRITICAL
  IAM-002  IAM role has wildcard resource (*) in policy           HIGH
  IAM-003  IAM role grants AdministratorAccess                    CRITICAL
  IAM-004  IAM role grants IAM write permissions                  HIGH
  IAM-005  IAM role has no permissions boundary                   MEDIUM
  IAM-006  IAM role trust policy allows all principals            CRITICAL
  IAM-007  IAM role trust policy allows cross-account access      MEDIUM
  IAM-008  IAM role allows PassRole permission                    HIGH
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from core.providers.base import CloudResource
from core.security.models import Evidence, Finding, Severity
from core.security.rules.base import RemediationSafety, RuleMetadata, SecurityRule


def _get_all_statements(resource: CloudResource) -> List[Dict[str, Any]]:
    """
    Flatten all policy statements from inline and managed policies
    into a single list for analysis.
    """
    all_statements: List[Dict[str, Any]] = []

    # Inline policies
    for policy in resource.get_config("inline_policies", []):
        if not isinstance(policy, dict):
            continue
        doc = policy.get("document", {})
        if isinstance(doc, str):
            try:
                import json
                doc = json.loads(doc)
            except Exception:
                doc = {}
        if isinstance(doc, dict):
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            elif not isinstance(stmts, list):
                stmts = []
            all_statements.extend([s for s in stmts if isinstance(s, dict)])

    # Managed policies (attached)
    for policy in resource.get_config("managed_policies", []):
        if not isinstance(policy, dict):
            continue
        doc = policy.get("document", {})
        if isinstance(doc, str):
            try:
                import json
                doc = json.loads(doc)
            except Exception:
                doc = {}
        if isinstance(doc, dict):
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            elif not isinstance(stmts, list):
                stmts = []
            all_statements.extend([s for s in stmts if isinstance(s, dict)])

    return all_statements


def _normalize_list(value: Any) -> List[str]:
    """Normalize a string or list into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


# ==============================================================================
# IAM-001 — Wildcard Action
# ==============================================================================

class IAMWildcardAction(SecurityRule):
    """
    Detects IAM roles with policies that use a wildcard (*) action.
    Wildcard actions grant the entity permission to perform ANY operation
    in the matched service or across ALL services.
    """

    metadata = RuleMetadata(
        rule_id="IAM-001",
        name="IAM Role Has Wildcard Action in Policy",
        description=(
            "An IAM policy attached to this role uses Action: '*' or 'service:*', "
            "granting excessive permissions that violate least-privilege principles."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.CRITICAL,
        privilege_escalation_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6", "ISO-A.9.2.3"],
        remediation_template=(
            "1. Open the AWS IAM console.\n"
            "2. Navigate to Roles → select the role.\n"
            "3. Review each policy for 'Action: *' or broad wildcards.\n"
            "4. Replace wildcard actions with specific required actions.\n"
            "5. Apply the principle of least privilege.\n\n"
            "Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        statements = _get_all_statements(resource)
        wildcard_stmts = []

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            wild_actions = [a for a in actions if a == "*" or a.endswith(":*")]
            if wild_actions:
                wildcard_stmts.append({
                    "sid": stmt.get("Sid", "Unnamed"),
                    "wildcard_actions": wild_actions[:5],  # Cap for readability
                })

        if wildcard_stmts:
            return self._make_finding(
                resource,
                title=f"IAM Role '{resource.display_name}' has wildcard actions (*)",
                description=(
                    f"The IAM role '{resource.display_name}' has {len(wildcard_stmts)} "
                    "policy statement(s) with wildcard actions. This grants excessive "
                    "permissions and violates the principle of least privilege."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=wildcard_stmts,
                    expected_value="Specific actions only (no wildcards)",
                    field_path="config.inline_policies|managed_policies[].document.Statement[].Action",
                    details={"affected_statement_count": len(wildcard_stmts)},
                ),
            )
        return None


# ==============================================================================
# IAM-002 — Wildcard Resource
# ==============================================================================

class IAMWildcardResource(SecurityRule):
    """
    Detects IAM roles where Allow statements target all resources (*).
    Even with specific actions, targeting all resources can allow
    operations on sensitive data or infrastructure.
    """

    metadata = RuleMetadata(
        rule_id="IAM-002",
        name="IAM Role Has Wildcard Resource in Policy",
        description=(
            "An IAM policy uses Resource: '*' in an Allow statement, "
            "permitting the action on any resource in the account."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.HIGH,
        privilege_escalation_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6"],
        remediation_template=(
            "1. Open the AWS IAM console → Roles → select the role.\n"
            "2. Identify Allow statements with Resource: '*'.\n"
            "3. Replace with specific resource ARNs.\n"
            "4. Example: arn:aws:s3:::my-specific-bucket/*"
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        statements = _get_all_statements(resource)
        wildcard_stmts = []

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in resources:
                actions = _normalize_list(stmt.get("Action", []))
                wildcard_stmts.append({
                    "sid": stmt.get("Sid", "Unnamed"),
                    "actions": actions[:5],
                })

        if wildcard_stmts:
            return self._make_finding(
                resource,
                title=f"IAM Role '{resource.display_name}' has wildcard resource (*)",
                description=(
                    f"The IAM role '{resource.display_name}' has {len(wildcard_stmts)} "
                    "policy statement(s) with 'Resource: *', allowing operations on "
                    "any resource in the account."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=wildcard_stmts,
                    expected_value="Specific resource ARNs only",
                    field_path="config.inline_policies|managed_policies[].document.Statement[].Resource",
                    details={"affected_statement_count": len(wildcard_stmts)},
                ),
            )
        return None


# ==============================================================================
# IAM-003 — AdministratorAccess Policy Attached
# ==============================================================================

class IAMAdministratorAccess(SecurityRule):
    """
    Detects IAM roles with the AWS-managed AdministratorAccess policy attached.
    This policy grants full access to all AWS services and resources.
    """

    metadata = RuleMetadata(
        rule_id="IAM-003",
        name="IAM Role Has AdministratorAccess Policy",
        description=(
            "The IAM role has the AWS-managed 'AdministratorAccess' policy attached, "
            "which grants full administrative access to all AWS services and resources."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.CRITICAL,
        privilege_escalation_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6", "ISO-A.9.2.3"],
        remediation_template=(
            "1. Open the AWS IAM console → Roles → select the role.\n"
            "2. Detach the AdministratorAccess managed policy.\n"
            "3. Create a custom policy granting only required permissions.\n"
            "4. Attach the custom policy instead.\n\n"
            "CLI: aws iam detach-role-policy \\\n"
            "  --role-name ROLE_NAME \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
    )

    _ADMIN_POLICY_ARNS = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
    }

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        managed_policies = resource.get_config("managed_policies", [])
        admin_policies = [
            p for p in managed_policies
            if p.get("arn", "") in self._ADMIN_POLICY_ARNS
        ]

        if admin_policies:
            return self._make_finding(
                resource,
                title=f"IAM Role '{resource.display_name}' has AdministratorAccess",
                description=(
                    f"CRITICAL: The IAM role '{resource.display_name}' has the "
                    "AdministratorAccess policy attached, granting complete control "
                    "over all AWS resources and services in the account."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=[p["arn"] for p in admin_policies],
                    expected_value="No AdministratorAccess or equivalent policy",
                    field_path="config.managed_policies[].arn",
                    details={"admin_policy_count": len(admin_policies)},
                ),
            )
        return None


# ==============================================================================
# IAM-004 — IAM Write Permissions
# ==============================================================================

class IAMWritePermissions(SecurityRule):
    """
    Detects IAM roles with permissions to create/modify/delete IAM resources.
    IAM write permissions allow privilege escalation — an attacker can create
    new users, roles or policies to gain additional access.
    """

    metadata = RuleMetadata(
        rule_id="IAM-004",
        name="IAM Role Has IAM Write Permissions (Privilege Escalation Risk)",
        description=(
            "The IAM role has permissions to modify IAM resources (create users, "
            "roles, or policies). This is a privilege escalation vector."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.HIGH,
        privilege_escalation_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6"],
        remediation_template=(
            "1. Review which IAM write actions are actually required.\n"
            "2. Remove or restrict: iam:CreateUser, iam:CreateRole, "
            "iam:AttachRolePolicy, iam:PutUserPolicy, iam:CreatePolicy.\n"
            "3. If IAM management is required, add permission boundaries."
        ),
    )

    _DANGEROUS_IAM_ACTIONS = {
        "iam:CreateUser", "iam:CreateRole", "iam:CreatePolicy",
        "iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:AttachGroupPolicy",
        "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:PutGroupPolicy",
        "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
        "iam:PassRole", "iam:DeleteRolePolicy",
    }

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        statements = _get_all_statements(resource)
        found_dangerous = set()

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            for action in actions:
                if action in self._DANGEROUS_IAM_ACTIONS or action == "*" or action == "iam:*":
                    if action == "*":
                        found_dangerous.update(["iam:*", "all services"])
                    elif action == "iam:*":
                        found_dangerous.add("iam:* (all IAM)")
                    else:
                        found_dangerous.add(action)

        if found_dangerous:
            return self._make_finding(
                resource,
                title=f"IAM Role '{resource.display_name}' has privilege escalation permissions",
                description=(
                    f"The IAM role '{resource.display_name}' has IAM write permissions "
                    "that could allow privilege escalation. Actions: "
                    f"{', '.join(sorted(found_dangerous)[:6])}."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value=sorted(found_dangerous)[:10],
                    expected_value="No IAM write permissions without permission boundary",
                    field_path="config.inline_policies|managed_policies[].document.Statement[].Action",
                    details={"dangerous_action_count": len(found_dangerous)},
                ),
            )
        return None


# ==============================================================================
# IAM-005 — Trust Policy Allows All Principals
# ==============================================================================

class IAMTrustPolicyAllPrincipals(SecurityRule):
    """
    Detects IAM roles where the trust policy allows any principal (* in Principal).
    This means any AWS entity can assume the role.
    """

    metadata = RuleMetadata(
        rule_id="IAM-005",
        name="IAM Role Trust Policy Allows All Principals",
        description=(
            "The IAM role trust policy uses Principal: '*', allowing any "
            "AWS entity — including external accounts — to assume the role."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.CRITICAL,
        privilege_escalation_risk=True,
        internet_exposure_risk=True,
        compliance_mappings=["CIS-1.16", "NIST-AC-6", "NIST-AC-3"],
        remediation_template=(
            "1. Open the AWS IAM console → Roles → select the role.\n"
            "2. Review the Trust relationships tab.\n"
            "3. Replace Principal: '*' with specific AWS service ARNs or account IDs.\n"
            "4. Add Condition clauses to further restrict access.\n\n"
            "Example trust for a Lambda function:\n"
            '{"Principal": {"Service": "lambda.amazonaws.com"}}'
        ),
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        trust_policy = resource.get_config("trust_policy", {})
        if not trust_policy:
            return None

        statements = trust_policy.get("Statement", [])
        open_stmts = []

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                open_stmts.append(stmt.get("Sid", "Unnamed"))
            elif isinstance(principal, dict):
                for key, val in principal.items():
                    if val == "*" or (isinstance(val, list) and "*" in val):
                        open_stmts.append(stmt.get("Sid", key))

        if open_stmts:
            return self._make_finding(
                resource,
                title=f"IAM Role '{resource.display_name}' trust allows all principals",
                description=(
                    f"CRITICAL: The IAM role '{resource.display_name}' trust policy "
                    "allows any principal (*) to assume it. This could allow external "
                    "attackers or unauthorized AWS accounts to assume the role."
                ),
                evidence=Evidence(
                    rule_id=self.rule_id,
                    observed_value={"Principal": "*"},
                    expected_value="Specific AWS principals (services or account ARNs)",
                    field_path="config.trust_policy.Statement[].Principal",
                    details={"open_statement_sids": open_stmts},
                ),
            )
        return None


# ==============================================================================
# IAM-006 — Trust Policy Allows Cross-Account Access
# ==============================================================================

class IAMCrossAccountTrust(SecurityRule):
    """
    Detects IAM roles whose trust policy grants AssumeRole to an external AWS account.

    Cross-account access is sometimes legitimate (for tooling or partner integrations)
    but should be detected and reviewed. External account IDs that were not intentionally
    added represent a significant risk of unauthorized access.
    """

    metadata = RuleMetadata(
        rule_id="IAM-006",
        name="IAM Role Trust Policy Allows Cross-Account Access",
        description=(
            "The IAM role trust policy grants AssumeRole access to an external AWS account. "
            "Cross-account trust relationships should be explicitly reviewed to ensure only "
            "authorized accounts can assume this role."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.MEDIUM,
        category="access-control",
        privilege_escalation_risk=True,
        remediation_safety=RemediationSafety.REVIEW_REQUIRED,
        compliance_mappings=["CIS-1.21", "NIST-AC-6"],
        remediation_template=(
            "1. Review the trust policy to verify the cross-account principal is authorized.\n"
            "2. If not needed, remove the external account principal.\n"
            "3. If legitimate, add an ExternalId condition to prevent confused deputy attacks.\n\n"
            "CLI: aws iam update-assume-role-policy \\ \n"
            "  --role-name ROLE_NAME \\\n"
            "  --policy-document file://updated-trust-policy.json"
        ),
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        trust_policy = resource.get_config("trust_policy", {})
        if not trust_policy:
            return None

        account_id = resource.account_id
        cross_account_principals = []

        for stmt in trust_policy.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            principal = stmt.get("Principal", {})

            # Normalize to list of principal ARNs
            arns = []
            if isinstance(principal, str):
                arns = [principal]
            elif isinstance(principal, dict):
                for val in principal.values():
                    if isinstance(val, list):
                        arns.extend(val)
                    elif isinstance(val, str):
                        arns.append(val)

            for arn in arns:
                # Check for explicit account ARNs that don't match our account
                if ":" in arn and "aws:iam::" in arn:
                    parts = arn.split(":")
                    if len(parts) >= 5:
                        arn_account = parts[4]
                        if arn_account and arn_account != account_id and arn_account not in ("aws", ""):
                            cross_account_principals.append(arn)

        if not cross_account_principals:
            return None

        return self._make_finding(
            resource,
            title=f"IAM Role '{resource.display_name}' allows cross-account access",
            description=(
                f"IAM role '{resource.display_name}' trust policy grants AssumeRole access "
                f"to {len(cross_account_principals)} external AWS account principal(s). "
                "Verify these cross-account relationships are intentional and add ExternalId "
                "conditions to prevent confused-deputy attacks."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.trust_policy.Statement[].Principal",
                observed_value=cross_account_principals[:5],
                expected_value="Only trusted account ARNs with ExternalId conditions",
                source="IAM trust policy",
                details={
                    "cross_account_count": len(cross_account_principals),
                    "own_account_id": account_id,
                },
            ),
        )


# ==============================================================================
# IAM-007 — No Permissions Boundary
# ==============================================================================

class IAMNoPermissionsBoundary(SecurityRule):
    """
    Detects IAM roles with significant permissions but no permissions boundary set.

    Permissions boundaries act as guardrails: even if the role's policies grant
    broad access, the boundary caps the effective permissions. They are especially
    important for roles that can create other IAM entities.
    """

    metadata = RuleMetadata(
        rule_id="IAM-007",
        name="IAM Role Has No Permissions Boundary",
        description=(
            "The IAM role does not have a permissions boundary set. Permissions boundaries "
            "limit the maximum permissions an entity can have, providing an additional "
            "layer of protection against privilege escalation."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.MEDIUM,
        category="access-control",
        privilege_escalation_risk=True,
        remediation_safety=RemediationSafety.SAFE,
        compliance_mappings=["NIST-AC-6", "ISO-A.9.2.3"],
        remediation_template=(
            "1. Create a permissions boundary policy scoping maximum allowed permissions.\n"
            "2. Attach it to the role:\n\n"
            "CLI: aws iam put-role-permissions-boundary \\\n"
            "  --role-name ROLE_NAME \\\n"
            "  --permissions-boundary arn:aws:iam::ACCOUNT:policy/BOUNDARY_POLICY"
        ),
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        boundary = resource.get_config("permissions_boundary")

        # Only flag roles that have explicit policies attached but no boundary
        inline_policies = resource.get_config("inline_policies", [])
        managed_policies = resource.get_config("managed_policies", [])

        if not inline_policies and not managed_policies:
            return None  # No policies attached — nothing to bound

        if boundary:
            return None  # Has a boundary — compliant

        return self._make_finding(
            resource,
            title=f"IAM Role '{resource.display_name}' has no permissions boundary",
            description=(
                f"IAM role '{resource.display_name}' has {len(inline_policies)} inline and "
                f"{len(managed_policies)} managed policies attached but no permissions boundary. "
                "A permissions boundary limits the maximum effective permissions, providing "
                "a critical safeguard against unintended privilege escalation."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.permissions_boundary",
                observed_value=None,
                expected_value="Permissions boundary policy ARN",
                source="IAM role configuration",
                details={
                    "inline_policy_count": len(inline_policies),
                    "managed_policy_count": len(managed_policies),
                },
            ),
        )


# ==============================================================================
# IAM-008 — PassRole Permission
# ==============================================================================

class IAMPassRolePermission(SecurityRule):
    """
    Detects IAM roles with iam:PassRole permission granted to broad resources.

    iam:PassRole allows the holder to assign an IAM role to an AWS service.
    If scoped to '*', this can be used to escalate privileges by passing a
    high-privilege role to a service (EC2, Lambda, etc.) that the attacker controls.
    """

    metadata = RuleMetadata(
        rule_id="IAM-008",
        name="IAM Role Grants iam:PassRole on Wildcard Resource",
        description=(
            "The IAM role has iam:PassRole permission scoped to '*' (all roles). "
            "This allows the holder to assign any IAM role to AWS services, enabling "
            "privilege escalation by attaching high-privilege roles to controlled resources."
        ),
        provider="aws",
        service="iam",
        resource_type="iam_role",
        severity=Severity.HIGH,
        category="access-control",
        privilege_escalation_risk=True,
        remediation_safety=RemediationSafety.REVIEW_REQUIRED,
        compliance_mappings=["CIS-1.16", "NIST-AC-6"],
        remediation_template=(
            "1. Scope iam:PassRole to only the specific role ARN(s) needed:\n"
            '   "Resource": ["arn:aws:iam::ACCOUNT:role/specific-role"]\n'
            "2. Add conditions to restrict which services the role can be passed to:\n"
            '   "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}'
        ),
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html",
        ],
    )

    def detect(self, resource: CloudResource) -> Optional[Finding]:
        statements = _get_all_statements(resource)
        pass_role_on_wildcard = []

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            has_pass_role = any(
                a in ("iam:PassRole", "iam:*", "*") for a in actions
            )
            if not has_pass_role:
                continue

            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in resources:
                pass_role_on_wildcard.append(stmt.get("Sid", "Unnamed"))

        if not pass_role_on_wildcard:
            return None

        return self._make_finding(
            resource,
            title=f"IAM Role '{resource.display_name}' can pass any IAM role (privilege escalation)",
            description=(
                f"IAM role '{resource.display_name}' has iam:PassRole permission with Resource '*'. "
                "This allows the role holder to attach any IAM role in the account to AWS services, "
                "enabling privilege escalation. Scope PassRole to specific role ARNs and add "
                "iam:PassedToService conditions."
            ),
            evidence=Evidence(
                rule_id=self.rule_id,
                field_path="config.inline_policies|managed_policies[].document.Statement[].Action",
                observed_value={"Action": "iam:PassRole", "Resource": "*"},
                expected_value="iam:PassRole scoped to specific role ARN(s)",
                source="IAM policy statements",
                details={"affected_sids": pass_role_on_wildcard},
            ),
        )


# ==============================================================================
# Rule Registry
# ==============================================================================

IAM_RULES: list[SecurityRule] = [
    IAMWildcardAction(),
    IAMWildcardResource(),
    IAMAdministratorAccess(),
    IAMWritePermissions(),
    IAMTrustPolicyAllPrincipals(),
    IAMCrossAccountTrust(),
    IAMNoPermissionsBoundary(),
    IAMPassRolePermission(),
]

