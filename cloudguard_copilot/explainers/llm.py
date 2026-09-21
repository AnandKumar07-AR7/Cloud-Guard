"""
LLM-based explainer for security findings.

This module provides AI-generated explanations for security misconfigurations.
"""

from typing import Dict, Any
import logging
import os
import json

from cloudguard_copilot.utils.debug_logger import get_debug_logger
from cloudguard_copilot.utils.data_masker import mask_finding, get_masking_summary

logger = logging.getLogger(__name__)
debug = get_debug_logger()

# Try to import Anthropic SDK
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic SDK not installed. Install with: pip install anthropic>=0.40.0")


def explain_finding(finding: Dict[str, Any], use_llm: bool = None) -> Dict[str, Any]:
    """
    Generate developer-friendly and manager-friendly explanations for a finding.

    Uses Claude Sonnet 4.5 for AI-generated explanations when available.
    Falls back to template-based explanations if LLM is unavailable.

    Args:
        finding: Security finding dictionary with keys:
            - id: Unique finding ID
            - resource_id: Resource identifier
            - resource_type: Type of resource
            - issue: Description of the issue
            - severity: Severity level
            - raw_config: Raw configuration data
        use_llm: Whether to use LLM (None=auto-detect, True=force LLM, False=force templates)

    Returns:
        Dictionary with:
            - developer_explanation: Technical explanation for developers
            - manager_summary: Executive summary for management
            - remediation_steps: Step-by-step remediation guide
    """
    if debug:
        debug.log_section_start(f"Explaining Finding: {finding.get('id')}")
        debug.log_custom(f"Resource Type: {finding.get('resource_type')}")
        debug.log_custom(f"Resource ID: {finding.get('resource_id')}")
        debug.log_custom(f"Issue: {finding.get('issue')}")
        debug.log_custom(f"Severity: {finding.get('severity')}")

    # Determine if we should use LLM
    if use_llm is None:
        # Auto-detect: use LLM if API key is available
        use_llm = ANTHROPIC_AVAILABLE and os.getenv("ANTHROPIC_API_KEY") is not None
    elif use_llm and not ANTHROPIC_AVAILABLE:
        logger.warning("LLM requested but Anthropic SDK not installed. Falling back to templates.")
        use_llm = False

    if debug:
        debug.log_custom(f"Using LLM: {use_llm}")

    # Generate explanation
    if use_llm:
        try:
            explanation = _generate_llm_explanation(finding)
            logger.debug(f"Generated LLM explanation for finding {finding.get('id')}")
            if debug:
                debug.log_custom("✓ LLM explanation generated successfully")
        except Exception as e:
            logger.error(f"LLM explanation failed: {e}. Falling back to templates.")
            if debug:
                debug.log_error(e, "LLM explanation generation")
                debug.log_custom("Falling back to template-based explanation")
            explanation = _generate_template_explanation(finding)
    else:
        explanation = _generate_template_explanation(finding)
        logger.debug(f"Generated template explanation for finding {finding.get('id')}")
        if debug:
            debug.log_custom("Generated template-based explanation")

    return explanation


def _generate_llm_explanation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate AI-powered explanation using Claude Sonnet 4.5.

    Args:
        finding: Security finding dictionary

    Returns:
        Explanation dictionary with LLM-generated content
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")

    # Initialize Anthropic client
    client = anthropic.Anthropic(api_key=api_key)

    if debug:
        debug.log_custom("Building LLM prompt...")

    # Build the prompt for Claude
    resource_type = finding.get("resource_type", "unknown")
    resource_id = finding.get("resource_id", "unknown")
    issue = finding.get("issue", "Security misconfiguration detected")
    severity = finding.get("severity", "medium")
    raw_config = finding.get("raw_config", {})

    # Create a simplified config for the prompt (remove overly verbose data)
    simplified_config = _simplify_config(raw_config)

    # Mask sensitive data before sending to LLM
    masked_config = mask_finding({"raw_config": simplified_config})["raw_config"]

    if debug:
        debug.log_custom("Data masking applied to protect sensitive information")
        masking_stats = get_masking_summary(simplified_config, masked_config)
        debug.log_custom(f"  Account IDs masked: {masking_stats['account_ids_masked']}")
        debug.log_custom(f"  IP addresses masked: {masking_stats['ip_addresses_masked']}")
        debug.log_custom(f"  Resource names masked: {masking_stats['resource_names_masked']}")
        debug.log_data_transformation("config simplification + masking", raw_config, masked_config)

    prompt = f"""You are a cloud security expert analyzing AWS misconfigurations.

Analyze this security finding and provide a comprehensive explanation:

**Finding Details:**
- Resource Type: {resource_type}
- Resource ID: {resource_id}
- Issue: {issue}
- Severity: {severity}

**Configuration Context:**
{json.dumps(masked_config, indent=2)}

Note: Sensitive data (account IDs, IP addresses, resource names) has been masked for privacy.

Please provide your response in the following JSON format:
{{
  "developer_explanation": "A technical explanation for developers (2-3 sentences). Explain what the issue is, why it's a security concern, and potential attack vectors.",
  "manager_summary": "An executive summary for management (1-2 sentences). Focus on business risk and impact without technical jargon.",
  "remediation_steps": "Step-by-step instructions to fix this issue in the AWS console. Be specific and actionable. Use numbered steps."
}}

Important guidelines:
- Be concise but thorough
- Use clear, professional language
- For remediation steps, provide actual AWS console navigation (e.g., 'Navigate to S3 console → Buckets → bucket-name')
- Focus on practical, actionable advice
- Consider compliance implications (GDPR, HIPAA, PCI-DSS) where relevant"""

    if debug:
        debug.log_llm_prompt(prompt)
        debug.log_custom("Calling Claude API with configuration:")
        debug.log_custom(f"  Model: claude-sonnet-4-20250514")
        debug.log_custom(f"  Max Tokens: 2048")
        debug.log_custom(f"  Temperature: 0.3")

    # Call Claude API
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        temperature=0.3,  # Lower temperature for more consistent technical responses
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    # Parse the response
    response_text = message.content[0].text

    if debug:
        debug.log_llm_response_raw(response_text)
        debug.log_custom(f"LLM Response Stats:")
        debug.log_custom(f"  Input Tokens: {message.usage.input_tokens}")
        debug.log_custom(f"  Output Tokens: {message.usage.output_tokens}")
        debug.log_custom(f"  Stop Reason: {message.stop_reason}")

    # Try to extract JSON from the response
    try:
        if debug:
            debug.log_custom("Parsing LLM response JSON...")

        # Look for JSON block in the response
        if "```json" in response_text:
            json_start = response_text.find("```json") + 7
            json_end = response_text.find("```", json_start)
            json_text = response_text[json_start:json_end].strip()
        elif "{" in response_text and "}" in response_text:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            json_text = response_text[json_start:json_end]
        else:
            json_text = response_text

        explanation = json.loads(json_text)

        if debug:
            debug.log_llm_response_parsed(explanation)

        # Validate required keys
        required_keys = ["developer_explanation", "manager_summary", "remediation_steps"]
        if not all(key in explanation for key in required_keys):
            missing_keys = [k for k in required_keys if k not in explanation]
            if debug:
                debug.log_custom(f"Missing required keys in LLM response: {missing_keys}")
            raise ValueError(f"LLM response missing required keys: {missing_keys}")

        if debug:
            debug.log_custom("✓ LLM response validated successfully")

        return explanation

    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse LLM response: {e}")
        logger.debug(f"Raw LLM response: {response_text}")
        if debug:
            debug.log_error(e, "Parsing LLM response JSON")
            debug.log_custom(f"Extracted JSON text: {json_text if 'json_text' in locals() else 'N/A'}")
        # Fall back to template-based explanation
        raise


def _simplify_config(config: Dict[str, Any], max_depth: int = 3) -> Dict[str, Any]:
    """
    Simplify configuration data for LLM prompt to avoid token overuse.

    Args:
        config: Raw configuration dictionary
        max_depth: Maximum nesting depth to include

    Returns:
        Simplified configuration dictionary
    """
    if not isinstance(config, dict):
        return {}

    simplified = {}
    for key, value in config.items():
        # Skip empty values
        if value is None or value == {} or value == []:
            continue

        # Include important keys
        if isinstance(value, (str, int, bool)):
            simplified[key] = value
        elif isinstance(value, dict) and max_depth > 0:
            nested = _simplify_config(value, max_depth - 1)
            if nested:
                simplified[key] = nested
        elif isinstance(value, list) and len(value) < 10:  # Limit list size
            simplified[key] = value[:5]  # Take first 5 items max

    return simplified


def _generate_template_explanation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate template-based explanation (placeholder for LLM).

    Args:
        finding: Security finding dictionary

    Returns:
        Explanation dictionary
    """
    resource_type = finding.get("resource_type")
    severity = finding.get("severity", "medium").upper()
    issue = finding.get("issue", "Security misconfiguration detected")
    resource_id = finding.get("resource_id", "unknown")

    # Build developer explanation
    developer_explanation = _build_developer_explanation(finding)

    # Build manager summary
    manager_summary = _build_manager_summary(finding)

    # Build remediation steps
    remediation_steps = _build_remediation_steps(finding)

    return {
        "developer_explanation": developer_explanation,
        "manager_summary": manager_summary,
        "remediation_steps": remediation_steps
    }


def _build_developer_explanation(finding: Dict[str, Any]) -> str:
    """Build technical explanation for developers."""
    resource_type = finding.get("resource_type")
    issue = finding.get("issue")
    resource_id = finding.get("resource_id")

    explanations = {
        "s3_bucket": (
            f"The S3 bucket '{resource_id}' has a security misconfiguration: {issue}. "
            "This could allow unauthorized access to sensitive data stored in the bucket. "
            "Public S3 buckets are a common attack vector and have led to numerous data breaches."
        ),
        "iam_role": (
            f"The IAM role '{resource_id}' has overly permissive permissions: {issue}. "
            "Following the principle of least privilege, IAM roles should only have the minimum "
            "permissions required to perform their intended function. Wildcard permissions "
            "can be exploited if the role is compromised."
        ),
        "security_group": (
            f"The security group '{resource_id}' allows unrestricted inbound access: {issue}. "
            "Exposing services to the internet (0.0.0.0/0) increases the attack surface and "
            "makes resources vulnerable to brute-force attacks, exploitation, and unauthorized access."
        ),
        "lambda_function": (
            f"The Lambda function '{resource_id}' has a security misconfiguration: {issue}. "
            "Lambda functions should follow the principle of least privilege for execution roles, "
            "avoid storing secrets in environment variables, and use supported runtimes to receive security updates."
        )
    }

    return explanations.get(
        resource_type,
        f"Security issue detected in {resource_type} '{resource_id}': {issue}"
    )


def _build_manager_summary(finding: Dict[str, Any]) -> str:
    """Build executive summary for management."""
    severity = finding.get("severity", "medium").upper()
    resource_type_display = finding.get("resource_type", "resource").replace("_", " ").title()

    risk_impact = {
        "critical": "immediate data breach or complete system compromise",
        "high": "unauthorized access to sensitive resources or data exposure",
        "medium": "potential security weakness that could be exploited",
        "low": "minor security gap that should be addressed as part of best practices"
    }

    impact = risk_impact.get(finding.get("severity", "medium").lower(), "security risk")

    return (
        f"{severity} severity issue detected in {resource_type_display}. "
        f"This misconfiguration poses a risk of {impact}. "
        f"Remediation is recommended to maintain security compliance and reduce organizational risk."
    )


def _build_remediation_steps(finding: Dict[str, Any]) -> str:
    """Build step-by-step remediation guide."""
    resource_type = finding.get("resource_type")
    resource_id = finding.get("resource_id")
    raw_config = finding.get("raw_config", {})

    remediation_guides = {
        "s3_bucket": _get_s3_remediation(finding),
        "iam_role": _get_iam_remediation(finding),
        "security_group": _get_sg_remediation(finding)
    }

    return remediation_guides.get(
        resource_type,
        "1. Review the resource configuration\n2. Apply security best practices\n3. Test changes in a non-production environment\n4. Deploy fixes to production"
    )


def _get_s3_remediation(finding: Dict[str, Any]) -> str:
    """Get S3-specific remediation steps."""
    issue = finding.get("issue", "").lower()
    resource_id = finding.get("resource_id")

    if "public" in issue:
        return f"""
1. Navigate to S3 console → Buckets → {resource_id}
2. Go to the "Permissions" tab
3. Enable "Block all public access" settings:
   - Block public access to buckets and objects granted through new ACLs
   - Block public access to buckets and objects granted through any ACLs
   - Block public access to buckets and objects granted through new public bucket or access point policies
   - Block public and cross-account access to buckets and objects through any public bucket or access point policies
4. Review and update bucket ACLs to remove public grants
5. Verify no bucket policy allows public access
6. Consider using VPC endpoints for internal AWS access
"""
    elif "encryption" in issue:
        return f"""
1. Navigate to S3 console → Buckets → {resource_id}
2. Go to the "Properties" tab
3. Scroll to "Default encryption"
4. Click "Edit"
5. Choose encryption type:
   - SSE-S3 (AES-256) for AWS-managed keys
   - SSE-KMS for AWS KMS keys (recommended for compliance)
6. Click "Save changes"
7. Consider enabling bucket key to reduce KMS costs
"""
    elif "versioning" in issue:
        return f"""
1. Navigate to S3 console → Buckets → {resource_id}
2. Go to the "Properties" tab
3. Scroll to "Bucket Versioning"
4. Click "Edit"
5. Select "Enable"
6. Click "Save changes"
7. Consider implementing lifecycle policies to manage old versions
"""

    return "Review S3 bucket security settings and apply AWS best practices."


def _get_iam_remediation(finding: Dict[str, Any]) -> str:
    """Get IAM-specific remediation steps."""
    raw_config = finding.get("raw_config", {})
    role_name = raw_config.get("role_name", finding.get("resource_id"))
    policy_name = raw_config.get("policy_name", "the policy")

    return f"""
1. Navigate to IAM console → Roles → {role_name}
2. Review the policy '{policy_name}' that contains wildcard permissions
3. Apply the principle of least privilege:
   - Replace "Action": "*" with specific actions needed (e.g., "s3:GetObject", "s3:PutObject")
   - Replace "Resource": "*" with specific ARNs (e.g., "arn:aws:s3:::my-bucket/*")
4. Create a new policy version with restricted permissions
5. Test the role with new permissions in a non-production environment
6. Monitor CloudTrail logs to ensure the role functions correctly
7. Set the new version as default once validated
8. Consider using AWS Access Analyzer to validate permissions
"""


def _get_sg_remediation(finding: Dict[str, Any]) -> str:
    """Get Security Group-specific remediation steps."""
    raw_config = finding.get("raw_config", {})
    group_name = raw_config.get("group_name", "the security group")
    rule = raw_config.get("rule", {})
    region = raw_config.get("region", "your region")

    port_info = ""
    from_port = rule.get("from_port", "all")
    if from_port != "all":
        port_info = f" on port(s) {from_port}"
        if rule.get("to_port") != from_port:
            port_info = f" on ports {from_port}-{rule.get('to_port')}"

    return f"""
1. Navigate to EC2 console → Security Groups → {group_name} (region: {region})
2. Go to the "Inbound rules" tab
3. Identify the rule allowing 0.0.0.0/0 or ::/0{port_info}
4. Choose one of these options:
   a) Restrict to specific IP ranges (recommended):
      - Click "Edit inbound rules"
      - Replace 0.0.0.0/0 with your organization's IP ranges
      - Add multiple rules if needed for different IP ranges
   b) Remove the rule entirely if not needed
   c) Use AWS Systems Manager Session Manager or VPN for administrative access
5. Click "Save rules"
6. Test connectivity to ensure legitimate access still works
7. Document the change in your change management system
8. Consider implementing AWS WAF for web applications
"""
