"""
Data masking utility for sensitive information.

This module masks sensitive data before sending it to external services (like LLMs)
while preserving the security-relevant structure and patterns needed for analysis.
"""

import re
from typing import Any, Dict, List, Union


def mask_sensitive_data(data: Any, preserve_public_indicators: bool = True) -> Any:
    """
    Recursively mask sensitive data in configuration objects.

    Args:
        data: Configuration data (dict, list, string, or primitive)
        preserve_public_indicators: Keep public IP indicators like 0.0.0.0/0 unmasked

    Returns:
        Masked version of the data with same structure
    """
    if isinstance(data, dict):
        return {key: mask_sensitive_data(value, preserve_public_indicators)
                for key, value in data.items()}
    elif isinstance(data, list):
        return [mask_sensitive_data(item, preserve_public_indicators) for item in data]
    elif isinstance(data, str):
        return _mask_string(data, preserve_public_indicators)
    else:
        # Return primitives (int, bool, None) as-is
        return data


def _mask_string(value: str, preserve_public_indicators: bool = True) -> str:
    """
    Mask sensitive information in string values.

    Args:
        value: String value to mask
        preserve_public_indicators: Keep public IP indicators unmasked

    Returns:
        Masked string
    """
    # Skip empty strings
    if not value:
        return value

    # Preserve common public access indicators (these are security-relevant)
    if preserve_public_indicators:
        public_indicators = ['0.0.0.0/0', '::/0', '*', 'public', 'Public', 'PUBLIC']
        if value in public_indicators:
            return value

    # Mask AWS Account IDs in ARNs
    # Format: arn:aws:service:region:123456789012:resource
    value = re.sub(
        r'(arn:aws:[^:]*:[^:]*:)(\d{12})(:[^:]*)',
        r'\1XXXXXXXXXXXX\3',
        value
    )

    # Mask standalone AWS Account IDs (12-digit numbers)
    value = re.sub(
        r'\b\d{12}\b',
        'XXXXXXXXXXXX',
        value
    )

    # Mask IP addresses (but preserve public indicators)
    if preserve_public_indicators and value in ['0.0.0.0/0', '::/0']:
        return value

    # Mask IPv4 addresses
    # Match patterns like 192.168.1.1 or 10.0.0.0/16
    value = re.sub(
        r'\b(?!0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?\b',
        lambda m: f"XXX.XXX.XXX.XXX{m.group(1) if m.group(1) else ''}",
        value
    )

    # Mask IPv6 addresses (but preserve ::/0)
    if not (preserve_public_indicators and value == '::/0'):
        value = re.sub(
            r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX',
            value
        )

    # Mask resource names that might contain sensitive info
    # Preserve structure but mask identifying parts
    value = _mask_resource_names(value)

    return value


def _mask_resource_names(value: str) -> str:
    """
    Mask resource names while preserving patterns.

    Examples:
        my-company-prod-bucket -> resource-****-bucket
        user-data-2024 -> resource-****-2024
        internal-api-gateway -> resource-****-gateway

    Args:
        value: Resource name string

    Returns:
        Masked resource name preserving structure
    """
    # Common AWS resource name patterns with hyphens or underscores
    # Mask middle portions while keeping prefixes and suffixes for context

    # Pattern: prefix-sensitive-suffix (3+ segments)
    parts = re.split(r'([-_])', value)

    # If name has multiple segments, mask the middle ones
    if len(parts) >= 5:  # At least 3 segments with 2 separators
        # Keep first and last segment, mask middle ones
        masked_parts = []
        for i, part in enumerate(parts):
            if i == 0:  # First segment
                masked_parts.append('resource')
            elif i == len(parts) - 1:  # Last segment
                masked_parts.append(part)
            elif part in ['-', '_']:  # Separator
                masked_parts.append(part)
            else:  # Middle segments - mask them
                masked_parts.append('****')

        return ''.join(masked_parts)

    # For shorter names, just indicate it's a resource
    elif len(parts) > 1:
        return f"resource-{parts[-1]}"  # Keep the suffix for context

    # Single word resources - keep as is if they're generic terms
    generic_terms = {
        'bucket', 'role', 'policy', 'group', 'function', 'lambda',
        'instance', 'volume', 'snapshot', 'vpc', 'subnet', 'table',
        'queue', 'topic', 'stream', 'cluster', 'database', 'key',
        'default', 'prod', 'dev', 'staging', 'test'
    }

    if value.lower() in generic_terms:
        return value

    # Otherwise, mask it
    return 'resource-name'


def mask_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask sensitive data in a security finding before sending to external services.

    This preserves:
    - Security-relevant indicators (wildcards, public access markers)
    - Resource types and patterns
    - Configuration structure

    While masking:
    - AWS Account IDs
    - Specific IP addresses (except public indicators)
    - Resource names with potentially sensitive information

    Args:
        finding: Security finding dictionary

    Returns:
        New finding dictionary with masked sensitive data
    """
    masked_finding = {}

    for key, value in finding.items():
        if key == 'raw_config':
            # Recursively mask the configuration
            masked_finding[key] = mask_sensitive_data(value, preserve_public_indicators=True)
        elif key in ['resource_id', 'id']:
            # Mask resource IDs but preserve type information
            masked_finding[key] = mask_sensitive_data(value, preserve_public_indicators=True)
        else:
            # Keep other fields (issue, severity, resource_type) as-is
            # These don't typically contain account-specific data
            masked_finding[key] = value

    return masked_finding


def get_masking_summary(original: Dict[str, Any], masked: Dict[str, Any]) -> Dict[str, int]:
    """
    Generate a summary of what was masked.

    Args:
        original: Original data
        masked: Masked data

    Returns:
        Dictionary with counts of masked items
    """
    stats = {
        'account_ids_masked': 0,
        'ip_addresses_masked': 0,
        'resource_names_masked': 0
    }

    original_str = str(original)
    masked_str = str(masked)

    # Count AWS account IDs
    stats['account_ids_masked'] = len(re.findall(r'\b\d{12}\b', original_str))

    # Count IP addresses (excluding public indicators)
    original_ips = re.findall(r'\b(?!0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}\b', original_str)
    stats['ip_addresses_masked'] = len(original_ips)

    # Count masked resource names
    stats['resource_names_masked'] = masked_str.count('resource-') + masked_str.count('****')

    return stats
