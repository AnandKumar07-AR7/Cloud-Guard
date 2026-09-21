"""
Normalization utilities for standardizing data formats.
"""

from typing import Dict, Any, List


def normalize_severity(severity: str) -> str:
    """
    Normalize severity levels to standard values.

    Args:
        severity: Raw severity string

    Returns:
        Normalized severity: "critical", "high", "medium", or "low"
    """
    severity_lower = severity.lower().strip()

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "low",
        "informational": "low"
    }

    return severity_map.get(severity_lower, "medium")


def normalize_cidr(cidr: str) -> str:
    """
    Normalize CIDR notation.

    Args:
        cidr: CIDR string

    Returns:
        Normalized CIDR string
    """
    return cidr.strip().lower()


def is_public_cidr(cidr: str) -> bool:
    """
    Check if a CIDR block represents public internet access.

    Args:
        cidr: CIDR string (e.g., "0.0.0.0/0" or "::/0")

    Returns:
        True if CIDR represents public access, False otherwise
    """
    public_cidrs = ["0.0.0.0/0", "::/0"]
    return normalize_cidr(cidr) in public_cidrs


def extract_policy_statements(policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract statements from an IAM policy document.

    Args:
        policy_document: IAM policy document dictionary

    Returns:
        List of policy statements
    """
    if not policy_document:
        return []

    statements = policy_document.get('Statement', [])

    # Ensure statements is a list
    if isinstance(statements, dict):
        statements = [statements]

    return statements


def has_wildcard_action(statement: Dict[str, Any]) -> bool:
    """
    Check if a policy statement contains wildcard actions.

    Args:
        statement: IAM policy statement

    Returns:
        True if statement has wildcard action ("*")
    """
    actions = statement.get('Action', [])

    # Normalize to list
    if isinstance(actions, str):
        actions = [actions]

    return '*' in actions


def has_wildcard_resource(statement: Dict[str, Any]) -> bool:
    """
    Check if a policy statement contains wildcard resources.

    Args:
        statement: IAM policy statement

    Returns:
        True if statement has wildcard resource ("*")
    """
    resources = statement.get('Resource', [])

    # Normalize to list
    if isinstance(resources, str):
        resources = [resources]

    return '*' in resources


def is_allow_statement(statement: Dict[str, Any]) -> bool:
    """
    Check if a policy statement has Allow effect.

    Args:
        statement: IAM policy statement

    Returns:
        True if statement has "Allow" effect
    """
    return statement.get('Effect', '').lower() == 'allow'
