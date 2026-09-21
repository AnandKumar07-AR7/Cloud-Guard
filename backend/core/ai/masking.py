"""
CloudGuard — AI Data Masking

Masks sensitive values before sending resource configuration data to AI APIs.
This prevents credential material, secrets, and PII from leaving the system
through AI prompts.

Rules:
  - Environment variable values that match sensitive key patterns → [REDACTED]
  - AWS credential strings (AKIA...) → [AWS_KEY_REDACTED]
  - URLs with embedded credentials → [REDACTED_URL]
  - Account IDs passed to AI are kept only as context, not full config dumps
  - No full config dict is ever sent to the AI; only a curated summary
"""
from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, Set

# Patterns for sensitive environment variable keys
_SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password", "passwd", "secret", "token", "key", "api_key",
    "auth", "credential", "credentials", "private", "access_key",
    "secret_key", "db_pass", "database_password", "apikey", "auth_token",
    "jwt", "signing_key", "encryption_key", "master_key", "db_uri",
    "conn_str", "connection_string", "auth_header", "bearer",
}

# Regex for AWS access key IDs (AKIA + 16 uppercase alphanumeric)
_AWS_KEY_RE = re.compile(r'\bAKIA[0-9A-Z]{16,}\b')
# Regex for URLs with embedded credentials (db uris, http uris, etc.)
_URL_CRED_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9+.-]*://[^:@\s/]+:[^@\s/]+@')
# Regex for JWT tokens (header.payload.signature)
_JWT_RE = re.compile(r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b')
# Regex for API keys (e.g. Anthropic, OpenAI, GitHub, Slack)
_API_KEY_RE = re.compile(r'\b(sk-[a-zA-Z0-9_-]{10,}|ant-api[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{30,}|xox[baprs]-[0-9a-zA-Z]{10,})\b')
# Regex for AWS secret access key assignments
_AWS_SECRET_RE = re.compile(r'(?i)(aws_secret_access_key|secret_key|aws_secret)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?')
# Long hex/base64 strings that look like secrets (40+ chars of hex or base64)
_LONG_SECRET_RE = re.compile(r'\b[0-9a-fA-F]{40,}\b')


def mask_env_vars(env_vars: Dict[str, str]) -> Dict[str, str]:
    """
    Return a copy of environment variables with sensitive values masked.

    The key name is preserved (it helps with detection context) but the
    value is replaced with [REDACTED].

    Args:
        env_vars: Dict of environment variable name → value.

    Returns:
        Masked copy. Original is not mutated.
    """
    masked = {}
    for key, value in env_vars.items():
        if _is_sensitive_key(key):
            masked[key] = "[REDACTED]"
        else:
            masked[key] = _redact_inline_secrets(str(value))
    return masked


def mask_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a deep copy of a resource config dict with sensitive values masked.

    Specifically handles:
      - environment_variables sub-dict
      - Any key that matches a sensitive pattern
      - Inline credential strings in values
    """
    config = deepcopy(config)
    return _mask_dict(config)


def _mask_dict(obj: Any) -> Any:
    """Recursively mask sensitive values in a dict/list/str."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if _is_sensitive_key(str(k)):
                result[k] = "[REDACTED]"
            elif isinstance(v, dict):
                result[k] = _mask_dict(v)
            elif isinstance(v, list):
                result[k] = [_mask_dict(item) for item in v]
            elif isinstance(v, str):
                result[k] = _redact_inline_secrets(v)
            else:
                result[k] = v
        return result
    elif isinstance(obj, list):
        return [_mask_dict(item) for item in obj]
    elif isinstance(obj, str):
        return _redact_inline_secrets(obj)
    return obj


def _is_sensitive_key(key: str) -> bool:
    """Return True if the key name matches a known sensitive pattern."""
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in _SENSITIVE_KEY_PATTERNS)


def _redact_inline_secrets(value: str) -> str:
    """Redact known secret patterns within a string value."""
    value = _AWS_KEY_RE.sub("[AWS_KEY_REDACTED]", value)
    value = _URL_CRED_RE.sub("[REDACTED_URL]//", value)
    value = _JWT_RE.sub("[REDACTED]", value)
    value = _API_KEY_RE.sub("[REDACTED]", value)
    value = _AWS_SECRET_RE.sub(r"\1=[REDACTED]", value)
    return value


def mask_finding_evidence_for_ai(evidence_observed: Any) -> Any:
    """
    Prepare the observed evidence value for inclusion in an AI prompt.
    Strips potential secret values while preserving diagnostic context.
    """
    if isinstance(evidence_observed, str):
        try:
            parsed = json.loads(evidence_observed)
            if isinstance(parsed, (dict, list)):
                return _mask_dict(parsed)
        except Exception:
            pass
    elif isinstance(evidence_observed, dict):
        return mask_config(evidence_observed)
    elif isinstance(evidence_observed, list):
        return [_mask_dict(item) for item in evidence_observed]

    value_str = str(evidence_observed)
    value_str = _redact_inline_secrets(value_str)
    # Truncate long values
    if len(value_str) > 300:
        value_str = value_str[:300] + "...[truncated]"
    return value_str


