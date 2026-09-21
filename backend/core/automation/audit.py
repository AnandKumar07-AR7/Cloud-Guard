"""
CloudGuard — Automation Audit Logging & Tamper-Evident Hash Chain (Phase 9)
Enforces application-level append-only audit trail with secret scrubbing and SHA-256 hashing.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_audit_lock = threading.Lock()

from sqlalchemy import select, desc, func, text
from sqlalchemy.orm import Session

from core.db_models import AutomationAuditEventDBModel


SENSITIVE_KEY_PATTERNS = [
    "password", "secret", "token", "key", "credential", "auth",
    "access_key", "secret_key", "refresh_token", "hash", "pwd", "bearer"
]

AWS_KEY_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
HASH_RE = re.compile(r"^\$(?:argon2|2b|6|5|1)\$")


def sanitize_value(val: Any) -> Any:
    """Recursively scrub sensitive patterns from values."""
    if isinstance(val, str):
        if AWS_KEY_RE.search(val) or JWT_RE.search(val) or HASH_RE.search(val):
            return "***REDACTED***"
        if len(val) >= 40 and not any(c in val for c in [" ", "\n", "/"]):
            return "***REDACTED***"
        return val
    elif isinstance(val, dict):
        return {
            k: ("***REDACTED***" if any(bad in k.lower() for bad in SENSITIVE_KEY_PATTERNS) else sanitize_value(v))
            for k, v in val.items()
        }
    elif isinstance(val, list):
        return [sanitize_value(v) for v in val]
    return val


def sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitize safe_details to ensure no secrets or tokens are stored."""
    if not details:
        return {}
    scrubbed = {}
    for k, v in details.items():
        if any(bad in k.lower() for bad in SENSITIVE_KEY_PATTERNS):
            scrubbed[k] = "***REDACTED***"
        else:
            scrubbed[k] = sanitize_value(v)
    return scrubbed


def format_canonical_timestamp(ts: datetime) -> str:
    """Produce deterministic ISO-8601 UTC timestamp string."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def compute_automation_event_hash(
    sequence_number: int,
    event_type: str,
    timestamp_str: str,
    previous_event_hash: Optional[str],
    actor_user_id: Optional[str] = None,
    policy_id: Optional[str] = None,
    remediation_id: Optional[str] = None,
    safe_details: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Computes deterministic SHA-256 hash of canonical audit event representation.
    """
    canonical_payload = {
        "actor_user_id": actor_user_id,
        "event_type": event_type,
        "policy_id": policy_id,
        "previous_event_hash": previous_event_hash,
        "remediation_id": remediation_id,
        "safe_details": safe_details or {},
        "sequence_number": sequence_number,
        "timestamp": timestamp_str,
    }
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def log_automation_event(
    session: Session,
    event_type: str,
    actor_user_id: Optional[str] = None,
    policy_id: Optional[str] = None,
    remediation_id: Optional[str] = None,
    safe_details: Optional[Dict[str, Any]] = None,
) -> AutomationAuditEventDBModel:
    """
    Creates and records a cryptographically linked, sanitized automation audit event.
    """
    with _audit_lock:
        # Serialize sequence assignment across concurrent transactions in PostgreSQL
        try:
            session.execute(text("SELECT pg_advisory_xact_lock(99998888)"))
        except Exception:
            pass

        max_seq = session.scalar(select(func.max(AutomationAuditEventDBModel.sequence_number))) or 0
        sequence_number = max_seq + 1

        last_event = session.scalar(
            select(AutomationAuditEventDBModel)
            .where(AutomationAuditEventDBModel.sequence_number == max_seq)
            .limit(1)
        )
        previous_hash = last_event.event_hash if last_event else None

        now = datetime.now(timezone.utc)
        ts_str = format_canonical_timestamp(now)
        scrubbed_details = sanitize_audit_details(safe_details)

        ev_hash = compute_automation_event_hash(
            sequence_number=sequence_number,
            event_type=event_type,
            timestamp_str=ts_str,
            previous_event_hash=previous_hash,
            actor_user_id=actor_user_id,
            policy_id=policy_id,
            remediation_id=remediation_id,
            safe_details=scrubbed_details,
        )

        audit_entry = AutomationAuditEventDBModel(
            event_type=event_type,
            actor_user_id=actor_user_id,
            policy_id=policy_id,
            remediation_id=remediation_id,
            timestamp=now,
            safe_details=scrubbed_details,
            sequence_number=sequence_number,
            previous_event_hash=previous_hash,
            event_hash=ev_hash,
        )

        session.add(audit_entry)
        session.flush()
        return audit_entry
