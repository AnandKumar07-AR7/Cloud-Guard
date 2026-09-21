"""
CloudGuard — Remediation Audit Logging & Tamper-Evident Hash Chain
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy.orm import Session
from sqlalchemy import text

from core.db_models import RemediationAuditEventDBModel, RemediationPlanDBModel

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
            # Potential raw secret / hash / long token
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
    """Sanitize safe_details to ensure no secrets, credentials, or hashes are stored."""
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


def compute_event_hash(
    remediation_id: str,
    sequence_number: int,
    event_type: str,
    timestamp_str: str,
    previous_event_hash: Optional[str],
    actor_user_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    previous_state: Optional[str] = None,
    new_state: Optional[str] = None,
    request_id: Optional[str] = None,
    safe_details: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Deterministically computes SHA-256 hash of canonical audit event representation.
    """
    canonical_payload = {
        "actor_user_id": actor_user_id,
        "event_type": event_type,
        "execution_id": execution_id,
        "new_state": new_state,
        "previous_event_hash": previous_event_hash,
        "previous_state": previous_state,
        "remediation_id": remediation_id,
        "request_id": request_id,
        "safe_details": safe_details or {},
        "sequence_number": sequence_number,
        "timestamp": timestamp_str,
    }
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def log_remediation_event(
    session: Session,
    remediation_id: str,
    event_type: str,
    actor_user_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    previous_state: Optional[str] = None,
    new_state: Optional[str] = None,
    request_id: Optional[str] = None,
    safe_details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
) -> RemediationAuditEventDBModel:
    """
    Append-only tamper-evident audit event.
    Automatically scrubs known secret patterns if inadvertently passed.
    Computes cryptographic SHA-256 hash chained to the previous event for this plan.
    Uses concurrency locking to ensure linear sequence and hash integrity under concurrent execution.
    """
    scrubbed_details = sanitize_audit_details(safe_details)

    # Concurrency control: serialize audit writes per remediation_id
    try:
        bind = session.get_bind()
        if bind and bind.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"remediation_audit_chain:{remediation_id}"}
            )
    except Exception:
        pass

    # Also lock the plan row if already persisted
    try:
        session.query(RemediationPlanDBModel).filter_by(
            remediation_id=remediation_id
        ).with_for_update().first()
    except Exception:
        pass

    # Find last audit event for this remediation plan
    last_event = (
        session.query(RemediationAuditEventDBModel)
        .filter_by(remediation_id=remediation_id)
        .order_by(
            RemediationAuditEventDBModel.sequence_number.desc(),
            RemediationAuditEventDBModel.timestamp.desc()
        )
        .first()
    )

    if last_event:
        sequence_number = (last_event.sequence_number or 0) + 1
        previous_event_hash = last_event.event_hash
    else:
        sequence_number = 1
        previous_event_hash = None

    now = timestamp or datetime.now(timezone.utc)
    ts_str = format_canonical_timestamp(now)

    event_hash = compute_event_hash(
        remediation_id=remediation_id,
        sequence_number=sequence_number,
        event_type=event_type,
        timestamp_str=ts_str,
        previous_event_hash=previous_event_hash,
        actor_user_id=actor_user_id,
        execution_id=execution_id,
        previous_state=previous_state,
        new_state=new_state,
        request_id=request_id,
        safe_details=scrubbed_details,
    )

    event = RemediationAuditEventDBModel(
        remediation_id=remediation_id,
        sequence_number=sequence_number,
        event_type=event_type,
        actor_user_id=actor_user_id,
        execution_id=execution_id,
        timestamp=now,
        previous_state=previous_state,
        new_state=new_state,
        request_id=request_id,
        safe_details=scrubbed_details,
        previous_event_hash=previous_event_hash,
        event_hash=event_hash,
    )

    session.add(event)
    session.flush()
    return event


def verify_audit_chain(session: Session, remediation_id: str) -> Dict[str, Any]:
    """
    Verify the cryptographic hash chain and sequence integrity of audit events for a plan.
    Returns a dictionary with status 'VALID' or 'INVALID' and diagnostic info.
    """
    events = (
        session.query(RemediationAuditEventDBModel)
        .filter_by(remediation_id=remediation_id)
        .order_by(
            RemediationAuditEventDBModel.sequence_number.asc(),
            RemediationAuditEventDBModel.timestamp.asc()
        )
        .all()
    )

    if not events:
        return {
            "status": "VALID",
            "verified": True,
            "events_count": 0,
            "message": "No audit events found for plan",
        }

    expected_prev_hash = None
    for idx, ev in enumerate(events, start=1):
        # 1. Verify sequence number
        if ev.sequence_number != idx:
            return {
                "status": "INVALID",
                "verified": False,
                "events_count": len(events),
                "error": f"Sequence break at index {idx}: expected {idx}, got {ev.sequence_number}",
                "event_id": ev.event_id,
            }

        # 2. Verify previous event hash linkage
        if ev.previous_event_hash != expected_prev_hash:
            return {
                "status": "INVALID",
                "verified": False,
                "events_count": len(events),
                "error": f"Hash linkage broken at sequence {idx}: expected {expected_prev_hash}, got {ev.previous_event_hash}",
                "event_id": ev.event_id,
            }

        # 3. Verify event hash computation
        ts_str = format_canonical_timestamp(ev.timestamp)
        details = ev.safe_details
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}

        expected_hash = compute_event_hash(
            remediation_id=ev.remediation_id,
            sequence_number=ev.sequence_number,
            event_type=ev.event_type,
            timestamp_str=ts_str,
            previous_event_hash=ev.previous_event_hash,
            actor_user_id=ev.actor_user_id,
            execution_id=ev.execution_id,
            previous_state=ev.previous_state,
            new_state=ev.new_state,
            request_id=ev.request_id,
            safe_details=details,
        )

        if ev.event_hash != expected_hash:
            return {
                "status": "INVALID",
                "verified": False,
                "events_count": len(events),
                "error": f"Tampered event detected at sequence {idx}: computed hash does not match stored hash",
                "event_id": ev.event_id,
            }

        expected_prev_hash = ev.event_hash

    return {
        "status": "VALID",
        "verified": True,
        "events_count": len(events),
        "head_hash": events[-1].event_hash,
    }
