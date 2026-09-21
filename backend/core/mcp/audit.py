"""
CloudGuard — MCP Tamper-Evident Audit Logging (Phase 10)
Enforces SHA-256 hash chaining and secret sanitization on all MCP interactions.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from core.db_models import MCPAuditEventDBModel
from core.utils.logging import get_logger

log = get_logger(__name__)

# Keys that must never be recorded in audit logs
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|secret|token|credential|jwt|authorization|api_key|database_url|access_key|private_key)",
    re.IGNORECASE,
)


def sanitize_mcp_audit_details(data: Any, depth: int = 0) -> Any:
    """
    Recursively redacts sensitive keys and values from audit details.
    Guarantees no raw secrets or tokens enter persistent storage.
    """
    if depth > 8:
        return "<max_depth_exceeded>"

    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                clean[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                clean[k] = sanitize_mcp_audit_details(v, depth + 1)
            elif isinstance(v, str) and (
                v.startswith("Bearer ") or v.startswith("ey") or len(v) > 500
            ):
                if v.startswith("Bearer ") or v.startswith("ey"):
                    clean[k] = "[REDACTED_TOKEN]"
                else:
                    clean[k] = v[:200] + "...[TRUNCATED]"
            else:
                clean[k] = v
        return clean
    elif isinstance(data, list):
        return [sanitize_mcp_audit_details(item, depth + 1) for item in data[:50]]
    elif isinstance(data, str) and (data.startswith("Bearer ") or data.startswith("ey")):
        return "[REDACTED_TOKEN]"
    return data


def log_mcp_event(
    session: Session,
    request_id: str,
    correlation_id: str,
    server_id: str,
    tool_name: str,
    operation_class: str,
    authorized: bool,
    status: str,
    latency_ms: int = 0,
    user_id: Optional[str] = None,
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> MCPAuditEventDBModel:
    """
    Persists a cryptographically linked MCP audit event to PostgreSQL.
    """
    safe_details = sanitize_mcp_audit_details(details or {})

    # Fetch last audit event to maintain hash chain
    last_event = session.scalar(
        select(MCPAuditEventDBModel)
        .order_by(desc(MCPAuditEventDBModel.sequence_number))
        .limit(1)
        .with_for_update()
    )

    if last_event:
        seq = last_event.sequence_number + 1
        prev_hash = last_event.event_hash
    else:
        seq = 1
        prev_hash = None

    # Compute deterministic SHA-256 event hash
    hasher = hashlib.sha256()
    payload = (
        f"{seq}|{prev_hash or 'GENESIS'}|{request_id}|{correlation_id}|"
        f"{server_id}|{tool_name}|{operation_class}|{authorized}|{status}|"
        f"{json.dumps(safe_details, sort_keys=True)}"
    )
    hasher.update(payload.encode("utf-8"))
    event_hash = hasher.hexdigest()

    event = MCPAuditEventDBModel(
        event_id=str(uuid.uuid4()),
        request_id=request_id,
        correlation_id=correlation_id,
        user_id=user_id,
        server_id=server_id,
        tool_name=tool_name,
        operation_class=operation_class,
        authorized=authorized,
        status=status,
        latency_ms=latency_ms,
        error_code=error_code,
        safe_details=safe_details,
        sequence_number=seq,
        previous_event_hash=prev_hash,
        event_hash=event_hash,
        timestamp=datetime.now(timezone.utc),
    )
    session.add(event)
    session.commit()
    session.refresh(event)

    log.info(
        "mcp_audit_recorded",
        event_id=event.event_id,
        server_id=server_id,
        tool_name=tool_name,
        status=status,
        seq=seq,
    )
    return event


def verify_mcp_audit_chain(session: Session) -> Tuple[bool, Optional[str]]:
    """
    Verifies that the entire MCP audit chain is intact and untampered.
    Returns:
        (True, None) if verified, (False, error_reason) if tampering detected.
    """
    events = session.scalars(
        select(MCPAuditEventDBModel).order_by(MCPAuditEventDBModel.sequence_number.asc())
    ).all()

    if not events:
        return True, None

    expected_prev = None
    for idx, event in enumerate(events, start=1):
        if event.sequence_number != idx:
            return False, f"Broken sequence at record {event.event_id}: expected {idx}, got {event.sequence_number}"

        if event.previous_event_hash != expected_prev:
            return (
                False,
                f"Broken hash link at sequence {event.sequence_number}: expected {expected_prev}, got {event.previous_event_hash}",
            )

        hasher = hashlib.sha256()
        payload = (
            f"{event.sequence_number}|{event.previous_event_hash or 'GENESIS'}|{event.request_id}|{event.correlation_id}|"
            f"{event.server_id}|{event.tool_name}|{event.operation_class}|{event.authorized}|{event.status}|"
            f"{json.dumps(event.safe_details, sort_keys=True)}"
        )
        hasher.update(payload.encode("utf-8"))
        computed_hash = hasher.hexdigest()

        if computed_hash != event.event_hash:
            return (
                False,
                f"Hash mismatch at sequence {event.sequence_number}: computed {computed_hash}, stored {event.event_hash}",
            )

        expected_prev = event.event_hash

    return True, None
