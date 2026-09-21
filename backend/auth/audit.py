"""
CloudGuard — Auth Audit Event Logging (Phase 6)

Records authentication security events using the existing structlog infrastructure.

SECURITY RULES enforced here:
- NEVER log: passwords, password_hashes, access tokens, refresh tokens,
  JWT secrets, DATABASE_URL, Authorization headers.
- Log only: event type, user_id (not username where avoidable), IP,
  timestamp, and non-sensitive contextual details.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from core.utils.logging import get_logger

log = get_logger(__name__)


class AuthEvent(str, Enum):
    LOGIN_SUCCESS       = "auth.login.success"
    LOGIN_FAILURE       = "auth.login.failure"       # No username in log — privacy
    LOGOUT              = "auth.logout"
    TOKEN_REFRESH       = "auth.token.refresh"
    TOKEN_REVOKED       = "auth.token.revoked"
    TOKEN_INVALID       = "auth.token.invalid"
    PASSWORD_CHANGED    = "auth.password.changed"
    USER_CREATED        = "auth.user.created"
    USER_DISABLED       = "auth.user.disabled"
    USER_ENABLED        = "auth.user.enabled"
    ROLE_CHANGED        = "auth.role.changed"
    PERMISSION_DENIED   = "auth.permission.denied"
    TOKEN_REUSE_DETECTED = "auth.token.reuse_detected"  # Security alert


def log_auth_event(
    event: AuthEvent,
    *,
    user_id: Optional[str] = None,
    actor_user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    permission: Optional[str] = None,
    role: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """
    Emit a structured authentication audit event.

    Args:
        event:          The auth event type (AuthEvent enum).
        user_id:        The subject user (who the action is about).
        actor_user_id:  Who performed the action (for admin actions).
        ip_address:     Client IP address for login events.
        permission:     The permission that was checked/denied.
        role:           Role name if relevant.
        extra:          Additional non-sensitive context.

    NEVER pass passwords, tokens, hashes, or secrets to this function.
    """
    payload: dict = {"event": event.value, "level": "info"}

    if user_id:
        payload["user_id"] = user_id
    if actor_user_id:
        payload["actor_user_id"] = actor_user_id
    if ip_address:
        payload["ip_address"] = ip_address
    if permission:
        payload["permission"] = permission
    if role:
        payload["role"] = role
    if extra:
        # Only include the extra dict — caller is responsible for not including secrets
        payload.update(extra)

    # Security events that may indicate attacks get ERROR level
    if event in (AuthEvent.TOKEN_REUSE_DETECTED,):
        log.error(**payload)
    elif event in (AuthEvent.LOGIN_FAILURE, AuthEvent.TOKEN_INVALID, AuthEvent.PERMISSION_DENIED):
        log.warning(**payload)
    else:
        log.info(**payload)
