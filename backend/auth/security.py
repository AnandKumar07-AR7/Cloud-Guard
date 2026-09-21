"""
CloudGuard — Auth Security Utilities

Password hashing via Argon2id (passlib + argon2-cffi).
JWT encode/decode via python-jose.
Refresh token generation (raw value + SHA-256 hash for storage).

SECURITY RULES:
- Never log the plain password, password_hash, tokens, or JWT secret.
- Argon2id with time_cost=3, memory_cost=65536 (64 MB), parallelism=2.
- JWT HS256 by default; algorithm validated on decode to prevent alg confusion.
- Refresh token raw value is a 256-bit (32-byte) cryptographically random token,
  URL-safe base64 encoded. Only the SHA-256 hex digest is stored.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from core.utils.logging import get_logger

log = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Password hashing — Argon2id via passlib
# ──────────────────────────────────────────────────────────────────────────────

_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__type="ID",           # Argon2id
    argon2__time_cost=3,
    argon2__memory_cost=65536,   # 64 MB
    argon2__parallelism=2,
    argon2__hash_len=32,
)


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using Argon2id.
    Returns the PHC-formatted hash string for storage.
    Never logs the input or output.
    """
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed: str) -> bool:
    """
    Verify a plain-text password against an Argon2id hash.
    Uses constant-time comparison internally via passlib.
    Returns False on any verification error without raising.
    Never logs the input, hash, or result details.
    """
    try:
        return _pwd_context.verify(plain_password, hashed)
    except Exception:
        # passlib may raise on malformed hashes — treat as failure
        return False


# ──────────────────────────────────────────────────────────────────────────────
# JWT — access token
# ──────────────────────────────────────────────────────────────────────────────

_ALGORITHM = "HS256"
_ACCEPTED_ALGORITHMS = ["HS256"]  # Never accept 'none' or RS256 when HS256 is configured


def _get_jwt_secret() -> str:
    """
    Retrieve the JWT signing secret from settings at call time.
    This is done lazily so tests can override via environment before import.
    Raises RuntimeError if the secret is the insecure default in a non-test context.
    """
    from config.settings import settings

    secret = settings.jwt_secret_key
    if not secret:
        raise RuntimeError(
            "JWT_SECRET_KEY is not configured. "
            "Set JWT_SECRET_KEY environment variable before starting CloudGuard."
        )
    # Prevent accidental use of the insecure default outside of demo/test
    if secret == "CHANGE-ME-BEFORE-PRODUCTION" and not _is_safe_context():
        raise RuntimeError(
            "JWT_SECRET_KEY is set to the insecure default. "
            "Set a strong random secret via JWT_SECRET_KEY environment variable."
        )
    return secret


def _is_safe_context() -> bool:
    """True when running under pytest or demo mode with explicit acknowledgement."""
    # Only allow the default key when explicitly in testing via pytest
    return os.environ.get("PYTEST_CURRENT_TEST") is not None


def create_access_token(
    sub: str,
    role: str,
    jti: str,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed JWT access token.

    Claims (minimal):
      sub  — user_id (UUID string)
      role — role name string (informational; backend re-checks DB)
      jti  — unique token ID for revocation tracking
      iss  — issuer (cloudguard service identifier)
      aud  — audience (cloudguard-api)
      iat  — issued at
      exp  — expiration
      type — "access" (explicit token type claim)
    """
    from config.settings import settings

    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub":  sub,
        "role": role,
        "jti":  jti,
        "iss":  settings.jwt_issuer,
        "aud":  settings.jwt_audience,
        "iat":  now,
        "exp":  now + expires_delta,
        "type": "access",
    }
    # Never log payload — it contains sub/role/jti
    return jwt.encode(payload, _get_jwt_secret(), algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Validates:
    - Signature (rejects wrong secret)
    - Algorithm (rejects 'none', RS256, etc.)
    - Expiration
    - Issuer ('iss' must match settings.jwt_issuer)
    - Audience ('aud' must match settings.jwt_audience)
    - Token type ('access')
    - Subject presence

    Raises JWTError on any validation failure.
    Never logs the token or its decoded contents.
    """
    from config.settings import settings

    try:
        payload = jwt.decode(
            token,
            _get_jwt_secret(),
            algorithms=_ACCEPTED_ALGORITHMS,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except JWTError:
        raise

    # Explicit token type check
    if payload.get("type") != "access":
        raise JWTError("Invalid token type")

    # Subject must be present
    if not payload.get("sub"):
        raise JWTError("Token missing subject")

    return payload


# ──────────────────────────────────────────────────────────────────────────────
# Refresh token — raw value generation + hashing
# ──────────────────────────────────────────────────────────────────────────────

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a cryptographically secure refresh token.

    Returns:
        (raw_token, sha256_hex_hash)

    Only the hash is stored in the database.
    The raw token is returned to the client once and never persisted.
    Never logs either value.
    """
    raw = secrets.token_urlsafe(32)  # 256 bits of entropy
    token_hash = _hash_refresh_token(raw)
    return raw, token_hash


def _hash_refresh_token(raw: str) -> str:
    """SHA-256 hex digest of a raw refresh token string."""
    return hashlib.sha256(raw.encode()).hexdigest()


def hash_refresh_token(raw: str) -> str:
    """Public API for hashing a raw refresh token before DB lookup."""
    return _hash_refresh_token(raw)
