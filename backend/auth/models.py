"""
CloudGuard — Auth SQLAlchemy DB Models (Phase 6)

Defines the identity and RBAC schema.
All tables are managed by Alembic migrations.

SECURITY NOTES:
- password_hash is NEVER returned through any API response schema
- Refresh tokens are stored as SHA-256 hashes only; the raw value never persists
- UUIDs used as primary keys throughout
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ──────────────────────────────────────────────────────────────────────────────
# Role
# ──────────────────────────────────────────────────────────────────────────────

class RoleDBModel(Base):
    """
    A named role (ADMIN, SECURITY_ANALYST, OPERATOR, VIEWER).
    Roles are seeded by migration; they are not created at runtime by users.
    """
    __tablename__ = "roles"

    role_id     = Column(String(36), primary_key=True, default=_uuid)
    name        = Column(String(50), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)

    # Relationships
    users       = relationship("UserDBModel", back_populates="role")
    permissions = relationship(
        "PermissionDBModel",
        secondary="role_permissions",
        back_populates="roles",
    )

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


# ──────────────────────────────────────────────────────────────────────────────
# Permission
# ──────────────────────────────────────────────────────────────────────────────

class PermissionDBModel(Base):
    """
    A granular permission string (e.g. 'scans.read', 'users.manage').
    Seeded by migration from auth.permissions.Permission constants.
    """
    __tablename__ = "permissions"

    permission_id = Column(String(36), primary_key=True, default=_uuid)
    name          = Column(String(100), nullable=False, unique=True, index=True)
    description   = Column(Text, nullable=True)
    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)

    # Relationships
    roles = relationship(
        "RoleDBModel",
        secondary="role_permissions",
        back_populates="permissions",
    )

    def __repr__(self) -> str:
        return f"<Permission {self.name}>"


# ──────────────────────────────────────────────────────────────────────────────
# Role ↔ Permission join table
# ──────────────────────────────────────────────────────────────────────────────

from sqlalchemy import Table

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id",       String(36), ForeignKey("roles.role_id"),            nullable=False),
    Column("permission_id", String(36), ForeignKey("permissions.permission_id"), nullable=False),
    UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
)


# ──────────────────────────────────────────────────────────────────────────────
# User
# ──────────────────────────────────────────────────────────────────────────────

class UserDBModel(Base):
    """
    Application user.

    SECURITY:
    - password_hash must NEVER be included in any Pydantic response schema.
    - is_active=False completely blocks authentication even with valid credentials.
    - last_login_at is updated on successful authentication only.
    """
    __tablename__ = "users"

    user_id       = Column(String(36), primary_key=True, default=_uuid)
    username      = Column(String(100), nullable=False, unique=True, index=True)
    email         = Column(String(255), nullable=True, unique=True, index=True)
    password_hash = Column(Text, nullable=False)

    role_id       = Column(String(36), ForeignKey("roles.role_id"), nullable=False)

    is_active     = Column(Boolean, nullable=False, default=True)
    is_verified   = Column(Boolean, nullable=False, default=True)

    created_at    = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    role           = relationship("RoleDBModel", back_populates="users")
    refresh_tokens = relationship(
        "RefreshTokenDBModel",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_users_username_active", "username", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<User {self.username} role={self.role_id}>"


# ──────────────────────────────────────────────────────────────────────────────
# Refresh Token
# ──────────────────────────────────────────────────────────────────────────────

class RefreshTokenDBModel(Base):
    """
    Persisted refresh token family entry.

    SECURITY DESIGN:
    - The raw refresh token is NEVER stored. Only a SHA-256 hash is persisted.
    - token_family groups tokens issued from the same original login session.
      If a revoked family token is presented (reuse detected), ALL tokens in
      that family are immediately invalidated (token family invalidation).
    - Rotation: every /auth/refresh issues a new token and revokes the old one.
    - Expiry: tokens expire after REFRESH_TOKEN_EXPIRE_DAYS.
    """
    __tablename__ = "refresh_tokens"

    token_id     = Column(String(36), primary_key=True, default=_uuid)
    user_id      = Column(String(36), ForeignKey("users.user_id"), nullable=False, index=True)
    token_hash   = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 hex
    token_family = Column(String(36), nullable=False, index=True)               # UUID grouping login session
    is_revoked   = Column(Boolean, nullable=False, default=False)
    expires_at   = Column(DateTime(timezone=True), nullable=False)
    created_at   = Column(DateTime(timezone=True), nullable=False, default=_now)
    replaced_by  = Column(String(36), nullable=True)  # token_id of the successor, if rotated

    # Relationships
    user = relationship("UserDBModel", back_populates="refresh_tokens")

    def __repr__(self) -> str:
        return f"<RefreshToken user={self.user_id} revoked={self.is_revoked}>"
