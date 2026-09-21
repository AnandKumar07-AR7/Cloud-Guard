"""
CloudGuard — Auth Repository (Phase 6)

Data access layer for Users, Roles, Permissions, and RefreshTokens.
All DB operations are performed through SQLAlchemy sessions.

SECURITY NOTES:
- UserRepository.get_by_username() performs a case-sensitive lookup.
- get_by_username returns None for both "not found" and "inactive" on
  authentication paths to prevent username enumeration.
- password_hash is fetched internally but never returned through repository
  public methods other than get_for_auth() (which is only called by AuthService).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from auth.models import (
    PermissionDBModel,
    RefreshTokenDBModel,
    RoleDBModel,
    UserDBModel,
)
from core.utils.logging import get_logger

log = get_logger(__name__)


class UserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get_by_id(self, user_id: str) -> Optional[UserDBModel]:
        return self.db.execute(
            select(UserDBModel).where(UserDBModel.user_id == user_id)
        ).scalar_one_or_none()

    def get_by_username(self, username: str) -> Optional[UserDBModel]:
        """
        Case-sensitive username lookup.
        Returns None if not found OR if the user record is somehow invalid.
        Used for non-auth lookup (profile display etc.).
        """
        return self.db.execute(
            select(UserDBModel).where(UserDBModel.username == username)
        ).scalar_one_or_none()

    def get_for_auth(self, username: str) -> Optional[UserDBModel]:
        """
        Lookup for authentication — returns the model including password_hash.
        Called ONLY by AuthService.login(). Do not call from route handlers.
        Returns None for non-existent usernames (does NOT reveal existence).
        """
        return self.db.execute(
            select(UserDBModel).where(UserDBModel.username == username)
        ).scalar_one_or_none()

    def get_by_email(self, email: str) -> Optional[UserDBModel]:
        return self.db.execute(
            select(UserDBModel).where(UserDBModel.email == email)
        ).scalar_one_or_none()

    def list(self, limit: int = 50, offset: int = 0) -> List[UserDBModel]:
        return list(
            self.db.execute(
                select(UserDBModel)
                .order_by(UserDBModel.created_at.desc())
                .offset(offset)
                .limit(limit)
            ).scalars().all()
        )

    def count(self) -> int:
        return self.db.execute(
            select(func.count(UserDBModel.user_id))
        ).scalar_one()

    def username_exists(self, username: str) -> bool:
        return self.db.execute(
            select(func.count(UserDBModel.user_id))
            .where(UserDBModel.username == username)
        ).scalar_one() > 0

    # ── Mutations ─────────────────────────────────────────────────────────────

    def create(
        self,
        username: str,
        password_hash: str,
        role_id: str,
        email: Optional[str] = None,
        is_active: bool = True,
    ) -> UserDBModel:
        user = UserDBModel(
            username=username,
            password_hash=password_hash,
            role_id=role_id,
            email=email,
            is_active=is_active,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def update_last_login(self, user_id: str) -> None:
        user = self.get_by_id(user_id)
        if user:
            user.last_login_at = datetime.now(timezone.utc)

    def update_password(self, user_id: str, new_password_hash: str) -> bool:
        user = self.get_by_id(user_id)
        if not user:
            return False
        user.password_hash = new_password_hash
        user.updated_at = datetime.now(timezone.utc)
        return True

    def set_active(self, user_id: str, is_active: bool) -> bool:
        user = self.get_by_id(user_id)
        if not user:
            return False
        user.is_active = is_active
        user.updated_at = datetime.now(timezone.utc)
        return True

    def update_role(self, user_id: str, role_id: str) -> bool:
        user = self.get_by_id(user_id)
        if not user:
            return False
        user.role_id = role_id
        user.updated_at = datetime.now(timezone.utc)
        return True

    def update_email(self, user_id: str, email: Optional[str]) -> bool:
        user = self.get_by_id(user_id)
        if not user:
            return False
        user.email = email
        user.updated_at = datetime.now(timezone.utc)
        return True


class RoleRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_name(self, name: str) -> Optional[RoleDBModel]:
        return self.db.execute(
            select(RoleDBModel).where(RoleDBModel.name == name)
        ).scalar_one_or_none()

    def get_by_id(self, role_id: str) -> Optional[RoleDBModel]:
        return self.db.execute(
            select(RoleDBModel).where(RoleDBModel.role_id == role_id)
        ).scalar_one_or_none()

    def list_all(self) -> List[RoleDBModel]:
        return list(
            self.db.execute(select(RoleDBModel)).scalars().all()
        )

    def get_permissions_for_role(self, role_id: str) -> List[str]:
        """Returns list of permission name strings for a given role_id."""
        role = self.db.execute(
            select(RoleDBModel).where(RoleDBModel.role_id == role_id)
        ).scalar_one_or_none()
        if not role:
            return []
        return [p.name for p in role.permissions]


class PermissionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_name(self, name: str) -> Optional[PermissionDBModel]:
        return self.db.execute(
            select(PermissionDBModel).where(PermissionDBModel.name == name)
        ).scalar_one_or_none()

    def list_all(self) -> List[PermissionDBModel]:
        return list(
            self.db.execute(select(PermissionDBModel)).scalars().all()
        )


class RefreshTokenRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        user_id: str,
        token_hash: str,
        token_family: str,
        expires_at: datetime,
    ) -> RefreshTokenDBModel:
        rt = RefreshTokenDBModel(
            user_id=user_id,
            token_hash=token_hash,
            token_family=token_family,
            expires_at=expires_at,
        )
        self.db.add(rt)
        self.db.flush()
        return rt

    def get_by_hash(self, token_hash: str) -> Optional[RefreshTokenDBModel]:
        return self.db.execute(
            select(RefreshTokenDBModel)
            .where(RefreshTokenDBModel.token_hash == token_hash)
        ).scalar_one_or_none()

    def revoke_token(self, token_id: str) -> None:
        rt = self.db.execute(
            select(RefreshTokenDBModel)
            .where(RefreshTokenDBModel.token_id == token_id)
        ).scalar_one_or_none()
        if rt:
            rt.is_revoked = True

    def revoke_family(self, token_family: str) -> int:
        """
        Revoke ALL tokens in a family.
        Called when token reuse is detected (security response).
        Returns number of tokens revoked.
        """
        tokens = self.db.execute(
            select(RefreshTokenDBModel)
            .where(RefreshTokenDBModel.token_family == token_family)
            .where(RefreshTokenDBModel.is_revoked.is_(False))
        ).scalars().all()
        for t in tokens:
            t.is_revoked = True
        return len(tokens)

    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke all tokens for a user (logout all sessions)."""
        tokens = self.db.execute(
            select(RefreshTokenDBModel)
            .where(RefreshTokenDBModel.user_id == user_id)
            .where(RefreshTokenDBModel.is_revoked.is_(False))
        ).scalars().all()
        for t in tokens:
            t.is_revoked = True
        return len(tokens)

    def is_valid(self, rt: RefreshTokenDBModel) -> bool:
        """Check if a refresh token record is still usable."""
        now = datetime.now(timezone.utc)
        if rt.is_revoked:
            return False
        # Handle timezone-naive datetimes from DB
        expires = rt.expires_at
        if expires.tzinfo is None:
            from datetime import timezone as tz
            expires = expires.replace(tzinfo=tz.utc)
        return expires > now
