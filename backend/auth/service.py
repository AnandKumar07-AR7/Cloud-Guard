"""
CloudGuard — Auth Service (Phase 6)

Business logic for authentication, user lifecycle, and token management.

SECURITY RULES:
- login() returns the same generic error for bad credentials AND unknown users
  to prevent username enumeration.
- Disabled users are rejected AFTER the generic failure path (no extra info leak).
- login() calls update_last_login() only on success.
- Token reuse triggers family-wide revocation (all sessions invalidated).
- Never log passwords, hashes, or raw tokens in this layer.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from auth.audit import AuthEvent, log_auth_event
from auth.models import UserDBModel
from auth.permissions import CloudGuardRole
from auth.repository import (
    PermissionRepository,
    RefreshTokenRepository,
    RoleRepository,
    UserRepository,
)
from auth.schemas import (
    CreateUserRequest,
    TokenResponse,
    AccessTokenResponse,
)
from auth.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from core.utils.logging import get_logger

log = get_logger(__name__)


class AuthError(Exception):
    """Raised for authentication/authorization business-logic failures."""
    def __init__(self, message: str, status_code: int = 401) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.user_repo     = UserRepository(db)
        self.role_repo     = RoleRepository(db)
        self.perm_repo     = PermissionRepository(db)
        self.rt_repo       = RefreshTokenRepository(db)

    # ── Login ─────────────────────────────────────────────────────────────────

    def login(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> TokenResponse:
        """
        Authenticate a user and issue access + refresh tokens.

        Failure mode: Always returns the same generic message for wrong
        username OR wrong password to prevent enumeration.
        Disabled users receive the same generic message (no extra info).
        """
        from config.settings import settings

        # Fetch user — may be None
        user = self.user_repo.get_for_auth(username)

        # Evaluate password regardless of whether user exists (timing-safe)
        supplied_hash_placeholder = (
            "$argon2id$v=19$m=65536,t=3,p=2$placeholder$placeholder"
        )
        stored_hash = user.password_hash if user else supplied_hash_placeholder

        password_ok = verify_password(password, stored_hash)

        # Final pass/fail — evaluate in constant-time path
        if not user or not password_ok or not user.is_active:
            log_auth_event(
                AuthEvent.LOGIN_FAILURE,
                ip_address=ip_address,
                # NEVER log the username or password here
            )
            raise AuthError("Invalid credentials.", status_code=401)

        # Issue tokens
        jti = str(uuid.uuid4())
        access_token = create_access_token(
            sub=user.user_id,
            role=user.role.name,
            jti=jti,
        )

        raw_refresh, refresh_hash = generate_refresh_token()
        family_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )

        self.rt_repo.create(
            user_id=user.user_id,
            token_hash=refresh_hash,
            token_family=family_id,
            expires_at=expires_at,
        )
        self.user_repo.update_last_login(user.user_id)
        self.db.commit()

        log_auth_event(
            AuthEvent.LOGIN_SUCCESS,
            user_id=user.user_id,
            ip_address=ip_address,
            role=user.role.name,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            expires_in=settings.access_token_expire_minutes * 60,
        )

    # ── Refresh ───────────────────────────────────────────────────────────────

    def refresh_tokens(self, raw_refresh_token: str) -> AccessTokenResponse:
        """
        Rotate a refresh token, issuing a new access token and new refresh token.
        On reuse detection (presenting a revoked token), the entire family is
        invalidated to protect against token theft.
        """
        from config.settings import settings

        token_hash = hash_refresh_token(raw_refresh_token)
        rt = self.rt_repo.get_by_hash(token_hash)

        if rt is None:
            # Unknown token — no family to invalidate
            raise AuthError("Invalid refresh token.", status_code=401)

        if rt.is_revoked:
            # Reuse detected — invalidate entire family
            revoked_count = self.rt_repo.revoke_family(rt.token_family)
            self.db.commit()
            log_auth_event(
                AuthEvent.TOKEN_REUSE_DETECTED,
                user_id=rt.user_id,
                extra={"family": rt.token_family, "revoked_tokens": revoked_count},
            )
            raise AuthError("Refresh token reuse detected. All sessions revoked.", status_code=401)

        if not self.rt_repo.is_valid(rt):
            raise AuthError("Refresh token expired or invalid.", status_code=401)

        # Fetch user (may have been disabled since token was issued)
        user = self.user_repo.get_by_id(rt.user_id)
        if not user or not user.is_active:
            self.rt_repo.revoke_token(rt.token_id)
            self.db.commit()
            raise AuthError("Account is disabled.", status_code=401)

        # Revoke old token
        self.rt_repo.revoke_token(rt.token_id)

        # Issue new tokens
        jti = str(uuid.uuid4())
        new_access_token = create_access_token(
            sub=user.user_id,
            role=user.role.name,
            jti=jti,
        )
        new_raw, new_hash = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )
        new_rt = self.rt_repo.create(
            user_id=user.user_id,
            token_hash=new_hash,
            token_family=rt.token_family,  # Same family, rotated
            expires_at=expires_at,
        )
        # Link predecessor to successor for audit trail
        rt.replaced_by = new_rt.token_id

        self.db.commit()

        log_auth_event(AuthEvent.TOKEN_REFRESH, user_id=user.user_id, role=user.role.name)

        return AccessTokenResponse(
            access_token=new_access_token,
            refresh_token=new_raw,
            expires_in=settings.access_token_expire_minutes * 60,
        )

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(self, user_id: str, raw_refresh_token: Optional[str] = None) -> None:
        """
        Revoke refresh token(s) for a user.
        If raw_refresh_token is provided, only that token's family is revoked.
        Otherwise, all tokens for the user are revoked (logout all devices).
        """
        if raw_refresh_token:
            token_hash = hash_refresh_token(raw_refresh_token)
            rt = self.rt_repo.get_by_hash(token_hash)
            if rt and rt.user_id == user_id:
                self.rt_repo.revoke_family(rt.token_family)
        else:
            self.rt_repo.revoke_all_for_user(user_id)

        self.db.commit()
        log_auth_event(AuthEvent.LOGOUT, user_id=user_id)

    # ── User management ───────────────────────────────────────────────────────

    def create_user(
        self,
        request: CreateUserRequest,
        actor_user_id: str,
    ) -> UserDBModel:
        """Admin creates a new user. Raises AuthError if username taken."""
        if self.user_repo.username_exists(request.username):
            raise AuthError(
                f"Username '{request.username}' already exists.",
                status_code=409,
            )

        role = self.role_repo.get_by_name(request.role)
        if not role:
            raise AuthError(f"Role '{request.role}' not found.", status_code=400)

        pw_hash = hash_password(request.password)
        user = self.user_repo.create(
            username=request.username,
            password_hash=pw_hash,
            role_id=role.role_id,
            email=request.email,
        )
        self.db.commit()

        log_auth_event(
            AuthEvent.USER_CREATED,
            user_id=user.user_id,
            actor_user_id=actor_user_id,
            role=request.role,
        )
        return user

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """User changes their own password. Validates current password first."""
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise AuthError("User not found.", status_code=404)

        if not verify_password(current_password, user.password_hash):
            raise AuthError("Current password is incorrect.", status_code=401)

        new_hash = hash_password(new_password)
        self.user_repo.update_password(user_id, new_hash)
        # Revoke all refresh tokens — force re-login after password change
        self.rt_repo.revoke_all_for_user(user_id)
        self.db.commit()

        log_auth_event(AuthEvent.PASSWORD_CHANGED, user_id=user_id)

    def disable_user(self, user_id: str, actor_user_id: str) -> None:
        """Admin disables a user account. Revokes all their refresh tokens."""
        ok = self.user_repo.set_active(user_id, False)
        if not ok:
            raise AuthError("User not found.", status_code=404)
        self.rt_repo.revoke_all_for_user(user_id)
        self.db.commit()
        log_auth_event(AuthEvent.USER_DISABLED, user_id=user_id, actor_user_id=actor_user_id)

    def enable_user(self, user_id: str, actor_user_id: str) -> None:
        """Admin re-enables a disabled user account."""
        ok = self.user_repo.set_active(user_id, True)
        if not ok:
            raise AuthError("User not found.", status_code=404)
        self.db.commit()
        log_auth_event(AuthEvent.USER_ENABLED, user_id=user_id, actor_user_id=actor_user_id)

    def update_user_role(
        self, user_id: str, new_role: str, actor_user_id: str
    ) -> None:
        """Admin changes a user's role. Revokes existing tokens to force re-login."""
        role = self.role_repo.get_by_name(new_role)
        if not role:
            raise AuthError(f"Role '{new_role}' not found.", status_code=400)

        ok = self.user_repo.update_role(user_id, role.role_id)
        if not ok:
            raise AuthError("User not found.", status_code=404)

        self.rt_repo.revoke_all_for_user(user_id)
        self.db.commit()

        log_auth_event(
            AuthEvent.ROLE_CHANGED,
            user_id=user_id,
            actor_user_id=actor_user_id,
            role=new_role,
        )

    def get_user_permissions(self, user: UserDBModel) -> list[str]:
        """
        Retrieve the current authoritative set of permissions for a user.
        Reads from DB (not from JWT claims).
        """
        if not user.role_id:
            return []
        return self.role_repo.get_permissions_for_role(user.role_id)

    # ── Seeding (demo/test only) ───────────────────────────────────────────────

    def seed_demo_admin(self, username: str, password: str) -> Optional[UserDBModel]:
        """
        Create a demo admin user if one doesn't already exist.
        ONLY called when CLOUDGUARD_MODE=demo.
        Never called in production/AWS mode.
        Never logs the password.
        """
        if self.user_repo.username_exists(username):
            log.info("demo_admin_exists", username=username)
            return None

        admin_role = self.role_repo.get_by_name(CloudGuardRole.ADMIN.value)
        if not admin_role:
            log.error("demo_seed_failed_no_admin_role")
            return None

        pw_hash = hash_password(password)
        user = self.user_repo.create(
            username=username,
            password_hash=pw_hash,
            role_id=admin_role.role_id,
            email=None,
        )
        self.db.commit()
        log.info("demo_admin_created", user_id=user.user_id)
        # NEVER log username or password here
        return user
