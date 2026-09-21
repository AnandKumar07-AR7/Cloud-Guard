"""
CloudGuard — Auth FastAPI Dependencies (Phase 6)

Provides composable, reusable FastAPI dependency functions for:
- Extracting and validating a Bearer token (get_current_user)
- Requiring an authenticated user (require_authenticated_user)
- Requiring a specific permission (require_permission)
- Requiring a specific role (require_role)

IMPORTANT DESIGN NOTES:
1. No global TESTING bypass exists here.
   Tests inject auth via real tokens issued by AuthService.
   The only test accommodation is test_override_get_current_user()
   which may be used in test dependency_overrides — it CANNOT be
   activated accidentally at runtime (it is never registered in main.py).

2. Authorization checks always read from DB state (authoritative RBAC),
   not from JWT claims alone. JWT claims (role field) are informational
   for logging only.

3. 401 = token missing or invalid.
   403 = valid token but insufficient permissions.

4. Authorization header is never logged.
"""
from __future__ import annotations

from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from auth.audit import AuthEvent, log_auth_event
from auth.models import UserDBModel
from auth.repository import RoleRepository, UserRepository
from auth.security import decode_access_token
from core.database import get_db

# OAuth2 bearer scheme — auto_error=False so we can return 401 ourselves
_bearer = HTTPBearer(auto_error=False)


def _get_token_from_request(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    """Extract raw Bearer token string. Raises 401 if missing."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_MISSING_TOKEN",
                "message": "Authentication required. Provide a Bearer token.",
            },
        )
    return credentials.credentials


def get_current_user(
    token: str = Depends(_get_token_from_request),
    db: Session = Depends(get_db),
) -> UserDBModel:
    """
    FastAPI dependency: decode JWT, load user from DB.

    Returns the UserDBModel with role + permissions loaded.
    Raises 401 for any token failure.
    Raises 401 if the user is disabled (token was valid but account deactivated).
    Never logs the token.
    """
    # Decode and validate JWT
    try:
        payload = decode_access_token(token)
    except JWTError as exc:
        log_auth_event(AuthEvent.TOKEN_INVALID)
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_TOKEN_INVALID",
                "message": "Invalid or expired authentication token.",
            },
        ) from exc

    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_TOKEN_INVALID",
                "message": "Invalid token: missing subject.",
            },
        )

    # Load user from DB — authoritative source
    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_TOKEN_INVALID",
                "message": "Authentication token refers to a non-existent account.",
            },
        )

    if not user.is_active:
        log_auth_event(AuthEvent.TOKEN_INVALID, user_id=user_id)
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTH_ACCOUNT_DISABLED",
                "message": "This account has been disabled.",
            },
        )

    return user


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Optional[UserDBModel]:
    """
    Like get_current_user but returns None instead of raising if no token.
    Used for endpoints that are optionally authenticated.
    """
    if credentials is None or not credentials.credentials:
        return None
    try:
        return get_current_user.__wrapped__(credentials.credentials, db)
    except HTTPException:
        return None


def require_permission(permission: str) -> Callable:
    """
    Returns a FastAPI dependency that:
    1. Authenticates the caller (get_current_user)
    2. Loads authoritative permissions from DB (not from JWT)
    3. Returns the user if permission is granted
    4. Raises 403 if permission is absent

    Example:
        @router.get("/scans")
        def list_scans(user = Depends(require_permission("scans.read"))):
            ...
    """
    def _check(
        user: UserDBModel = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserDBModel:
        role_repo = RoleRepository(db)
        user_permissions = role_repo.get_permissions_for_role(user.role_id)

        if permission not in user_permissions:
            log_auth_event(
                AuthEvent.PERMISSION_DENIED,
                user_id=user.user_id,
                permission=permission,
                role=user.role.name if user.role else None,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTH_FORBIDDEN",
                    "message": f"You do not have permission to perform this action.",
                    "required_permission": permission,
                },
            )
        return user

    return _check


def require_role(role: str) -> Callable:
    """
    Returns a FastAPI dependency that requires a specific role.
    Uses authoritative DB role name, not JWT claim.

    Example:
        @router.post("/auth/users")
        def create_user(user = Depends(require_role("ADMIN"))):
            ...
    """
    def _check(
        user: UserDBModel = Depends(get_current_user),
    ) -> UserDBModel:
        user_role = user.role.name if user.role else ""
        if user_role != role:
            log_auth_event(
                AuthEvent.PERMISSION_DENIED,
                user_id=user.user_id,
                role=user_role,
                extra={"required_role": role},
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTH_FORBIDDEN",
                    "message": "You do not have the required role for this action.",
                    "required_role": role,
                },
            )
        return user

    return _check


def require_admin(user: UserDBModel = Depends(get_current_user)) -> UserDBModel:
    """Convenience dependency: require ADMIN role."""
    user_role = user.role.name if user.role else ""
    if user_role != "ADMIN":
        log_auth_event(
            AuthEvent.PERMISSION_DENIED,
            user_id=user.user_id,
            role=user_role,
            extra={"required_role": "ADMIN"},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTH_FORBIDDEN",
                "message": "Administrator role required.",
            },
        )
    return user
