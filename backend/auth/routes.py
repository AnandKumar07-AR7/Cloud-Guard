"""
CloudGuard — Auth API Routes (Phase 6)

Route classification:
  POST /auth/login               PUBLIC (no auth required)
  POST /auth/refresh             PUBLIC (with valid refresh token body)
  POST /auth/logout              AUTHENTICATED (any role)
  GET  /auth/me                  AUTHENTICATED (any role)
  POST /auth/change-password     AUTHENTICATED (any role)
  GET  /auth/users               PERMISSION-RESTRICTED: users.read
  POST /auth/users               PERMISSION-RESTRICTED: users.manage
  GET  /auth/users/{user_id}     PERMISSION-RESTRICTED: users.read
  PATCH /auth/users/{user_id}    PERMISSION-RESTRICTED: users.manage
  POST /auth/users/{user_id}/disable  PERMISSION-RESTRICTED: users.manage
  POST /auth/users/{user_id}/enable   PERMISSION-RESTRICTED: users.manage
  POST /auth/users/{user_id}/role     PERMISSION-RESTRICTED: users.manage

SECURITY:
- Login endpoint does NOT reveal whether a username exists.
- IP address is captured for audit events.
- Passwords are never echoed or logged.
- Token values are never logged.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from auth.dependencies import (
    get_current_user,
    require_permission,
)
from auth.models import UserDBModel
from auth.permissions import Permission
from auth.schemas import (
    AccessTokenResponse,
    ChangePasswordRequest,
    CreateUserRequest,
    GoogleAuthRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    SwitchAccountRequest,
    TokenResponse,
    UpdateUserRequest,
    UserListResponse,
    UserResponse,
)
from auth.service import AuthError, AuthService
from core.database import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> Optional[str]:
    """
    Extract the real client IP address.

    SECURITY: X-Forwarded-For is only trusted when the directly connected
    peer (request.client.host) is in the configured TRUSTED_PROXY_IPS list.
    If the peer is not a known proxy, we return the direct socket IP regardless
    of what X-Forwarded-For says, preventing audit log poisoning.

    Configure trusted proxies via TRUSTED_PROXY_IPS env var (comma-separated IPs/CIDRs).
    Docker internal gateway (172.0.0.0/8) and localhost should be added when running
    behind a local nginx or Traefik.
    """
    from config.settings import settings
    import ipaddress

    direct_ip: Optional[str] = request.client.host if request.client else None

    # Only honour the forwarded header if the connected peer is a trusted proxy.
    if direct_ip and settings.trusted_proxy_ips:
        try:
            peer_addr = ipaddress.ip_address(direct_ip)
            for proxy_cidr in settings.trusted_proxy_ips:
                try:
                    # Handle bare IPs and CIDR notation uniformly
                    network = ipaddress.ip_network(proxy_cidr, strict=False)
                    if peer_addr in network:
                        forwarded = request.headers.get("X-Forwarded-For")
                        if forwarded:
                            # Take the leftmost (original client) IP
                            return forwarded.split(",")[0].strip()
                        break
                except ValueError:
                    # Skip malformed CIDR entries
                    continue
        except ValueError:
            pass

    return direct_ip


def _user_to_response(user: UserDBModel) -> UserResponse:
    role_name = user.role.name if user.role else "UNKNOWN"
    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=role_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
        aws_account_id=getattr(user, "aws_account_id", None),
    )


def _auth_error_to_http(exc: AuthError) -> HTTPException:
    code_map = {
        401: "AUTH_INVALID_CREDENTIALS",
        403: "AUTH_FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        400: "VALIDATION_ERROR",
    }
    return HTTPException(
        status_code=exc.status_code,
        detail={
            "error_code": code_map.get(exc.status_code, "AUTH_ERROR"),
            "message": exc.message,
        },
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with username and password",
    description=(
        "Authenticate with username and password. "
        "Returns a short-lived JWT access token, a refresh token, and the user profile. "
        "Authentication failures return a generic message to prevent enumeration."
    ),
)
def login(
    request: Request,
    body: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    ip = _get_client_ip(request)
    svc = AuthService(db)
    try:
        token_resp = svc.login(body.username, body.password, ip_address=ip)
        from auth.repository import UserRepository
        repo = UserRepository(db)
        user_model = repo.get_by_username(body.username)
        if user_model:
            token_resp.user = _user_to_response(user_model)
        return token_resp
    except AuthError as exc:
        raise _auth_error_to_http(exc)


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=201,
    summary="User Registration (Sign Up)",
)
@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=201,
    summary="User Registration (Sign Up alias)",
)
def register(
    request: Request,
    body: RegisterRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    ip = _get_client_ip(request)
    svc = AuthService(db)
    
    # Server-side authorization check: Public registration MUST NOT allow client to choose privileged roles
    if body.role and body.role.upper() != "VIEWER":
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTH_FORBIDDEN",
                "message": f"Privilege escalation rejected: Public registration cannot assign privileged role '{body.role}'. Only VIEWER accounts may be self-registered.",
            },
        )

    try:
        user_model = svc.create_user(
            CreateUserRequest(
                username=body.username,
                password=body.password,
                email=body.email,
                role="VIEWER",
            ),
            actor_user_id=None,
        )
        token_resp = svc.login(body.username, body.password, ip_address=ip)
        token_resp.user = _user_to_response(user_model)
        return token_resp
    except AuthError as exc:
        raise _auth_error_to_http(exc)



@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
    summary="Rotate refresh token and get new access token",
)
def refresh_token(
    body: RefreshRequest,
    db: Session = Depends(get_db),
) -> AccessTokenResponse:
    svc = AuthService(db)
    try:
        return svc.refresh_tokens(body.refresh_token)
    except AuthError as exc:
        raise _auth_error_to_http(exc)


@router.post(
    "/google",
    response_model=TokenResponse,
    summary="Sign in with Google + AWS Account ID verification",
    description=(
        "Authenticate using a Google ID token obtained from Sign-in With Google. "
        "The caller must also supply a valid 12-digit AWS Account ID that is "
        "linked (or will be linked) to their Gmail address. "
        "Only verified @gmail.com addresses are accepted. "
        "New users are auto-provisioned with the VIEWER role."
    ),
)
def google_login(
    request: Request,
    body: GoogleAuthRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    ip = _get_client_ip(request)
    svc = AuthService(db)
    try:
        token_resp = svc.google_login(
            id_token=body.id_token,
            aws_account_id=body.aws_account_id,
            ip_address=ip,
        )
        from auth.security import decode_access_token
        try:
            payload = decode_access_token(token_resp.access_token)
            user_id = payload.get("sub")
            from auth.repository import UserRepository
            repo = UserRepository(db)
            user_model = repo.get_by_id(user_id)
            if user_model:
                token_resp.user = _user_to_response(user_model)
        except Exception:
            pass
        return token_resp
    except AuthError as exc:
        raise _auth_error_to_http(exc)


# ──────────────────────────────────────────────────────────────────────────────
# Authenticated endpoints (any role)
# ──────────────────────────────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
)
def get_me(current_user: UserDBModel = Depends(get_current_user)) -> UserResponse:
    return _user_to_response(current_user)


@router.post(
    "/logout",
    status_code=204,
    summary="Logout — revoke current refresh token family",
)
def logout(
    body: Optional[RefreshRequest] = None,
    current_user: UserDBModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    svc = AuthService(db)
    raw_refresh = body.refresh_token if body else None
    svc.logout(current_user.user_id, raw_refresh_token=raw_refresh)


@router.post(
    "/change-password",
    status_code=204,
    summary="Change own password — requires current password",
)
def change_password(
    body: ChangePasswordRequest,
    current_user: UserDBModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    svc = AuthService(db)
    try:
        svc.change_password(
            current_user.user_id,
            body.current_password,
            body.new_password,
        )
    except AuthError as exc:
        raise _auth_error_to_http(exc)


@router.post(
    "/switch-account",
    response_model=UserResponse,
    summary="Switch or update active AWS Account ID for current session",
)
def switch_account(
    body: SwitchAccountRequest,
    current_user: UserDBModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Switch the active AWS Account ID for the logged in user."""
    current_user.aws_account_id = body.aws_account_id
    db.commit()
    db.refresh(current_user)
    return _user_to_response(current_user)


# ──────────────────────────────────────────────────────────────────────────────
# Admin user management — requires users.read / users.manage
# ──────────────────────────────────────────────────────────────────────────────

@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List users (admin/analyst)",
)
def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_READ)),
    db: Session = Depends(get_db),
) -> UserListResponse:
    from auth.repository import UserRepository
    repo = UserRepository(db)
    users = repo.list(limit=limit, offset=offset)
    total = repo.count()
    return UserListResponse(
        items=[_user_to_response(u) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=201,
    summary="Create a new user (admin only)",
)
def create_user(
    body: CreateUserRequest,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> UserResponse:
    svc = AuthService(db)
    try:
        user = svc.create_user(body, actor_user_id=current_user.user_id)
    except AuthError as exc:
        raise _auth_error_to_http(exc)
    # Re-fetch to load relationship
    from auth.repository import UserRepository
    user = UserRepository(db).get_by_id(user.user_id)
    return _user_to_response(user)


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID (admin/analyst)",
)
def get_user(
    user_id: str,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_READ)),
    db: Session = Depends(get_db),
) -> UserResponse:
    from auth.repository import UserRepository
    user = UserRepository(db).get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "NOT_FOUND", "message": f"User '{user_id}' not found."},
        )
    return _user_to_response(user)


@router.patch(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Update user (admin only)",
)
def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> UserResponse:
    from auth.repository import UserRepository
    svc = AuthService(db)
    repo = UserRepository(db)

    user = repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "NOT_FOUND", "message": "User not found."},
        )

    try:
        if body.role is not None:
            svc.update_user_role(user_id, body.role, actor_user_id=current_user.user_id)
        if body.is_active is not None:
            if body.is_active:
                svc.enable_user(user_id, actor_user_id=current_user.user_id)
            else:
                svc.disable_user(user_id, actor_user_id=current_user.user_id)
        if body.email is not None:
            repo.update_email(user_id, body.email)
            db.commit()
    except AuthError as exc:
        raise _auth_error_to_http(exc)

    user = repo.get_by_id(user_id)
    return _user_to_response(user)


@router.post(
    "/users/{user_id}/disable",
    status_code=204,
    summary="Disable a user account (admin only)",
)
def disable_user(
    user_id: str,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> None:
    svc = AuthService(db)
    try:
        svc.disable_user(user_id, actor_user_id=current_user.user_id)
    except AuthError as exc:
        raise _auth_error_to_http(exc)


@router.post(
    "/users/{user_id}/enable",
    status_code=204,
    summary="Enable a disabled user account (admin only)",
)
def enable_user(
    user_id: str,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> None:
    svc = AuthService(db)
    try:
        svc.enable_user(user_id, actor_user_id=current_user.user_id)
    except AuthError as exc:
        raise _auth_error_to_http(exc)


@router.post(
    "/users/{user_id}/role",
    status_code=204,
    summary="Change a user's role (admin only)",
)
def change_user_role(
    user_id: str,
    body: UpdateUserRequest,
    current_user: UserDBModel = Depends(require_permission(Permission.USERS_MANAGE)),
    db: Session = Depends(get_db),
) -> None:
    if not body.role:
        raise HTTPException(
            status_code=400,
            detail={"error_code": "VALIDATION_ERROR", "message": "role is required."},
        )
    svc = AuthService(db)
    try:
        svc.update_user_role(user_id, body.role, actor_user_id=current_user.user_id)
    except AuthError as exc:
        raise _auth_error_to_http(exc)
