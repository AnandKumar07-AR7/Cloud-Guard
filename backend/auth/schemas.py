"""
CloudGuard — Auth Pydantic API Schemas (Phase 6)

SECURITY NOTES:
- UserResponse NEVER includes password_hash, token values, or internal IDs beyond user_id.
- TokenResponse returns raw access token + raw refresh token to client.
  The refresh token is not stored in DB; only its hash is persisted.
- LoginRequest fields are never logged.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# Auth request/response schemas
# ──────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """POST /auth/login"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    """POST /auth/refresh"""
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1)


class RegisterRequest(BaseModel):
    """POST /auth/register or POST /auth/signup"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=128, description="Must be at least 12 characters")
    role: Optional[str] = "VIEWER"


# ──────────────────────────────────────────────────────────────────────────────
# User schemas
# ──────────────────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """
    Public user representation.
    NEVER includes password_hash or raw tokens.
    """
    user_id:       str
    username:      str
    email:         Optional[str] = None
    role:          str
    is_active:     bool
    is_verified:   bool
    created_at:    datetime
    updated_at:    Optional[datetime] = None
    last_login_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    """Successful authentication response."""
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int = Field(description="Access token lifetime in seconds")
    user:          Optional[UserResponse] = None


class AccessTokenResponse(BaseModel):
    """Refresh-only response — new access token, rotated refresh token."""
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int



class CreateUserRequest(BaseModel):
    """POST /auth/users — Admin creates a new user."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=128,
                          description="Must be at least 12 characters")
    email:    Optional[str] = Field(default=None, max_length=255)
    role:     str = Field(description="ADMIN | SECURITY_ANALYST | OPERATOR | VIEWER")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        from auth.permissions import CloudGuardRole
        valid = [r.value for r in CloudGuardRole]
        if v.upper() not in valid:
            raise ValueError(f"Role must be one of: {valid}")
        return v.upper()


class UpdateUserRequest(BaseModel):
    """PATCH /auth/users/{user_id} — Admin updates user fields."""
    model_config = ConfigDict(extra="forbid")

    email:     Optional[str] = Field(default=None, max_length=255)
    is_active: Optional[bool] = None
    role:      Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from auth.permissions import CloudGuardRole
        valid = [r.value for r in CloudGuardRole]
        if v.upper() not in valid:
            raise ValueError(f"Role must be one of: {valid}")
        return v.upper()


class ChangePasswordRequest(BaseModel):
    """POST /auth/change-password — authenticated user changes own password."""
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=128)
    new_password:     str = Field(min_length=12, max_length=128,
                                  description="Must be at least 12 characters")


class UserListResponse(BaseModel):
    """GET /auth/users — paginated user list (admin only)."""
    items:  List[UserResponse]
    total:  int
    limit:  int
    offset: int
