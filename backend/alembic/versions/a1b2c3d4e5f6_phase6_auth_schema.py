"""Phase 6 — Auth schema: roles, permissions, role_permissions, users, refresh_tokens

Revision ID: a1b2c3d4e5f6
Revises: 864b9e54f89f
Create Date: 2026-09-05

This migration:
1. Creates roles, permissions, role_permissions join table
2. Creates users table (references roles)
3. Creates refresh_tokens table (references users)
4. Seeds the 4 default roles and all permissions
5. Assigns the correct permission sets to each role per ROLE_PERMISSIONS matrix
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "864b9e54f89f"
branch_labels = None
depends_on = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


def upgrade() -> None:
    # ── roles ─────────────────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("role_id",     sa.String(36), primary_key=True),
        sa.Column("name",        sa.String(50),  nullable=False, unique=True),
        sa.Column("description", sa.Text,        nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_roles_name", "roles", ["name"], unique=True)

    # ── permissions ───────────────────────────────────────────────────────────
    op.create_table(
        "permissions",
        sa.Column("permission_id", sa.String(36), primary_key=True),
        sa.Column("name",          sa.String(100), nullable=False, unique=True),
        sa.Column("description",   sa.Text,        nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_permissions_name", "permissions", ["name"], unique=True)

    # ── role_permissions ──────────────────────────────────────────────────────
    op.create_table(
        "role_permissions",
        sa.Column("role_id",       sa.String(36), sa.ForeignKey("roles.role_id"),            nullable=False),
        sa.Column("permission_id", sa.String(36), sa.ForeignKey("permissions.permission_id"), nullable=False),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("user_id",       sa.String(36), primary_key=True),
        sa.Column("username",      sa.String(100), nullable=False, unique=True),
        sa.Column("email",         sa.String(255), nullable=True,  unique=True),
        sa.Column("password_hash", sa.Text,        nullable=False),
        sa.Column("role_id",       sa.String(36), sa.ForeignKey("roles.role_id"), nullable=False),
        sa.Column("is_active",     sa.Boolean,     nullable=False, default=True),
        sa.Column("is_verified",   sa.Boolean,     nullable=False, default=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_username",        "users", ["username"],                unique=True)
    op.create_index("ix_users_email",           "users", ["email"],                   unique=True)
    op.create_index("ix_users_username_active", "users", ["username", "is_active"])

    # ── refresh_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("token_id",     sa.String(36), primary_key=True),
        sa.Column("user_id",      sa.String(36), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("token_hash",   sa.String(64), nullable=False, unique=True),
        sa.Column("token_family", sa.String(36), nullable=False),
        sa.Column("is_revoked",   sa.Boolean,    nullable=False, default=False),
        sa.Column("expires_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("replaced_by",  sa.String(36), nullable=True),
    )
    op.create_index("ix_refresh_tokens_user_id",      "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash",   "refresh_tokens", ["token_hash"],   unique=True)
    op.create_index("ix_refresh_tokens_token_family", "refresh_tokens", ["token_family"])

    # ── Seed roles and permissions ────────────────────────────────────────────
    _seed_roles_and_permissions()


def _seed_roles_and_permissions() -> None:
    """
    Seed the 4 default roles, all permissions, and the role→permission matrix.
    This matches auth.permissions.ROLE_PERMISSIONS exactly.
    """
    from auth.permissions import CloudGuardRole, Permission, ROLE_PERMISSIONS

    roles_table      = sa.table("roles",      sa.column("role_id"), sa.column("name"), sa.column("description"), sa.column("created_at"))
    perms_table      = sa.table("permissions", sa.column("permission_id"), sa.column("name"), sa.column("description"), sa.column("created_at"))
    role_perms_table = sa.table("role_permissions", sa.column("role_id"), sa.column("permission_id"))

    now = _now()

    # Insert roles
    role_descriptions = {
        CloudGuardRole.ADMIN:            "Full administrative access to all CloudGuard features.",
        CloudGuardRole.SECURITY_ANALYST: "Read security data, scans, findings, investigation, rules, posture, and audit.",
        CloudGuardRole.OPERATOR:         "Operational read access plus scan creation.",
        CloudGuardRole.VIEWER:           "Read-only security visibility. No management or write access.",
    }
    role_id_map: dict[str, str] = {}
    for role in CloudGuardRole:
        rid = _uuid()
        role_id_map[role.value] = rid
        op.bulk_insert(roles_table, [{
            "role_id":     rid,
            "name":        role.value,
            "description": role_descriptions[role],
            "created_at":  now,
        }])

    # Insert all permissions
    all_perm_names = Permission.all_permissions()
    perm_id_map: dict[str, str] = {}
    perm_descriptions = {
        Permission.DASHBOARD_READ:     "View security dashboard.",
        Permission.ASSETS_READ:        "View cloud assets.",
        Permission.RESOURCES_READ:     "Browse resource explorer.",
        Permission.SCANS_READ:         "List and view security scans.",
        Permission.SCANS_CREATE:       "Initiate new security scans.",
        Permission.FINDINGS_READ:      "View security findings.",
        Permission.FINDINGS_UPDATE:    "Update finding status.",
        Permission.RULES_READ:         "View detection rule catalog.",
        Permission.POSTURE_READ:       "View security posture scores.",
        Permission.INVESTIGATION_READ: "Access finding investigation context.",
        Permission.REPORTS_READ:       "View security reports.",
        Permission.AUDIT_READ:         "Read authentication and security audit events.",
        Permission.USERS_READ:         "List and view user accounts.",
        Permission.USERS_MANAGE:       "Create, update, and disable user accounts.",
        Permission.SETTINGS_MANAGE:    "Manage application settings.",
    }
    for pname in all_perm_names:
        pid = _uuid()
        perm_id_map[pname] = pid
        op.bulk_insert(perms_table, [{
            "permission_id": pid,
            "name":          pname,
            "description":   perm_descriptions.get(pname, pname),
            "created_at":    now,
        }])

    # Assign permissions to roles per the matrix
    for role, perms in ROLE_PERMISSIONS.items():
        rid = role_id_map[role.value]
        for pname in perms:
            pid = perm_id_map.get(pname)
            if pid:
                op.bulk_insert(role_perms_table, [{
                    "role_id":       rid,
                    "permission_id": pid,
                }])


def downgrade() -> None:
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
