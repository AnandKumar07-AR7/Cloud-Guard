"""
CloudGuard — Auth Permission Constants and Role Matrix

This is the single authoritative source for all permission strings and the
role → permission mapping. Backend authorization checks query DB state at
runtime; these constants ensure consistency between code and DB seeding.
"""
from __future__ import annotations

from enum import Enum


# ──────────────────────────────────────────────────────────────────────────────
# Roles
# ──────────────────────────────────────────────────────────────────────────────

class CloudGuardRole(str, Enum):
    ADMIN             = "ADMIN"
    SECURITY_ANALYST  = "SECURITY_ANALYST"
    OPERATOR          = "OPERATOR"
    VIEWER            = "VIEWER"


# ──────────────────────────────────────────────────────────────────────────────
# Permission strings — single canonical definition
# ──────────────────────────────────────────────────────────────────────────────

class Permission:
    # Dashboard
    DASHBOARD_READ      = "dashboard.read"

    # Assets / Resources
    ASSETS_READ         = "assets.read"
    RESOURCES_READ      = "resources.read"

    # Scans
    SCANS_READ          = "scans.read"
    SCANS_CREATE        = "scans.create"

    # Findings
    FINDINGS_READ       = "findings.read"
    FINDINGS_UPDATE     = "findings.update"

    # Rules
    RULES_READ          = "rules.read"

    # Posture
    POSTURE_READ        = "posture.read"

    # Investigation
    INVESTIGATION_READ  = "investigation.read"

    # Reports
    REPORTS_READ        = "reports.read"

    # Audit
    AUDIT_READ          = "audit.read"

    # User management (admin only)
    USERS_READ          = "users.read"
    USERS_MANAGE        = "users.manage"

    # Settings (admin only)
    SETTINGS_MANAGE     = "settings.manage"

    # Remediation (Phase 7)
    REMEDIATIONS_READ     = "remediations.read"
    REMEDIATIONS_CREATE   = "remediations.create"
    REMEDIATIONS_VALIDATE = "remediations.validate"
    REMEDIATIONS_APPROVE  = "remediations.approve"
    REMEDIATIONS_EXECUTE  = "remediations.execute"
    REMEDIATIONS_CANCEL   = "remediations.cancel"
    REMEDIATIONS_AUDIT_READ = "remediations.audit.read"

    # AI Orchestration (Phase 8)
    AI_ANALYZE              = "ai.analyze"
    AI_READ                 = "ai.read"
    AI_AUDIT_READ           = "ai.audit.read"
    AI_ADMIN                = "ai.admin"

    # Automation Orchestration (Phase 9)
    AUTOMATION_READ         = "automation.read"
    AUTOMATION_EVALUATE     = "automation.evaluate"
    AUTOMATION_MANAGE       = "automation.manage"
    AUTOMATION_KILLSWITCH   = "automation.killswitch"
    AUTOMATION_AUDIT_READ   = "automation.audit.read"

    # Model Context Protocol (Phase 10)
    MCP_READ                = "mcp.read"
    MCP_EXECUTE             = "mcp.execute"
    MCP_MANAGE              = "mcp.manage"
    MCP_AUDIT_READ          = "mcp.audit.read"

    @classmethod
    def all_permissions(cls) -> list[str]:
        return [
            v for k, v in vars(cls).items()
            if not k.startswith("_") and isinstance(v, str)
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Role → Permission matrix
# This is seeded into the database on migration; backend always checks DB state.
# ──────────────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS: dict[CloudGuardRole, list[str]] = {
    CloudGuardRole.ADMIN: Permission.all_permissions(),  # Full access

    CloudGuardRole.SECURITY_ANALYST: [
        Permission.DASHBOARD_READ,
        Permission.ASSETS_READ,
        Permission.RESOURCES_READ,
        Permission.SCANS_READ,
        Permission.FINDINGS_READ,
        Permission.FINDINGS_UPDATE,
        Permission.RULES_READ,
        Permission.POSTURE_READ,
        Permission.INVESTIGATION_READ,
        Permission.REPORTS_READ,
        Permission.AUDIT_READ,
        Permission.USERS_READ,
        # Remediation
        Permission.REMEDIATIONS_READ,
        Permission.REMEDIATIONS_CREATE,
        Permission.REMEDIATIONS_VALIDATE,
        Permission.REMEDIATIONS_APPROVE,
        Permission.REMEDIATIONS_CANCEL,
        Permission.REMEDIATIONS_AUDIT_READ,
        # AI Orchestration (Phase 8)
        Permission.AI_ANALYZE,
        Permission.AI_READ,
        Permission.AI_AUDIT_READ,
        # Automation Orchestration (Phase 9)
        Permission.AUTOMATION_READ,
        Permission.AUTOMATION_EVALUATE,
        Permission.AUTOMATION_AUDIT_READ,
        # Model Context Protocol (Phase 10)
        Permission.MCP_READ,
        Permission.MCP_EXECUTE,
        Permission.MCP_AUDIT_READ,
    ],

    CloudGuardRole.OPERATOR: [
        Permission.DASHBOARD_READ,
        Permission.ASSETS_READ,
        Permission.RESOURCES_READ,
        Permission.SCANS_READ,
        Permission.SCANS_CREATE,
        Permission.FINDINGS_READ,
        Permission.RULES_READ,
        Permission.POSTURE_READ,
        # Remediation
        Permission.REMEDIATIONS_READ,
        Permission.REMEDIATIONS_EXECUTE,
        Permission.REMEDIATIONS_AUDIT_READ,
        # AI Orchestration (Phase 8)
        Permission.AI_READ,
        # Automation Orchestration (Phase 9)
        Permission.AUTOMATION_READ,
        Permission.AUTOMATION_AUDIT_READ,
        # Model Context Protocol (Phase 10)
        Permission.MCP_READ,
        Permission.MCP_AUDIT_READ,
    ],

    CloudGuardRole.VIEWER: [
        Permission.DASHBOARD_READ,
        Permission.ASSETS_READ,
        Permission.RESOURCES_READ,
        Permission.SCANS_READ,
        Permission.FINDINGS_READ,
        Permission.RULES_READ,
        Permission.POSTURE_READ,
        # Remediation
        Permission.REMEDIATIONS_READ,
        # Automation Orchestration (Phase 9)
        Permission.AUTOMATION_READ,
        # Model Context Protocol (Phase 10)
        Permission.MCP_READ,
    ],
}

