"""
CloudGuard — AI MCP Capability Policy (Phase 10)
Defines bounded MCP access per AI agent persona.
Strictly prevents AI agents from executing unapproved or destructive actions.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Set

from core.mcp.models import MCPOperationClass


class AIAgentPersona(str, Enum):
    SECURITY_ANALYST = "SECURITY_ANALYST"
    REMEDIATION_PLANNER = "REMEDIATION_PLANNER"
    AUTOMATION_OBSERVER = "AUTOMATION_OBSERVER"


class MCPAgentPolicy:
    """
    Authoritative capability policy governing AI agent interaction with MCP.
    """

    # Explicit allowed tool names per persona
    _PERSONA_ALLOWED_TOOLS: Dict[AIAgentPersona, Set[str]] = {
        AIAgentPersona.SECURITY_ANALYST: {
            "list_cloud_accounts",
            "list_resources",
            "get_resource",
            "get_resource_relationships",
            "get_resource_snapshot",
            "get_scan",
            "get_scan_status",
            "list_findings",
            "get_finding",
            "get_finding_history",
            "list_rules",
            "get_rule",
            "get_risk_context",
            "get_posture",
            "get_investigation_context",
            "get_allowed_remediation_strategies",
            "get_remediation_status",
            "get_approval_status",
        },
        AIAgentPersona.REMEDIATION_PLANNER: {
            "get_finding",
            "get_resource",
            "get_allowed_remediation_strategies",
            "get_remediation_status",
            "create_remediation_plan",
            "validate_remediation_plan",
        },
        AIAgentPersona.AUTOMATION_OBSERVER: {
            "get_scan_status",
            "get_remediation_status",
            "get_approval_status",
            "get_posture",
        },
    }

    @classmethod
    def is_tool_allowed_for_ai(
        cls, persona: AIAgentPersona, tool_name: str, op_class: MCPOperationClass
    ) -> bool:
        """
        Validates if an AI agent persona is authorized to invoke an MCP tool.
        DESTRUCTIVE actions are universally rejected.
        """
        # Hard boundary: AI cannot invoke destructive actions
        if op_class == MCPOperationClass.DESTRUCTIVE:
            return False

        allowed = cls._PERSONA_ALLOWED_TOOLS.get(persona, set())
        return tool_name in allowed
