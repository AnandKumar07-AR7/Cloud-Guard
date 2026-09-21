"""
CloudGuard — Remediation MCP Server (Phase 10)
Exposes controlled, policy-governed remediation tools.
Integrates with Phase 7 State Machine and Phase 9 Policy Engine.
Arbitrary execution or destructive actions are strictly prohibited.
"""
from __future__ import annotations

from typing import Any, Dict, List
from sqlalchemy import select

from auth.permissions import Permission
from core.automation.service import AutomationService
from core.db_models import FindingDBModel, RemediationPlanDBModel
from core.mcp.models import (
    MCPExecutionContext,
    MCPOperationClass,
    MCPToolDefinition,
)
from core.mcp.schemas import (
    CreateRemediationPlanInput,
    GetAllowedStrategiesInput,
    GetApprovalStatusInput,
    GetRemediationStatusInput,
    RequestApprovalInput,
    ValidateRemediationPlanInput,
)
from core.mcp.servers.base import BaseCloudGuardMCPServer
from core.remediation.strategy import get_strategy
from services.remediation_service import RemediationService


class RemediationMCPServer(BaseCloudGuardMCPServer):
    """
    CloudGuard Remediation MCP Server.
    Provides controlled write capabilities governed by Phase 7 and Phase 9.
    Does NOT expose arbitrary execution or destructive tools.
    """

    def __init__(self):
        super().__init__(
            server_id="cloudguard-remediation-mcp",
            server_name="CloudGuard Remediation MCP",
            version="1.0.0",
            server_type="remediation",
            description="Policy-governed MCP server for safe remediation planning, validation, and approval status.",
            permission_scope=[
                Permission.REMEDIATIONS_READ,
                Permission.REMEDIATIONS_CREATE,
                Permission.REMEDIATIONS_VALIDATE,
                Permission.REMEDIATIONS_APPROVE,
            ],
        )
        self._remediation_service = RemediationService()
        self._automation_service = AutomationService()
        self._register_remediation_tools()

    def _register_remediation_tools(self) -> None:
        self.register_tool(
            MCPToolDefinition(
                name="get_allowed_remediation_strategies",
                description="Retrieve explicitly allowlisted Phase 7 remediation strategies for a rule.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetAllowedStrategiesInput,
                required_permission=Permission.REMEDIATIONS_READ,
                handler=self._handle_get_allowed_strategies,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="create_remediation_plan",
                description="Generate a deterministic Phase 7 remediation plan for a finding.",
                operation_class=MCPOperationClass.WRITE,
                input_schema=CreateRemediationPlanInput,
                required_permission=Permission.REMEDIATIONS_CREATE,
                handler=self._handle_create_remediation_plan,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="validate_remediation_plan",
                description="Perform pre-execution validation on a draft remediation plan.",
                operation_class=MCPOperationClass.WRITE,
                input_schema=ValidateRemediationPlanInput,
                required_permission=Permission.REMEDIATIONS_VALIDATE,
                handler=self._handle_validate_remediation_plan,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_remediation_status",
                description="Check current state machine status of a remediation plan for a finding.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetRemediationStatusInput,
                required_permission=Permission.REMEDIATIONS_READ,
                handler=self._handle_get_remediation_status,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="request_approval",
                description="Submit a validated remediation plan for human or policy review.",
                operation_class=MCPOperationClass.WRITE,
                input_schema=RequestApprovalInput,
                required_permission=Permission.REMEDIATIONS_APPROVE,
                handler=self._handle_request_approval,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_approval_status",
                description="Check approval state, approver identity, and decision metadata for a plan.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetApprovalStatusInput,
                required_permission=Permission.REMEDIATIONS_READ,
                handler=self._handle_get_approval_status,
            )
        )

    # ── Tool Handlers ─────────────────────────────────────────────────────────

    def _handle_get_allowed_strategies(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rule_id = args["rule_id"]
        strat = get_strategy(rule_id)
        if not strat:
            return {
                "rule_id": rule_id,
                "remediable": False,
                "strategies": [],
                "message": f"Rule '{rule_id}' has no allowlisted Phase 7 remediation strategy.",
            }

        return {
            "rule_id": rule_id,
            "remediable": True,
            "strategies": [
                {
                    "strategy_id": strat.rule_id,
                    "action_type": strat.action_type,
                    "safety": strat.safety.value,
                    "description_template": strat.description_template,
                }
            ],
        }

    def _handle_create_remediation_plan(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        finding_id = args["finding_id"]

        # Check Phase 9 kill switch
        if self._automation_service.is_kill_switch_active(ctx.session):
            return {
                "error": "Emergency kill-switch is ACTIVE. Remediation plan creation is blocked.",
                "blocked": True,
            }

        user_id = ctx.user_id or "mcp_system_user"
        try:
            plan = self._remediation_service.create_plan(
                session=ctx.session,
                finding_id=finding_id,
                user_id=user_id,
            )
            return {
                "remediation_id": plan.remediation_id,
                "finding_id": plan.finding_id,
                "state": plan.state.value if hasattr(plan.state, "value") else str(plan.state),
                "created_by": plan.created_by,
                "created_at": plan.created_at.isoformat() if plan.created_at else None,
            }
        except ValueError as exc:
            return {"error": str(exc), "finding_id": finding_id}

    def _handle_validate_remediation_plan(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rem_id = args["remediation_id"]
        user_id = ctx.user_id or "mcp_system_user"
        try:
            plan = self._remediation_service.validate_plan(
                session=ctx.session,
                remediation_id=rem_id,
                user_id=user_id,
            )
            return {
                "remediation_id": plan.remediation_id,
                "state": plan.state.value if hasattr(plan.state, "value") else str(plan.state),
                "validated": True,
            }
        except Exception as exc:
            return {"error": str(exc), "remediation_id": rem_id, "validated": False}

    def _handle_get_remediation_status(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        finding_id = args["finding_id"]
        plan = ctx.session.scalar(
            select(RemediationPlanDBModel)
            .where(RemediationPlanDBModel.finding_id == finding_id)
            .order_by(RemediationPlanDBModel.created_at.desc())
            .limit(1)
        )
        if not plan:
            return {"finding_id": finding_id, "has_plan": False}

        return {
            "finding_id": finding_id,
            "has_plan": True,
            "remediation_id": plan.remediation_id,
            "state": plan.state,
            "created_by": plan.created_by,
            "approved_by": plan.approved_by,
            "executed_by": plan.executed_by,
        }

    def _handle_request_approval(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rem_id = args["remediation_id"]
        justification = args.get("justification")

        # Check Phase 9 kill switch
        if self._automation_service.is_kill_switch_active(ctx.session):
            return {
                "error": "Emergency kill-switch is ACTIVE. Approval requests are blocked.",
                "blocked": True,
            }

        plan = ctx.session.scalar(
            select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == rem_id)
        )
        if not plan:
            return {"error": f"Remediation plan '{rem_id}' not found."}

        # Check separation of duties: creator cannot approve own plan
        if ctx.user_id and plan.created_by == ctx.user_id:
            return {
                "error": "Separation of duties violation: plan creator cannot approve their own plan.",
                "blocked": True,
            }

        return {
            "remediation_id": rem_id,
            "state": plan.state,
            "approval_requested": True,
            "justification": justification,
        }

    def _handle_get_approval_status(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rem_id = args["remediation_id"]
        plan = ctx.session.scalar(
            select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == rem_id)
        )
        if not plan:
            return {"error": f"Remediation plan '{rem_id}' not found."}

        is_approved = plan.state in ("APPROVED", "EXECUTING", "EXECUTED", "VERIFIED")
        return {
            "remediation_id": rem_id,
            "state": plan.state,
            "approved": is_approved,
            "approved_by": plan.approved_by,
            "approved_at": plan.approved_at.isoformat() if plan.approved_at else None,
        }
