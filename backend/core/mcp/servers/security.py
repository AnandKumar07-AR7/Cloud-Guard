"""
CloudGuard — Security MCP Server (Phase 10)
Exposes strictly read-only tools for security findings, posture, rules, and risk intelligence.
"""
from __future__ import annotations

from typing import Any, Dict, List
from sqlalchemy import select, desc, func

from auth.permissions import Permission
from core.ai.masking import mask_finding_evidence_for_ai
from core.db_models import (
    FindingDBModel,
    ResourceDBModel,
    ResourceRelationshipDBModel,
    ScanDBModel,
)
from core.mcp.models import (
    MCPExecutionContext,
    MCPOperationClass,
    MCPToolDefinition,
)
from core.mcp.schemas import (
    GetFindingHistoryInput,
    GetFindingInput,
    GetInvestigationContextInput,
    GetPostureInput,
    GetRiskContextInput,
    GetRuleInput,
    ListFindingsInput,
    ListRulesInput,
)
from core.mcp.servers.base import BaseCloudGuardMCPServer
from core.security.catalog import get_all_rules, get_rule


class SecurityMCPServer(BaseCloudGuardMCPServer):
    """
    CloudGuard Security MCP Server.
    Provides read-only access to findings, security rules, posture metrics, and risk intelligence.
    """

    def __init__(self):
        super().__init__(
            server_id="cloudguard-security-mcp",
            server_name="CloudGuard Security MCP",
            version="1.0.0",
            server_type="security",
            description="Read-only MCP server for security findings, rules, risk context, and posture.",
            permission_scope=[
                Permission.FINDINGS_READ,
                Permission.RULES_READ,
                Permission.POSTURE_READ,
                Permission.INVESTIGATION_READ,
            ],
        )
        self._register_security_tools()

    def _register_security_tools(self) -> None:
        self.register_tool(
            MCPToolDefinition(
                name="list_findings",
                description="List security findings with optional filters (scan, severity, status) and pagination.",
                operation_class=MCPOperationClass.READ,
                input_schema=ListFindingsInput,
                required_permission=Permission.FINDINGS_READ,
                handler=self._handle_list_findings,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_finding",
                description="Retrieve detailed security finding information with masked evidence.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetFindingInput,
                required_permission=Permission.FINDINGS_READ,
                handler=self._handle_get_finding,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_finding_history",
                description="Retrieve historical timeline of a canonical finding across past scans.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetFindingHistoryInput,
                required_permission=Permission.FINDINGS_READ,
                handler=self._handle_get_finding_history,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="list_rules",
                description="List registered security rules and metadata from the authoritative catalog.",
                operation_class=MCPOperationClass.READ,
                input_schema=ListRulesInput,
                required_permission=Permission.RULES_READ,
                handler=self._handle_list_rules,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_rule",
                description="Retrieve full details, rationale, and remediation guidance for a security rule.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetRuleInput,
                required_permission=Permission.RULES_READ,
                handler=self._handle_get_rule,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_risk_context",
                description="Compute contextual risk metrics and exposure profile for a cloud resource.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetRiskContextInput,
                required_permission=Permission.FINDINGS_READ,
                handler=self._handle_get_risk_context,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_posture",
                description="Retrieve overall security posture metrics and severity breakdown.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetPostureInput,
                required_permission=Permission.POSTURE_READ,
                handler=self._handle_get_posture,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_investigation_context",
                description="Retrieve graph investigation context and related entity impact for a finding.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetInvestigationContextInput,
                required_permission=Permission.INVESTIGATION_READ,
                handler=self._handle_get_investigation_context,
            )
        )

    # ── Tool Handlers ─────────────────────────────────────────────────────────

    def _handle_list_findings(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        query = select(FindingDBModel)
        if args.get("scan_id"):
            query = query.where(FindingDBModel.scan_id == args["scan_id"])
        if args.get("severity"):
            query = query.where(FindingDBModel.severity == args["severity"].upper())
        if args.get("status"):
            query = query.where(FindingDBModel.status == args["status"].upper())

        limit = min(args.get("limit", 50), 100)
        offset = args.get("offset", 0)

        query = query.order_by(desc(FindingDBModel.last_detected_at)).limit(limit).offset(offset)
        findings = ctx.session.scalars(query).all()

        items = [
            {
                "finding_id": f.finding_id,
                "canonical_id": f.canonical_id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "service": f.service,
                "resource_id": f.resource_id,
                "risk_score": f.risk_score,
            }
            for f in findings
        ]
        return {"items": items, "count": len(items), "limit": limit, "offset": offset}

    def _handle_get_finding(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        fid = args["finding_id"]
        finding = ctx.session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == fid)
        )
        if not finding:
            return {"error": f"Finding '{fid}' not found."}

        evidence_str = (
            finding.evidence.get("summary")
            if isinstance(finding.evidence, dict)
            else str(finding.evidence)
        )
        masked_ev = mask_finding_evidence_for_ai(evidence_str)
        if isinstance(masked_ev, str):
            import re
            masked_ev = re.sub(r'(?i)(token|bearer|key|secret)[=\s:]+([^\s,;]+)', r'\1=[REDACTED]', masked_ev)
            masked_ev = re.sub(r'\bey[a-zA-Z0-9_-]+\b', '[REDACTED]', masked_ev)

        return {
            "finding_id": finding.finding_id,
            "canonical_id": finding.canonical_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "status": finding.status,
            "category": finding.category,
            "service": finding.service,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "region": finding.region,
            "risk_score": finding.risk_score,
            "internet_exposed": finding.internet_exposed,
            "evidence_summary": masked_ev,
            "first_detected_at": finding.first_detected_at.isoformat() if finding.first_detected_at else None,
            "last_detected_at": finding.last_detected_at.isoformat() if finding.last_detected_at else None,
        }

    def _handle_get_finding_history(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        cid = args["canonical_id"]
        findings = ctx.session.scalars(
            select(FindingDBModel)
            .where(FindingDBModel.canonical_id == cid)
            .order_by(desc(FindingDBModel.last_detected_at))
            .limit(10)
        ).all()

        timeline = [
            {
                "finding_id": f.finding_id,
                "scan_id": f.scan_id,
                "status": f.status,
                "severity": f.severity,
                "last_detected_at": f.last_detected_at.isoformat() if f.last_detected_at else None,
            }
            for f in findings
        ]
        return {"canonical_id": cid, "occurrences": len(timeline), "timeline": timeline}

    def _handle_list_rules(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        service_filter = args.get("service")
        severity_filter = args.get("severity")
        all_rules = get_all_rules(service=service_filter, severity=severity_filter)

        filtered = []
        for r in all_rules:
            m = r.metadata
            filtered.append({
                "rule_id": m.rule_id,
                "title": m.name,
                "severity": m.severity.value,
                "service": m.service,
                "category": m.category,
                "description": m.description,
            })
        return {"rules": filtered, "total": len(filtered)}

    def _handle_get_rule(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rid = args["rule_id"]
        rule = get_rule(rid)
        if not rule:
            return {"error": f"Security rule '{rid}' not found."}

        m = rule.metadata
        return {
            "rule_id": m.rule_id,
            "title": m.name,
            "severity": m.severity.value,
            "service": m.service,
            "category": m.category,
            "description": m.description,
            "rationale": m.rationale,
            "remediation": m.remediation,
        }

    def _handle_get_risk_context(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rid = args["resource_id"]
        findings = ctx.session.scalars(
            select(FindingDBModel).where(FindingDBModel.resource_id == rid)
        ).all()
        if not findings:
            return {"resource_id": rid, "risk_score": 0.0, "finding_count": 0, "status": "CLEAN"}

        max_risk = max((f.risk_score or 0.0) for f in findings)
        any_exposed = any(bool(f.internet_exposed) for f in findings)
        return {
            "resource_id": rid,
            "risk_score": max_risk,
            "finding_count": len(findings),
            "internet_exposed": any_exposed,
            "severities": list(set(f.severity for f in findings)),
        }

    def _handle_get_posture(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        query = select(FindingDBModel)
        if args.get("scan_id"):
            query = query.where(FindingDBModel.scan_id == args["scan_id"])

        findings = ctx.session.scalars(query).all()
        total = len(findings)
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        return {
            "total_findings": total,
            "severity_counts": sev_counts,
            "critical_count": sev_counts.get("CRITICAL", 0),
            "high_count": sev_counts.get("HIGH", 0),
            "medium_count": sev_counts.get("MEDIUM", 0),
            "low_count": sev_counts.get("LOW", 0),
        }

    def _handle_get_investigation_context(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        fid = args["finding_id"]
        finding = ctx.session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == fid)
        )
        if not finding:
            return {"error": f"Finding '{fid}' not found."}

        # Query related findings on the same resource
        related = ctx.session.scalars(
            select(FindingDBModel)
            .where(FindingDBModel.resource_id == finding.resource_id)
            .where(FindingDBModel.finding_id != fid)
            .limit(5)
        ).all()

        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "resource_id": finding.resource_id,
            "service": finding.service,
            "severity": finding.severity,
            "related_findings": [
                {"finding_id": rf.finding_id, "rule_id": rf.rule_id, "severity": rf.severity}
                for rf in related
            ],
        }
