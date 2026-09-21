"""
CloudGuard — Read-Only AI Tool Registry (Phase 8)

Explicit, server-side allowlist of read-only tools.
No tool in this registry can modify infrastructure, change database records,
execute shell commands, or perform arbitrary network operations.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Type
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select

from core.ai.tools.schemas import (
    GetFindingInput,
    GetFindingHistoryInput,
    GetResourceDetailsInput,
    GetRuleDetailsInput,
    GetAllowedRemediationStrategiesInput,
    GetRemediationStatusInput,
)
from core.db_models import (
    FindingDBModel,
    ResourceDBModel,
    ResourceSnapshotDBModel,
    RemediationPlanDBModel,
)
from core.remediation.strategy import get_strategy
from core.ai.masking import mask_finding_evidence_for_ai, mask_config


class ReadOnlyTool:
    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Type[BaseModel],
        handler: Callable[[Session, Dict[str, Any]], Dict[str, Any]],
    ):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_schema.model_json_schema(),
        }


# ── Tool Handlers (Strictly Read-Only) ─────────────────────────────────────────

def handle_get_finding(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = args["finding_id"]
    finding = session.scalar(
        select(FindingDBModel).where(FindingDBModel.finding_id == finding_id)
    )
    if not finding:
        return {"error": f"Finding {finding_id} not found."}

    evidence_summary = (
        finding.evidence.get("summary")
        if isinstance(finding.evidence, dict)
        else str(finding.evidence)
    )

    return {
        "finding_id": finding.finding_id,
        "canonical_id": finding.canonical_id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.category,
        "service": finding.service,
        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,
        "region": finding.region,
        "status": finding.status,
        "risk_score": finding.risk_score,
        "internet_exposed": finding.internet_exposed,
        "evidence_summary": mask_finding_evidence_for_ai(evidence_summary),
    }


def handle_get_finding_history(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    canonical_id = args["canonical_id"]
    findings = session.scalars(
        select(FindingDBModel)
        .where(FindingDBModel.canonical_id == canonical_id)
        .order_by(FindingDBModel.last_detected_at.desc())
        .limit(10)
    ).all()

    timeline = [
        {
            "finding_id": f.finding_id,
            "scan_id": f.scan_id,
            "status": f.status,
            "last_detected_at": f.last_detected_at.isoformat() if f.last_detected_at else None,
            "severity": f.severity,
        }
        for f in findings
    ]
    return {"canonical_id": canonical_id, "occurrences": len(timeline), "timeline": timeline}


def handle_get_resource_details(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    resource_id = args["resource_id"]
    res = session.scalar(
        select(ResourceDBModel).where(ResourceDBModel.resource_id == resource_id)
    )
    if not res:
        return {"error": f"Resource {resource_id} not found."}

    # Mask tags safely
    masked_tags = mask_config(res.tags) if isinstance(res.tags, dict) else {}

    # Get latest snapshot
    snapshot = session.scalar(
        select(ResourceSnapshotDBModel)
        .where(ResourceSnapshotDBModel.resource_id == resource_id)
        .order_by(ResourceSnapshotDBModel.observed_at.desc())
        .limit(1)
    )
    masked_cfg = mask_config(snapshot.configuration) if snapshot and isinstance(snapshot.configuration, dict) else {}

    return {
        "resource_id": res.resource_id,
        "provider": res.provider,
        "service": res.service,
        "resource_type": res.resource_type,
        "region": res.region,
        "tags": masked_tags,
        "configuration_sample": masked_cfg,
    }


def handle_get_rule_details(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = args["rule_id"]
    # Provide authoritative metadata
    metadata = {
        "S3-001": {
            "title": "S3 Bucket Public Access Block Disabled",
            "severity": "HIGH",
            "description": "Checks if S3 bucket has Public Access Block enabled at bucket level.",
            "rationale": "S3 buckets without Public Access Block risk accidental exposure of sensitive data.",
        },
        "s3-public-access-block-disabled": {
            "title": "S3 Bucket Public Access Block Disabled",
            "severity": "HIGH",
            "description": "Checks if S3 bucket has Public Access Block enabled at bucket level.",
            "rationale": "S3 buckets without Public Access Block risk accidental exposure of sensitive data.",
        },
        "SG-001": {
            "title": "Security Group Open Ingress (SSH)",
            "severity": "HIGH",
            "description": "Checks for security groups with SSH (port 22) open to 0.0.0.0/0.",
            "rationale": "Open SSH allows unrestricted brute force or unauthorized access attempts from the internet.",
        },
        "ec2-sg-open-ssh": {
            "title": "Security Group Open Ingress (SSH)",
            "severity": "HIGH",
            "description": "Checks for security groups with SSH (port 22) open to 0.0.0.0/0.",
            "rationale": "Open SSH allows unrestricted brute force or unauthorized access attempts from the internet.",
        },
    }
    info = metadata.get(rule_id, {
        "title": f"Security Rule {rule_id}",
        "severity": "MEDIUM",
        "description": f"Enforces compliance policy for rule {rule_id}.",
        "rationale": "Non-compliant infrastructure introduces operational and security risks.",
    })
    return {"rule_id": rule_id, **info}


def handle_get_allowed_remediation_strategies(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
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


def handle_get_remediation_status(session: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = args["finding_id"]
    plan = session.scalar(
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
    }


# ── Strict Allowlist Registry ──────────────────────────────────────────────────

READ_ONLY_TOOL_REGISTRY: Dict[str, ReadOnlyTool] = {
    "get_finding": ReadOnlyTool(
        name="get_finding",
        description="Retrieve security finding details, evidence, and context by finding_id.",
        input_schema=GetFindingInput,
        handler=handle_get_finding,
    ),
    "get_finding_history": ReadOnlyTool(
        name="get_finding_history",
        description="Retrieve historical scan timeline for a canonical finding ID.",
        input_schema=GetFindingHistoryInput,
        handler=handle_get_finding_history,
    ),
    "get_resource_details": ReadOnlyTool(
        name="get_resource_details",
        description="Retrieve resource metadata, tags, and configuration snapshot by resource_id.",
        input_schema=GetResourceDetailsInput,
        handler=handle_get_resource_details,
    ),
    "get_rule_details": ReadOnlyTool(
        name="get_rule_details",
        description="Retrieve security rule title, severity, description, and rationale.",
        input_schema=GetRuleDetailsInput,
        handler=handle_get_rule_details,
    ),
    "get_allowed_remediation_strategies": ReadOnlyTool(
        name="get_allowed_remediation_strategies",
        description="Retrieve explicitly allowlisted Phase 7 remediation strategies for a rule.",
        input_schema=GetAllowedRemediationStrategiesInput,
        handler=handle_get_allowed_remediation_strategies,
    ),
    "get_remediation_status": ReadOnlyTool(
        name="get_remediation_status",
        description="Check if an active Phase 7 remediation plan exists for a finding.",
        input_schema=GetRemediationStatusInput,
        handler=handle_get_remediation_status,
    ),
}
