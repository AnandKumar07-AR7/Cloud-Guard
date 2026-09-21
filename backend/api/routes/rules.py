"""
CloudGuard — Rules API Routes

GET /rules              — list all security rules (filterable, paginated)  [rules.read]
GET /rules/{rule_id}    — get a single rule's full metadata                [rules.read]

These endpoints expose the Rule Catalog so the Obsidian Command Center UI
can render the Detection Rules view with filters by service, severity, category.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission
from api.errors import NotFoundError, CloudGuardAPIError, ErrorCode
from api.schemas import (
    RuleCatalogSummary,
    RuleListResponse,
    RuleResponse,
)
from core.security.catalog import get_all_rules, get_catalog_summary, get_rule
from core.security.models import Severity
from core.security.rules.base import SecurityRule
from core.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/rules", tags=["Rules"])

# Valid filter values
_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_CATEGORIES = {
    "encryption", "access-control", "network", "logging",
    "configuration", "monitoring",
}
_VALID_SERVICES = {
    "s3", "iam", "ec2", "lambda", "rds", "vpc", "cloudtrail",
    "cloudwatch", "kms", "sns", "sqs",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _rule_to_response(rule: SecurityRule) -> RuleResponse:
    """Convert a SecurityRule instance to the API response schema."""
    m = rule.metadata
    return RuleResponse(
        rule_id=m.rule_id,
        name=m.name,
        description=m.description,
        provider=m.provider,
        service=m.service,
        resource_type=m.resource_type,
        severity=m.severity.value,
        category=m.category,
        version=m.version,
        internet_exposure_risk=m.internet_exposure_risk,
        privilege_escalation_risk=m.privilege_escalation_risk,
        data_exposure_risk=m.data_exposure_risk,
        remediation_safety=m.remediation_safety.value,
        remediation_available=m.remediation_available,
        remediation_guidance=m.remediation_template,
        compliance_mappings=list(m.compliance_mappings),
        references=list(m.references),
        enabled=m.enabled,
    )


def _validate_severity(severity: Optional[str]) -> Optional[str]:
    if severity is None:
        return None
    lower = severity.lower()
    if lower not in _VALID_SEVERITIES:
        raise CloudGuardAPIError(
            status_code=400,
            error_code=ErrorCode.INVALID_FILTER,
            message=f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}",
        )
    return lower


def _validate_category(category: Optional[str]) -> Optional[str]:
    if category is None:
        return None
    lower = category.lower()
    # Don't strictly validate unknown categories — allow new ones
    return lower


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=RuleListResponse)
async def list_rules(
    service: Optional[str] = Query(
        default=None,
        description="Filter by AWS service: s3|iam|ec2|lambda|rds|vpc|cloudtrail",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: critical|high|medium|low|informational",
    ),
    category: Optional[str] = Query(
        default=None,
        description="Filter by category: encryption|access-control|network|logging|configuration|monitoring",
    ),
    include_disabled: bool = Query(
        default=False,
        description="Include disabled rules in the response",
    ),
    include_summary: bool = Query(
        default=True,
        description="Include catalog summary statistics in the response",
    ),
    limit: int = Query(default=100, ge=1, le=500, description="Rules per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    _user: UserDBModel = Depends(require_permission(Permission.RULES_READ)),
):
    """
    List all registered security rules.

    Returns the complete Rule Catalog with optional filtering.
    Rules are returned sorted by service, then severity (critical first),
    then rule_id.
    """
    sev_filter = _validate_severity(severity)
    cat_filter = _validate_category(category)

    filters_applied: Dict[str, Any] = {}
    if service:
        filters_applied["service"] = service.lower()
    if sev_filter:
        filters_applied["severity"] = sev_filter
    if cat_filter:
        filters_applied["category"] = cat_filter
    if include_disabled:
        filters_applied["include_disabled"] = True

    rules = get_all_rules(
        service=service,
        severity=sev_filter,
        category=cat_filter,
        enabled_only=not include_disabled,
    )

    # Sort: service asc, severity (critical→informational), rule_id asc
    _SEVERITY_ORDER = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4
    }
    rules.sort(key=lambda r: (
        r.metadata.service,
        _SEVERITY_ORDER.get(r.metadata.severity.value, 9),
        r.metadata.rule_id,
    ))

    total = len(rules)
    page = rules[offset: offset + limit]

    summary = None
    if include_summary:
        raw = get_catalog_summary()
        summary = RuleCatalogSummary(**raw)

    log.info(
        "rules_listed",
        total=total,
        page_size=len(page),
        filters=filters_applied,
    )

    return RuleListResponse(
        items=[_rule_to_response(r) for r in page],
        total=total,
        limit=limit,
        offset=offset,
        filters_applied=filters_applied,
        catalog_summary=summary,
    )


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule_by_id(
    rule_id: str,
    _user: UserDBModel = Depends(require_permission(Permission.RULES_READ)),
):
    """
    Get a single security rule by its rule ID (e.g. 'S3-001', 'IAM-003').

    Returns full rule metadata including description, severity, compliance
    mappings, remediation guidance, and references.
    """
    rule = get_rule(rule_id)
    if rule is None:
        raise NotFoundError("Rule", rule_id)

    log.info("rule_fetched", rule_id=rule_id)
    return _rule_to_response(rule)
