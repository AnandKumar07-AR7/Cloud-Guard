"""
CloudGuard — Findings Routes

GET /findings              — list findings (filterable, paginated)  [findings.read]
GET /findings/{finding_id} — get a single finding by ID             [findings.read]
GET /findings/{finding_id}/investigation — investigation context    [investigation.read]
GET /findings/{canonical_id}/history   — finding history            [findings.read]
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from core.database import get_db

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission
from api.errors import CloudGuardAPIError, ErrorCode, NotFoundError
from api.schemas import (
    EvidenceResponse,
    FindingListResponse,
    FindingResponse,
    InvestigationResponse,
    RuleResponse,
    FindingHistoryResponse,
    FindingHistoryItem,
)
from core.security.models import FindingStatus, Severity
from services.scan_service import get_scan_service
from core.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/findings", tags=["Findings"])

# Valid severity values for filter validation
_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_STATUSES = {s.value for s in FindingStatus}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _finding_to_response(finding, scan_id: Optional[str] = None) -> FindingResponse:
    """Convert a domain Finding to the API response schema."""
    sec_ctx = finding.security_context or finding.derive_security_context()
    return FindingResponse(
        finding_id=finding.finding_id,
        canonical_id=finding.canonical_id,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        scan_id=scan_id or finding.scan_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        resource_name=finding.resource_name or finding.resource_id,
        resource_arn=finding.resource_arn,
        service=finding.service,
        account_id=finding.account_id,
        region=finding.region,
        provider="demo",
        severity=finding.severity.value,
        risk_score=finding.risk_score,
        status=finding.status.value,
        title=finding.title,
        description=finding.description,
        remediation_guidance=finding.remediation_guidance,
        category=finding.category,
        remediation_safety=finding.remediation_safety,
        resource_relationships=finding.resource_relationships,
        evidence=EvidenceResponse(
            rule_id=finding.evidence.rule_id,
            field_path=finding.evidence.field_path,
            observed_value=finding.evidence.observed_value,
            expected_value=finding.evidence.expected_value,
            summary=finding.evidence.to_summary(),
        ),
        compliance_mappings=finding.compliance_mappings,
        internet_exposed=finding.internet_exposed,
        privilege_escalation_risk=finding.privilege_escalation_risk,
        data_exposure_risk=finding.data_exposure_risk,
        security_context=sec_ctx.model_dump() if sec_ctx else None,
        risk_context=finding.risk_context.model_dump() if finding.risk_context else None,
        relationships=[r.model_dump() for r in finding.relationships],
        compliance_context=finding.compliance_context.model_dump() if finding.compliance_context else None,
        remediation_context=finding.remediation_context.model_dump() if finding.remediation_context else None,
        ai_analysis=finding.ai_analysis.model_dump() if finding.ai_analysis else None,
        ai_explanation=finding.ai_explanation,
        ai_manager_summary=finding.ai_manager_summary,
        ai_source=finding.ai_analysis.ai_source if finding.ai_analysis else ("claude" if finding.ai_explanation else None),
        detected_at=finding.detected_at.isoformat(),
        updated_at=finding.updated_at.isoformat(),
    )


def _validate_severity(severity: Optional[str]) -> Optional[str]:
    if severity is None:
        return None
    sev_lower = severity.lower()
    if sev_lower not in _VALID_SEVERITIES:
        raise CloudGuardAPIError(
            status_code=400,
            error_code=ErrorCode.INVALID_FILTER,
            message=f"Invalid severity '{severity}'. Valid values: {sorted(_VALID_SEVERITIES)}",
        )
    return sev_lower


def _validate_status(status: Optional[str]) -> Optional[str]:
    if status is None:
        return None
    if status.upper() not in _VALID_STATUSES:
        raise CloudGuardAPIError(
            status_code=400,
            error_code=ErrorCode.INVALID_FILTER,
            message=f"Invalid status '{status}'. Valid values: {sorted(_VALID_STATUSES)}",
        )
    return status.upper()


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=FindingListResponse)
async def list_findings(
    scan_id: Optional[str] = Query(default=None, description="Filter by scan ID"),
    severity: Optional[str] = Query(default=None, description="Filter: critical|high|medium|low|informational"),
    status: Optional[str] = Query(default=None, description="Filter: OPEN|RESOLVED|..."),
    service: Optional[str] = Query(default=None, description="Filter by AWS service: s3|iam|ec2|lambda"),
    resource_type: Optional[str] = Query(default=None, description="Filter by resource type"),
    region: Optional[str] = Query(default=None, description="Filter by AWS region"),
    rule_id: Optional[str] = Query(default=None, description="Filter by rule ID"),
    internet_exposed: Optional[bool] = Query(default=None, description="Filter to internet-exposed findings"),
    limit: int = Query(default=50, ge=1, le=200, description="Number of findings per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """
    List findings with filtering and pagination.

    All filters are AND-combined.
    Use scan_id to scope findings to a specific scan.
    Filters that are omitted are not applied.
    """
    sev_filter = _validate_severity(severity)
    status_filter = _validate_status(status)

    from services.repositories import FindingRepository, ScanRepository
    
    effective_scan_id = scan_id
    if effective_scan_id == "all":
        effective_scan_id = None
    elif not effective_scan_id:
        from services.scan_service import get_scan_service
        from services.scan_models import ScanStatus
        scan_svc = get_scan_service(db)
        latest_scans = scan_svc.list_scans(limit=1, offset=0, status=ScanStatus.COMPLETED)
        if latest_scans:
            effective_scan_id = latest_scans[0].scan_id

    if effective_scan_id:
        scan_repo = ScanRepository(db)
        if not scan_repo.get(effective_scan_id):
            raise CloudGuardAPIError(
                status_code=404,
                error_code=ErrorCode.NOT_FOUND,
                message=f"Scan {effective_scan_id} not found"
            )

    repo = FindingRepository(db)
    
    filters = {
        "scan_id": effective_scan_id,
        "severity": sev_filter,
        "status": status_filter,
        "service": service.lower() if service else None,
        "resource_type": resource_type.lower() if resource_type else None,
        "region": region.lower() if region else None,
        "rule_id": rule_id.upper() if rule_id else None,
        "internet_exposed": internet_exposed,
    }

    findings = repo.list(**filters, limit=limit, offset=offset)
    total = repo.count(**filters)
    
    filters_applied = {k: v for k, v in filters.items() if v is not None}

    log.info(
        "findings_listed",
        total=total,
        page_size=len(findings),
        offset=offset,
        filters=filters_applied,
    )

    return FindingListResponse(
        items=[_finding_to_response(f, f.scan_id) for f in findings],
        total=total,
        limit=limit,
        offset=offset,
        filters_applied=filters_applied,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """
    Get a single finding by its ID or canonical_id.
    """
    from services.repositories import FindingRepository
    repo = FindingRepository(db)
    
    finding = repo.get(finding_id)
    if not finding:
        # Fallback to legacy scan store check for running tests that use mock data
        service_ref = get_scan_service()
        scans = service_ref.list_scans(limit=100, offset=0)
        for record in scans:
            for f in record.findings:
                if f.finding_id == finding_id or f.canonical_id == finding_id:
                    return _finding_to_response(f, scan_id=record.scan_id)
        
        raise NotFoundError("Finding", finding_id)

    return _finding_to_response(finding, scan_id=finding.scan_id)


@router.get("/{finding_id}/investigation", response_model=InvestigationResponse)
async def get_finding_investigation(
    finding_id: str,
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    enrich_with_ai: bool = Query(False, description="Run AI analysis if not present"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    """
    Get full investigation context for a finding.
    """
    from services.investigation_service import get_investigation_service
    inv_svc = get_investigation_service(db)
    context = inv_svc.investigate(finding_id, scan_id=scan_id, enrich_with_ai=enrich_with_ai)
    if not context:
        raise NotFoundError("Finding", finding_id)

    finding_resp = _finding_to_response(context.finding, scan_id=context.finding.scan_id)
    related_findings_resp = [_finding_to_response(f, scan_id=f.scan_id) for f in context.related_findings]

    rule_resp = None
    if context.rule_metadata:
        rule_resp = RuleResponse(
            rule_id=context.rule_metadata["rule_id"],
            name=context.rule_metadata["name"],
            description=context.rule_metadata["description"],
            provider=context.rule_metadata["provider"],
            service=context.rule_metadata["service"],
            resource_type=context.rule_metadata["resource_type"],
            severity=context.rule_metadata["severity"],
            category=context.rule_metadata["category"],
            version=context.rule_metadata["version"],
            internet_exposure_risk=context.rule_metadata["internet_exposure_risk"],
            privilege_escalation_risk=context.rule_metadata["privilege_escalation_risk"],
            data_exposure_risk=context.rule_metadata["data_exposure_risk"],
            remediation_safety=context.rule_metadata["remediation_safety"],
            remediation_available=context.rule_metadata["remediation_available"],
            remediation_guidance=context.rule_metadata["remediation_guidance"],
            compliance_mappings=context.rule_metadata["compliance_mappings"],
            references=context.rule_metadata["references"],
            enabled=context.rule_metadata["enabled"],
        )

    return InvestigationResponse(
        finding=finding_resp,
        rule=rule_resp,
        resource=context.resource,
        evidence=finding_resp.evidence,
        risk_context=context.risk_context.model_dump() if context.risk_context else None,
        security_context=context.security_context.model_dump() if context.security_context else None,
        related_resources=context.related_resources,
        related_findings=related_findings_resp,
        ai_analysis=context.ai_analysis.model_dump() if context.ai_analysis else None,
        remediation_context=context.remediation_context.model_dump() if context.remediation_context else None,
        compliance_context=context.compliance_context.model_dump() if context.compliance_context else None,
    )


@router.get("/{finding_id}/history", response_model=FindingHistoryResponse)
async def get_finding_history(
    finding_id: str,
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """
    Get the historical occurrences of a finding across multiple scans based on canonical identity.
    """
    from services.repositories import FindingRepository
    repo = FindingRepository(db)
    finding = repo.get(finding_id)
    if not finding:
        raise NotFoundError("Finding", finding_id)

    # Get all findings with the same canonical_id
    historical_findings = repo.get_history(finding.canonical_id)

    items = []
    for f in historical_findings:
        obs = f.last_detected_at or f.first_detected_at
        obs_str = obs.isoformat() if hasattr(obs, "isoformat") else str(obs or "")
        items.append(FindingHistoryItem(
            finding_id=f.finding_id,
            scan_id=f.scan_id,
            status=f.status.value if hasattr(f.status, "value") else str(f.status),
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            risk_score=f.risk_score,
            observed_at=obs_str,
        ))

    return FindingHistoryResponse(
        canonical_id=finding.canonical_id,
        resource_id=finding.resource_id,
        rule_id=finding.rule_id,
        history=items
    )
