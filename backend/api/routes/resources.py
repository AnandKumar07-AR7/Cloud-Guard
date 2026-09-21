"""
CloudGuard — Resource Explorer Routes

GET /resources               — list discovered cloud resources  [resources.read]
GET /resources/{resource_id} — get a single resource's detail   [resources.read]
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from core.database import get_db

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission

from api.errors import CloudGuardAPIError, ErrorCode, NotFoundError
from api.routes.findings import _finding_to_response
from api.schemas import (
    ResourceDetailResponse,
    ResourceListResponse,
    ResourceResponse,
)
from core.security.models import ResourcePosture, Severity
from core.security.relationships import extract_relationships_for_scan
from services.scan_service import get_scan_service
from core.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/resources", tags=["Resources"])

_VALID_POSTURES = {p.value for p in ResourcePosture}


def _derive_posture(findings: list) -> tuple[str, dict]:
    """Calculate posture label and severity count breakdown from findings on a resource."""
    open_findings = [f for f in findings if f.is_open]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings:
        sev = f.severity.value
        if sev in counts:
            counts[sev] += 1

    if counts["critical"] > 0:
        posture = ResourcePosture.CRITICAL.value
    elif counts["high"] > 0:
        posture = ResourcePosture.HIGH_RISK.value
    elif counts["medium"] > 0 or counts["low"] > 0:
        posture = ResourcePosture.AT_RISK.value
    else:
        posture = ResourcePosture.SECURE.value

    return posture, counts


@router.get("", response_model=ResourceListResponse)
async def list_resources(
    scan_id: Optional[str] = Query(None, description="Scan ID (defaults to latest scan)"),
    service: Optional[str] = Query(None, description="Filter by service: s3, iam, ec2, rds, etc."),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    region: Optional[str] = Query(None, description="Filter by region"),
    security_posture: Optional[str] = Query(None, description="Filter by posture: SECURE, AT_RISK, HIGH_RISK, CRITICAL"),
    limit: int = Query(50, ge=1, le=200, description="Max resources to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.RESOURCES_READ)),
):
    """
    List all discovered cloud resources from a scan with security posture.

    If scan_id is omitted, uses the latest completed scan.
    """
    service_ref = get_scan_service(db)

    if scan_id:
        record = service_ref.get_scan(scan_id)
        if not record:
            raise NotFoundError("Scan", scan_id)
    else:
        scans = service_ref.list_scans(limit=1, offset=0)
        record = scans[0] if scans else None

    if not record:
        return ResourceListResponse(
            items=[],
            total=0,
            limit=limit,
            offset=offset,
            filters_applied={},
        )

    # Group findings by resource_id
    findings_by_res = {}
    for f in record.findings:
        findings_by_res.setdefault(f.resource_id, []).append(f)

    # Relationships map
    relationships_by_res = extract_relationships_for_scan(record.resources)

    # Convert to ResourceResponse items
    all_resources = []
    for r in record.resources:
        res_findings = findings_by_res.get(r.resource_id, [])
        posture, counts = _derive_posture(res_findings)
        rels = [rel.model_dump() for rel in relationships_by_res.get(r.resource_id, [])]

        item = ResourceResponse(
            resource_id=r.resource_id,
            resource_type=r.resource_type.value,
            service=r.service,
            provider=r.provider,
            account_id=r.account_id,
            region=r.region,
            name=r.display_name,
            tags=r.tags,
            security_posture=posture,
            finding_count=len(res_findings),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            relationships=rels,
        )
        all_resources.append(item)

    # Apply filters
    filters_applied: Dict[str, Any] = {}
    if service:
        all_resources = [r for r in all_resources if r.service.lower() == service.lower()]
        filters_applied["service"] = service.lower()

    if resource_type:
        all_resources = [r for r in all_resources if r.resource_type.lower() == resource_type.lower()]
        filters_applied["resource_type"] = resource_type.lower()

    if region:
        all_resources = [r for r in all_resources if r.region.lower() == region.lower()]
        filters_applied["region"] = region.lower()

    if security_posture:
        posture_upper = security_posture.upper()
        if posture_upper not in _VALID_POSTURES:
            raise CloudGuardAPIError(
                status_code=400,
                error_code=ErrorCode.INVALID_FILTER,
                message=f"Invalid posture '{security_posture}'. Valid: {sorted(_VALID_POSTURES)}",
            )
        all_resources = [r for r in all_resources if r.security_posture == posture_upper]
        filters_applied["security_posture"] = posture_upper

    total = len(all_resources)
    page = all_resources[offset: offset + limit]

    return ResourceListResponse(
        items=page,
        total=total,
        limit=limit,
        offset=offset,
        filters_applied=filters_applied,
    )


@router.get("/{resource_id}", response_model=ResourceDetailResponse)
async def get_resource(
    resource_id: str,
    scan_id: Optional[str] = Query(None, description="Scan ID (defaults to search all scans)"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.RESOURCES_READ)),
):
    """
    Get full details for a single resource, including its configuration,
    relationships, and all findings associated with it.
    """
    service_ref = get_scan_service(db)

    found_record = None
    target_resource = None

    if scan_id:
        record = service_ref.get_scan(scan_id)
        if not record:
            raise NotFoundError("Scan", scan_id)
        for r in record.resources:
            if r.resource_id == resource_id:
                found_record = record
                target_resource = r
                break
    else:
        scans = service_ref.list_scans(limit=50, offset=0)
        for record in scans:
            for r in record.resources:
                if r.resource_id == resource_id:
                    found_record = record
                    target_resource = r
                    break
            if target_resource:
                break

    if not target_resource or not found_record:
        raise NotFoundError("Resource", resource_id)

    # Gather findings for this resource
    res_findings = [f for f in found_record.findings if f.resource_id == resource_id]
    posture, counts = _derive_posture(res_findings)

    # Relationships
    relationships_by_res = extract_relationships_for_scan(found_record.resources)
    rels = [rel.model_dump() for rel in relationships_by_res.get(resource_id, [])]

    finding_responses = [_finding_to_response(f, scan_id=found_record.scan_id) for f in res_findings]

    from core.ai.masking import mask_config
    safe_config = mask_config(target_resource.config)

    return ResourceDetailResponse(
        resource_id=target_resource.resource_id,
        resource_type=target_resource.resource_type.value,
        service=target_resource.service,
        provider=target_resource.provider,
        account_id=target_resource.account_id,
        region=target_resource.region,
        name=target_resource.display_name,
        tags=target_resource.tags,
        security_posture=posture,
        finding_count=len(res_findings),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        relationships=rels,
        config=safe_config,
        findings=finding_responses,
    )

