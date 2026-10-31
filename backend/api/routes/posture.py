"""
CloudGuard — Security Posture Routes

GET /posture — comprehensive environment and service security posture breakdown  [posture.read]
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from core.database import get_db

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission
from api.errors import NotFoundError
from api.routes.resources import _derive_posture
from api.schemas import PostureResponse
from core.risk.engine import calculate_service_posture
from services.scan_service import get_scan_service
from services.scan_models import ScanStatus
from core.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/posture", tags=["Posture"])


@router.get("", response_model=PostureResponse)
async def get_security_posture(
    scan_id: Optional[str] = Query(None, description="Scan ID (defaults to latest scan)"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.POSTURE_READ)),
):
    """
    Get the overall security posture and per-service breakdown.

    If scan_id is omitted, returns posture from the latest scan.
    """
    service_ref = get_scan_service(db)

    if scan_id:
        record = service_ref.get_scan(scan_id)
        if not record:
            raise NotFoundError("Scan", scan_id)
    else:
        # Prioritize the latest COMPLETED scan so an in-flight QUEUED/RUNNING scan does not produce a false 100/100 score
        scans = service_ref.list_scans(limit=1, offset=0, status=ScanStatus.COMPLETED)
        if not scans:
            scans = service_ref.list_scans(limit=1, offset=0)
        record = scans[0] if scans else None

    # If the retrieved record is still in-progress (QUEUED, RUNNING) and has no risk summary yet,
    # fallback to the most recent completed scan so the caller gets real posture data instead of an empty snapshot.
    if record and record.status != ScanStatus.COMPLETED and not record.risk_summary:
        completed = service_ref.list_scans(limit=1, offset=0, status=ScanStatus.COMPLETED)
        if completed:
            record = completed[0]

    if not record:
        return PostureResponse(
            posture_score=100.0,
            risk_level="NONE",
            total_resources=0,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            service_posture={},
            resource_posture_summary={"SECURE": 0, "AT_RISK": 0, "HIGH_RISK": 0, "CRITICAL": 0},
            last_scanned_at=None,
        )

    # Risk summary
    posture_score = record.risk_summary.posture_score if record.risk_summary else 100.0
    risk_level = record.risk_summary.risk_level if record.risk_summary else "NONE"

    # Count findings by severity
    critical_count = sum(1 for f in record.findings if f.severity.value == "critical" and f.is_open)
    high_count = sum(1 for f in record.findings if f.severity.value == "high" and f.is_open)
    medium_count = sum(1 for f in record.findings if f.severity.value == "medium" and f.is_open)
    low_count = sum(1 for f in record.findings if f.severity.value == "low" and f.is_open)

    # Per-service posture
    svc_posture = calculate_service_posture(record.findings)

    # Resource posture summary
    findings_by_res = {}
    for f in record.findings:
        findings_by_res.setdefault(f.resource_id, []).append(f)

    posture_counts = {"SECURE": 0, "AT_RISK": 0, "HIGH_RISK": 0, "CRITICAL": 0}
    for r in record.resources:
        p, _ = _derive_posture(findings_by_res.get(r.resource_id, []))
        if p in posture_counts:
            posture_counts[p] += 1

    last_scanned = record.completed_at.isoformat() if record.completed_at else record.started_at.isoformat()

    return PostureResponse(
        posture_score=posture_score,
        risk_level=risk_level,
        total_resources=len(record.resources),
        total_findings=len(record.findings),
        critical_findings=critical_count,
        high_findings=high_count,
        medium_findings=medium_count,
        low_findings=low_count,
        service_posture=svc_posture,
        resource_posture_summary=posture_counts,
        last_scanned_at=last_scanned,
    )
