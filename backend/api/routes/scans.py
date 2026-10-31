"""
CloudGuard — Scan Routes

POST /scans          — run a new scan
GET  /scans          — list all scans (paginated)
GET  /scans/{id}     — get a specific scan by ID

Scan execution modes:
  - Demo mode: Runs synchronously (fast, <1s). Returns completed scan.
  - AWS mode:  Runs asynchronously. Returns 202 with scan_id in QUEUED status.
               Client polls GET /scans/{id} until status is COMPLETED or FAILED.
"""
from __future__ import annotations

import threading
from typing import Optional

from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from core.database import get_db, SessionLocal

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission

from api.errors import (
    AWSAuthError,
    InvalidScenarioError,
    NotFoundError,
    ScanFailedError,
)
from api.schemas import (
    RiskSummaryResponse,
    ScanListResponse,
    ScanRequest,
    ScanSummaryResponse,
    ScanErrorResponse,
    SeveritySummary,
)
from config.settings import settings
from core.providers.demo.provider import DemoProvider
from services.scan_models import ScanRecord, ScanStatus
from services.scan_service import get_scan_service, ScanService
from core.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _record_to_summary(record: ScanRecord) -> ScanSummaryResponse:
    """Convert a domain ScanRecord to the API response schema."""
    severity_counts = record.severity_counts
    sev_summary = SeveritySummary(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        informational=severity_counts.get("informational", 0),
    )

    risk_resp = None
    if record.risk_summary:
        rs = record.risk_summary
        risk_resp = RiskSummaryResponse(
            posture_score=rs.posture_score,
            risk_level=rs.risk_level,
            severity_counts=sev_summary,
            top_risk_score=rs.top_risk_score,
            average_risk_score=rs.average_risk_score,
            open_finding_count=rs.open_finding_count,
            total_finding_count=rs.total_finding_count,
        )

    return ScanSummaryResponse(
        scan_id=record.scan_id,
        correlation_id=record.correlation_id,
        provider=record.provider,
        account_id=record.account_id,
        mode=record.mode,
        scenario=record.scenario,
        status=record.status.value,
        regions=record.regions,
        resource_count=record.resource_count,
        finding_count=record.finding_count,
        severity_summary=sev_summary,
        risk_summary=risk_resp,
        started_at=record.started_at.isoformat(),
        completed_at=record.completed_at.isoformat() if record.completed_at else None,
        duration_seconds=record.duration_seconds,
        error_count=len(record.errors),
        error_message=record.error_message,
    )


def _get_provider(request: ScanRequest):
    """Instantiate the correct provider based on settings and request."""
    if settings.is_demo_mode:
        if not request.scenario:
            return DemoProvider(scenario="default")
        scenario = request.scenario
        scenario_alias_map = {
            "full": "default",
            "s3_critical": "critical",
            "iam_privilege": "critical",
            "network_ingress": "default",
        }
        mapped_scenario = scenario_alias_map.get(scenario, scenario)
        if mapped_scenario not in DemoProvider.available_scenarios():
            raise InvalidScenarioError(request.scenario, available=DemoProvider.available_scenarios())
        return DemoProvider(scenario=mapped_scenario)

    # AWS mode
    from core.providers.aws.provider import AWSProvider
    provider = AWSProvider(
        region=settings.aws_default_region,
        profile=settings.aws_profile,
        access_key_id=settings.aws_access_key_id,
        secret_access_key=settings.aws_secret_access_key,
        role_arn=settings.aws_role_arn,
        role_session_name=settings.aws_role_session_name,
        external_id=settings.aws_external_id,
    )
    try:
        provider.validate_connection()
    except (ConnectionError, Exception) as exc:
        log.warning("aws_auth_failed", error=str(exc))
        raise AWSAuthError()
    return provider


def _run_scan_in_background(
    scan_id: str,
    provider,
    regions,
    scenario,
    enrich_with_ai: bool,
) -> None:
    """
    Background thread function: runs the full scan pipeline with its own DB session.

    Uses its own SessionLocal() to avoid holding the request's DB connection
    for the entire duration of an AWS scan (which can take 1-3 minutes).
    """
    db = SessionLocal()
    try:
        service = ScanService(db=db)
        service.execute_scan_pipeline(
            scan_id=scan_id,
            provider=provider,
            regions=regions,
            scenario=scenario,
            enrich_with_ai=enrich_with_ai,
        )
    except Exception:
        log.error("background_scan_failed", scan_id=scan_id, exc_info=True)
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.post("", response_model=ScanSummaryResponse, status_code=201)
async def run_scan(
    request: ScanRequest = None,
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.SCANS_CREATE)),
):
    """
    Initiate a security scan.

    **Demo mode**: Runs synchronously (fast). Returns completed scan with 201.
    **AWS mode**: Returns 202 with scan in QUEUED status. The scan runs in a
    background thread. Poll `GET /scans/{scan_id}` for progress and results.

    Returns the scan summary. Use GET /findings?scan_id={id}
    to retrieve individual findings once the scan is COMPLETED.
    """
    if request is None:
        request = ScanRequest()

    provider = _get_provider(request)
    service = get_scan_service(db)

    # ── Demo mode: synchronous (fast, <1s) ────────────────────────────────
    if settings.is_demo_mode:
        record = service.run_scan(
            provider=provider,
            regions=request.regions,
            scenario=request.scenario,
            enrich_with_ai=request.enrich_with_ai,
        )
        if record.status == ScanStatus.FAILED:
            raise ScanFailedError(
                message=record.error_message or "Scan execution failed.",
                request_id=record.correlation_id,
            )
        return _record_to_summary(record)

    # ── AWS mode: async (scan runs in background thread) ──────────────────
    # Phase 1: Create the scan record immediately and return it.
    record = service.initiate_scan(
        provider=provider,
        regions=request.regions,
        scenario=request.scenario,
    )

    # Phase 2: Launch background thread with its own DB session.
    # Using a thread rather than FastAPI BackgroundTasks so we get a fresh
    # DB connection and don't hold the request's connection for minutes.
    scan_thread = threading.Thread(
        target=_run_scan_in_background,
        kwargs={
            "scan_id": record.scan_id,
            "provider": provider,
            "regions": request.regions,
            "scenario": request.scenario,
            "enrich_with_ai": request.enrich_with_ai,
        },
        name=f"scan-{record.scan_id[:8]}",
        daemon=True,
    )
    scan_thread.start()

    log.info(
        "scan_dispatched_to_background",
        scan_id=record.scan_id,
        thread_name=scan_thread.name,
    )

    return _record_to_summary(record)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100, description="Number of scans per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.SCANS_READ)),
):
    """
    List all scans, most recent first.

    Supports pagination via limit/offset and optional status filtering.
    """
    service = get_scan_service(db)

    # Validate status filter
    status_filter = None
    if status:
        try:
            status_filter = ScanStatus(status.upper())
        except ValueError:
            from api.errors import CloudGuardAPIError, ErrorCode
            raise CloudGuardAPIError(
                status_code=400,
                error_code=ErrorCode.INVALID_FILTER,
                message=f"Invalid status filter '{status}'. Valid values: {[s.value for s in ScanStatus]}",
            )

    records = service.list_scans(limit=limit, offset=offset, status=status_filter)
    total = service.total_scan_count()

    return ScanListResponse(
        items=[_record_to_summary(r) for r in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanSummaryResponse)
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _user: UserDBModel = Depends(require_permission(Permission.SCANS_READ)),
):
    """
    Get a scan by ID.

    Returns the complete scan summary including risk summary and severity breakdown.
    For AWS scans, poll this endpoint to check scan progress (status field
    transitions: QUEUED → DISCOVERING → ANALYZING → RISK_SCORING → COMPLETED).
    Use GET /findings?scan_id={id} to retrieve individual findings.
    """
    service = get_scan_service(db)
    record = service.get_scan(scan_id)
    if not record:
        raise NotFoundError("Scan", scan_id)
    return _record_to_summary(record)
