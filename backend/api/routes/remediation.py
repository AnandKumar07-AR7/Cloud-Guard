"""
CloudGuard — Remediation API Router (Phase 7)

Routes:
  POST /api/v1/remediations/plans              PERMISSION: remediations.create
  GET  /api/v1/remediations/plans/{id}         PERMISSION: remediations.read
  POST /api/v1/remediations/plans/{id}/validate PERMISSION: remediations.validate
  POST /api/v1/remediations/plans/{id}/approve  PERMISSION: remediations.approve
  POST /api/v1/remediations/plans/{id}/execute  PERMISSION: remediations.execute
  POST /api/v1/remediations/plans/{id}/verify   PERMISSION: remediations.read
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from core.database import get_db
from auth.dependencies import require_permission
from auth.permissions import Permission
from auth.models import UserDBModel
from core.remediation.models import RemediationPlan, RemediationAuditEvent
from services.remediation_service import RemediationService

router = APIRouter(
    prefix="/api/v1/remediations",
    tags=["remediations"],
)

remediation_service = RemediationService()


@router.get("/plans", response_model=List[RemediationPlan])
def list_plans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    state: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_READ)),
):
    """List remediation plans with optional filtering and pagination."""
    return remediation_service.list_plans(db, limit=limit, offset=offset, state=state)


@router.post("/plans", response_model=RemediationPlan, status_code=status.HTTP_201_CREATED)
def create_plan(
    finding_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_CREATE)),
):
    """Creates a new deterministic remediation plan for a finding."""
    try:
        return remediation_service.create_plan(db, finding_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/plans/{remediation_id}", response_model=RemediationPlan)
def get_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_READ)),
):
    """Get a specific remediation plan by ID."""
    try:
        return remediation_service.get_plan(db, remediation_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")


@router.post("/plans/{remediation_id}/validate", response_model=RemediationPlan)
def validate_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_VALIDATE)),
):
    """Validate a DRAFT remediation plan before approval."""
    try:
        return remediation_service.validate_plan(db, remediation_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/plans/{remediation_id}/approve", response_model=RemediationPlan)
def approve_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_APPROVE)),
):
    """Approve a PENDING_APPROVAL plan. Requires separation of duties — creator cannot approve."""
    try:
        return remediation_service.approve_plan(db, remediation_id, user.user_id)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/plans/{remediation_id}/execute", response_model=RemediationPlan)
def execute_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_EXECUTE)),
):
    """Execute an APPROVED remediation plan against the target provider."""
    try:
        return remediation_service.execute_plan(db, remediation_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/plans/{remediation_id}/verify", response_model=RemediationPlan)
def verify_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_READ)),
):
    """Independently verify whether an EXECUTED remediation actually fixed the finding."""
    try:
        return remediation_service.verify_plan(db, remediation_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/plans/{remediation_id}/reject", response_model=RemediationPlan)
def reject_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_APPROVE)),
):
    """Reject a PENDING_APPROVAL remediation plan."""
    try:
        return remediation_service.reject_plan(db, remediation_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/plans/{remediation_id}/cancel", response_model=RemediationPlan)
def cancel_plan(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_CANCEL)),
):
    """Cancel an active remediation plan."""
    try:
        return remediation_service.cancel_plan(db, remediation_id, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/plans/{remediation_id}/audit", response_model=List[RemediationAuditEvent])
def get_audit_events(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_AUDIT_READ)),
):
    """Get immutable audit events for a remediation plan."""
    try:
        return remediation_service.get_audit_events(db, remediation_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/plans/{remediation_id}/audit/verify")
def verify_audit_chain(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_AUDIT_READ)),
):
    """Verify cryptographic hash chain integrity for a remediation plan's audit events."""
    try:
        return remediation_service.verify_audit_chain(db, remediation_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

