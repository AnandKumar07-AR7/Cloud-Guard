"""
CloudGuard — Automation API Router (Phase 9)
Exposes policy governance, evaluation, progression, emergency kill switch, and audit logs.
Enforces:
- JWT Authentication
- Phase 6 RBAC via require_permission()
- Resource Ownership / IDOR Protection (404 on unowned resource)
- Rate limiting protection
- Safe error envelopes with no stack traces
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from auth.dependencies import require_permission
from auth.models import UserDBModel
from auth.permissions import Permission, CloudGuardRole
from core.automation.exceptions import (
    AutomationBlockedError,
    AutomationError,
    KillSwitchActiveError,
    PolicyConflictError,
    PolicyNotFoundError,
)
from core.automation.schemas import (
    AutomationAuditEventResponse,
    AutomationDecisionResponse,
    AutomationEvaluateRequest,
    AutomationPolicyCreateRequest,
    AutomationPolicyResponse,
    AutomationPolicyUpdateRequest,
    AutomationProgressionResponse,
    AutomationProgressRequest,
    KillSwitchStatusResponse,
    KillSwitchToggleRequest,
)
from core.automation.service import AutomationService
from core.database import get_db
from core.db_models import (
    AutomationDecisionDBModel,
    AutomationPolicyDBModel,
    FindingDBModel,
    RemediationPlanDBModel,
)
from core.utils.logging import get_logger

log = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/automation",
    tags=["automation"],
)

automation_service = AutomationService()


def _get_plan_with_ownership_check(
    db: Session,
    remediation_id: str,
    user: UserDBModel,
) -> RemediationPlanDBModel:
    """
    Validates plan existence and enforces ownership scoping.
    Admin can access all plans. Non-admin can only access own plans.
    Returns 404 to prevent resource enumeration.
    """
    plan = db.scalar(
        select(RemediationPlanDBModel).where(
            RemediationPlanDBModel.remediation_id == remediation_id
        )
    )
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation plan '{remediation_id}' not found.",
        )

    is_admin = user.role and user.role.name == CloudGuardRole.ADMIN.value
    if not is_admin and plan.created_by != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation plan '{remediation_id}' not found.",
        )

    return plan


# ── 1. Policy Management Endpoints ───────────────────────────────────────────

@router.post("/policies", response_model=AutomationPolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    req: AutomationPolicyCreateRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_MANAGE)),
):
    """Create a new automation policy. Admin only."""
    try:
        return automation_service.create_policy(db, req, user.user_id)
    except PolicyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/policies", response_model=List[AutomationPolicyResponse])
def list_policies(
    enabled_only: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_READ)),
):
    """List all automation policies."""
    return automation_service.list_policies(db, enabled_only=enabled_only)


@router.get("/policies/{policy_id}", response_model=AutomationPolicyResponse)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_READ)),
):
    """Get a single automation policy by ID."""
    try:
        return automation_service.get_policy(db, policy_id)
    except PolicyNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found.")


@router.patch("/policies/{policy_id}", response_model=AutomationPolicyResponse)
def update_policy(
    policy_id: str,
    req: AutomationPolicyUpdateRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_MANAGE)),
):
    """Update an automation policy. Admin only."""
    try:
        return automation_service.update_policy(db, policy_id, req, user.user_id)
    except PolicyNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found.")
    except PolicyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_MANAGE)),
):
    """Delete an automation policy. Admin only."""
    try:
        automation_service.delete_policy(db, policy_id, user.user_id)
    except PolicyNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found.")


# ── 2. Evaluation & Progression Endpoints ─────────────────────────────────────

@router.post("/evaluate", response_model=AutomationDecisionResponse)
def evaluate_remediation(
    req: AutomationEvaluateRequest,
    target_transition: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_EVALUATE)),
):
    """
    Evaluates a remediation plan against enabled automation policies without mutating state.
    Returns the deterministic decision snapshot.
    """
    _get_plan_with_ownership_check(db, req.remediation_id, user)
    try:
        return automation_service.evaluate_remediation(
            session=db,
            remediation_id=req.remediation_id,
            user_id=user.user_id,
            target_transition=target_transition,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/progress/{remediation_id}", response_model=AutomationProgressionResponse)
def progress_remediation(
    remediation_id: str,
    req: Optional[AutomationProgressRequest] = None,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_EVALUATE)),
):
    """
    Executes a policy-approved automated lifecycle progression on a Phase 7 remediation plan.
    Row-locked and transactional.
    """
    _get_plan_with_ownership_check(db, remediation_id, user)
    transition = req.target_transition if req else None
    try:
        return automation_service.progress_remediation(
            session=db,
            remediation_id=remediation_id,
            user_id=user.user_id,
            target_transition=transition,
        )
    except KillSwitchActiveError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except AutomationBlockedError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AutomationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ── 3. Decision & Audit Endpoints ─────────────────────────────────────────────

@router.get("/decisions", response_model=List[AutomationDecisionResponse])
def list_decisions(
    remediation_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_READ)),
):
    """List historical automation decisions."""
    if remediation_id:
        _get_plan_with_ownership_check(db, remediation_id, user)
    return automation_service.list_decisions(db, remediation_id=remediation_id)


@router.get("/decisions/{decision_id}", response_model=AutomationDecisionResponse)
def get_decision(
    decision_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_READ)),
):
    """Get a specific automation decision by ID."""
    try:
        dec = automation_service.get_decision(db, decision_id)
        _get_plan_with_ownership_check(db, dec.remediation_id, user)
        return dec
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found.")


@router.get("/audit", response_model=List[AutomationAuditEventResponse])
def list_audit_events(
    remediation_id: Optional[str] = Query(default=None),
    policy_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_AUDIT_READ)),
):
    """Query immutable automation audit events."""
    if remediation_id:
        _get_plan_with_ownership_check(db, remediation_id, user)
    return automation_service.list_audit_events(db, remediation_id=remediation_id, policy_id=policy_id)


# ── 4. Kill Switch Endpoints ──────────────────────────────────────────────────

@router.get("/kill-switch", response_model=KillSwitchStatusResponse)
def get_kill_switch_status(
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_READ)),
):
    """Get current emergency kill switch status."""
    return automation_service.get_kill_switch_status(db)


@router.post("/kill-switch/enable", response_model=KillSwitchStatusResponse)
def enable_kill_switch(
    req: KillSwitchToggleRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_KILLSWITCH)),
):
    """Emergency halt: activate global automation kill switch. Admin only."""
    return automation_service.set_kill_switch(db, enabled=True, user_id=user.user_id, reason=req.reason)


@router.post("/kill-switch/disable", response_model=KillSwitchStatusResponse)
def disable_kill_switch(
    req: KillSwitchToggleRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AUTOMATION_KILLSWITCH)),
):
    """Deactivate global automation kill switch. Admin only."""
    return automation_service.set_kill_switch(db, enabled=False, user_id=user.user_id, reason=req.reason)
