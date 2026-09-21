"""
CloudGuard — AI API Router (Phase 8)

Endpoints for AI security analysis runs, recommendations, and audit logs.
Enforces:
- JWT Authentication
- Phase 6 RBAC
- Resource Ownership / IDOR Protection
- Process-Local Single-Instance Rate Limiting
- Recommendation Immutability (append-only)
- Strict Phase 7 Execution Boundary
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from core.database import get_db
from auth.dependencies import require_permission
from auth.permissions import Permission, CloudGuardRole
from auth.models import UserDBModel
from core.ai.schemas import (
    AIAnalyzeRequest,
    AIAgentRunResponse,
    AIRecommendationResponse,
    AIToolEventResponse,
)
from core.ai.orchestrator import AIAgentOrchestrator
from core.ai.rate_limiter import ai_rate_limiter
from core.db_models import (
    AIAgentRunDBModel,
    AIRecommendationDBModel,
    AIToolEventDBModel,
    FindingDBModel,
)
from core.remediation.models import RemediationPlan
from core.remediation.strategy import get_strategy
from core.security.models import FindingStatus
from services.remediation_service import RemediationService
from core.utils.logging import get_logger

log = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/ai",
    tags=["ai"],
)

remediation_service = RemediationService()


# ── IDOR / Ownership Helper ───────────────────────────────────────────────────

def _get_run_with_ownership_check(
    db: Session,
    run_id: str,
    user: UserDBModel,
) -> AIAgentRunDBModel:
    """
    Retrieves an AI run enforcing ownership boundaries.
    ADMINs can view all runs.
    Non-ADMINs can only view their own runs.
    Returns 404 to prevent resource enumeration.
    """
    run = db.scalar(select(AIAgentRunDBModel).where(AIAgentRunDBModel.run_id == run_id))
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI analysis run '{run_id}' not found.",
        )

    is_admin = user.role and user.role.name == CloudGuardRole.ADMIN.value
    if not is_admin and run.initiating_user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI analysis run '{run_id}' not found.",
        )

    return run


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AIAgentRunResponse, status_code=status.HTTP_201_CREATED)
def initiate_analysis(
    req: AIAnalyzeRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_ANALYZE)),
):
    """
    Initiates a bounded, server-controlled AI security analysis run for a finding.
    Rate limited to 10 requests per user per minute (process-local).
    """
    # 1. Rate Limiting Check
    ai_rate_limiter.check_rate_limit(user.user_id)

    # 2. Check Finding Exists
    finding = db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == req.finding_id))
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{req.finding_id}' not found.",
        )

    # 3. Execute Orchestrator
    orchestrator = AIAgentOrchestrator(session=db)
    run, rec = orchestrator.run_analysis(finding_id=req.finding_id, user_id=user.user_id)

    if run.status == "FAILED" and run.error_category in ("provider_error", "provider_timeout"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI Provider error: {run.error_category}",
        )

    return run


@router.get("/runs", response_model=List[AIAgentRunResponse])
def list_runs(
    finding_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_READ)),
):
    """
    Lists AI analysis runs.
    SECURITY_ANALYSTs see only their own runs. ADMINs see all runs.
    """
    stmt = select(AIAgentRunDBModel).order_by(AIAgentRunDBModel.created_at.desc()).limit(limit)

    is_admin = user.role and user.role.name == CloudGuardRole.ADMIN.value
    if not is_admin:
        stmt = stmt.where(AIAgentRunDBModel.initiating_user_id == user.user_id)

    if finding_id:
        stmt = stmt.where(AIAgentRunDBModel.finding_id == finding_id)

    runs = db.scalars(stmt).all()
    return list(runs)


@router.get("/runs/{run_id}", response_model=AIAgentRunResponse)
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_READ)),
):
    """Get status and details of an AI analysis run with IDOR protection."""
    return _get_run_with_ownership_check(db, run_id, user)


@router.get("/runs/{run_id}/recommendations", response_model=List[AIRecommendationResponse])
def get_run_recommendations(
    run_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_READ)),
):
    """Get recommendations produced by an AI run with IDOR protection."""
    _get_run_with_ownership_check(db, run_id, user)
    recs = db.scalars(
        select(AIRecommendationDBModel).where(AIRecommendationDBModel.run_id == run_id)
    ).all()
    return list(recs)


@router.get("/recommendations/{recommendation_id}", response_model=AIRecommendationResponse)
def get_recommendation(
    recommendation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_READ)),
):
    """Get specific AI recommendation by ID with IDOR protection. Immutable record."""
    rec = db.scalar(
        select(AIRecommendationDBModel).where(
            AIRecommendationDBModel.recommendation_id == recommendation_id
        )
    )
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI recommendation '{recommendation_id}' not found.",
        )

    # Enforce run ownership
    _get_run_with_ownership_check(db, rec.run_id, user)
    return rec


@router.get("/runs/{run_id}/audit", response_model=List[AIToolEventResponse])
def get_run_audit_events(
    run_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.AI_AUDIT_READ)),
):
    """Get tool execution audit events for an AI run with IDOR protection."""
    _get_run_with_ownership_check(db, run_id, user)
    events = db.scalars(
        select(AIToolEventDBModel)
        .where(AIToolEventDBModel.run_id == run_id)
        .order_by(AIToolEventDBModel.created_at.asc())
    ).all()
    return list(events)


@router.post(
    "/recommendations/{recommendation_id}/remediation-plan",
    response_model=RemediationPlan,
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_plan_from_recommendation(
    recommendation_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.REMEDIATIONS_CREATE)),
):
    """
    Explicit user-driven conversion of an AI recommendation into a Phase 7 RemediationPlan.
    CRITICAL: Requires Phase 7 'remediations.create' permission.
    AI recommendation provides zero remediation authority.
    Re-validates recommendation, finding, strategy allowlist, and concurrency before creating DRAFT plan.
    """
    # 1. Validate Recommendation Exists
    rec = db.scalar(
        select(AIRecommendationDBModel).where(
            AIRecommendationDBModel.recommendation_id == recommendation_id
        )
    )
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI recommendation '{recommendation_id}' not found.",
        )

    # 2. Enforce Run Ownership Check
    _get_run_with_ownership_check(db, rec.run_id, user)

    # 3. Re-validate Finding Exists
    finding = db.scalar(
        select(FindingDBModel)
        .where(FindingDBModel.finding_id == rec.finding_id)
        .with_for_update()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Finding '{rec.finding_id}' associated with recommendation no longer exists.",
        )

    # 4. Re-validate Finding is eligible for remediation
    if finding.status not in (FindingStatus.OPEN.value, FindingStatus.STILL_VULNERABLE.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Finding '{finding.finding_id}' is in status '{finding.status}' and cannot be remediated.",
        )

    # 5. Re-validate Recommended Strategy
    if not rec.recommended_strategy_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI recommendation does not specify a remediation strategy.",
        )

    # 6. Re-validate Strategy is in Phase 7 Allowlist
    strategy = get_strategy(rec.recommended_strategy_id)
    if not strategy:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Strategy '{rec.recommended_strategy_id}' is not in the Phase 7 allowlist.",
        )

    # 7. Delegate to Phase 7 Safe Remediation Engine (starts in DRAFT state)
    try:
        plan = remediation_service.create_plan(
            session=db,
            finding_id=finding.finding_id,
            user_id=user.user_id,
        )
        return plan
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
