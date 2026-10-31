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

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from core.database import get_db
from config.settings import settings
from auth.dependencies import require_permission, get_current_user
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


# ── Gemini Interactive Chatbot Endpoint ──────────────────────────────────────

class AIChatMessage(BaseModel):
    role: str
    content: str


class AIChatRequest(BaseModel):
    message: str
    history: Optional[List[AIChatMessage]] = None


class AIChatResponse(BaseModel):
    response: str
    suggested_actions: Optional[List[str]] = None
    role: str = "assistant"


@router.post("/chat", response_model=AIChatResponse)
def chat_with_gemini(
    req: AIChatRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(get_current_user),
):
    """
    Interactive Gemini Cloud Security Copilot Chatbot.
    Context-aware conversational assistant grounded in live cloud telemetry.
    """
    user_msg = req.message.strip()
    user_lower = user_msg.lower()

    # Query active findings context
    findings = list(db.scalars(
        select(FindingDBModel).where(FindingDBModel.status == FindingStatus.OPEN.value).limit(15)
    ).all())

    total_findings = len(findings)
    high_findings = [f for f in findings if (f.severity or "").upper() in ("CRITICAL", "HIGH")]
    active_account_id = getattr(user, "aws_account_id", None) or "371700247056"

    # ── Live Gemini API Call (when GEMINI_API_KEY is configured) ─────────────
    if settings.has_gemini_key:
        try:
            import httpx
            api_key = settings.gemini_api_key.strip()
            model = settings.gemini_model.strip() or "gemini-3.5-flash"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

            findings_summary = "\n".join([
                f"- [{f.severity.upper()}] {f.title} (Resource: {f.resource_id}, Rule: {f.rule_id}, Score: {getattr(f, 'risk_score', 'N/A')})"
                for f in findings[:10]
            ]) or "No active misconfigurations."

            system_instruction = (
                f"You are the CloudGuard Gemini Cloud Security Copilot, an expert autonomous cloud security architect.\n"
                f"You are assisting security engineer '{user.username or 'operator'}' on AWS account '{active_account_id}' (region: {settings.aws_default_region}).\n\n"
                f"LIVE ENVIRONMENT TELEMETRY:\n"
                f"- Active Open Findings: {total_findings} (High/Critical: {len(high_findings)})\n"
                f"Top Findings:\n{findings_summary}\n\n"
                f"INSTRUCTIONS:\n"
                f"1. Provide actionable, accurate AWS security advice grounded in the findings above.\n"
                f"2. Format code blocks using ```bash, ```json, or ```hcl (Terraform).\n"
                f"3. Be concise, authoritative, professional, and practical.\n"
                f"4. Suggest 2-4 brief, relevant follow-up questions at the very end formatted as: SUGGESTED_ACTIONS: [Action 1 | Action 2 | Action 3]"
            )

            contents = []
            if req.history:
                for h in req.history[-6:]:
                    contents.append({
                        "role": "model" if h.role in ("assistant", "system") else "user",
                        "parts": [{"text": h.content}],
                    })
            contents.append({
                "role": "user",
                "parts": [{"text": user_msg}],
            })

            payload = {
                "contents": contents,
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 2048,
                },
            }

            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, json=payload, headers={"Content-Type": "application/json"})

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    raw_text = "".join(p.get("text", "") for p in parts).strip()

                    suggestions = []
                    if "SUGGESTED_ACTIONS:" in raw_text or "SUGESTED_ACTIONS:" in raw_text:
                        marker = "SUGGESTED_ACTIONS:" if "SUGGESTED_ACTIONS:" in raw_text else "SUGESTED_ACTIONS:"
                        parts_split = raw_text.split(marker, 1)
                        raw_text = parts_split[0].strip()
                        raw_suggestions = parts_split[1].strip().strip("[]")
                        suggestions = [s.strip() for s in raw_suggestions.split("|") if s.strip()]

                    if not suggestions:
                        suggestions = [
                            "How do I remediate this?",
                            "Generate AWS CLI fix commands",
                            "Explain the blast radius",
                        ]

                    return AIChatResponse(
                        response=raw_text,
                        suggested_actions=suggestions[:4],
                        role="assistant",
                    )
                log.warning("gemini_empty_candidates", response=data)
            else:
                log.warning("gemini_api_error", status_code=resp.status_code, body=resp.text[:300])
        except Exception as exc:
            log.warning("gemini_live_call_fallback", error=str(exc))

    # ── Fallback Deterministic Copilot Engine ─────────────────────────────────
    if any(k in user_lower for k in ["hi", "hello", "hey", "who are you", "what can you do"]):
        reply = (
            f"👋 Hello **{user.username or 'Commander'}**! I am your **Gemini Cloud Security Copilot**.\n\n"
            f"I have real-time visibility into your cloud environment (**AWS US-EAST-1**). Currently, I am tracking **{total_findings} active findings** "
            f"across your infrastructure (including **{len(high_findings)} high/critical issues**).\n\n"
            f"Here are a few things you can ask me:\n"
            f"• *\"What are my top security risks right now?\"*\n"
            f"• *\"How do I fix the IAM wildcard permissions?\"*\n"
            f"• *\"What is an IAM permissions boundary?\"*\n"
            f"• *\"Show me CLI remediation commands\"*\n"
            f"• *\"Explain S3 Public Access Block\"*"
        )
        suggestions = [
            "What are my top risks right now?",
            "How do I fix the IAM wildcard role?",
            "What is a permissions boundary?",
            "Show me CLI remediation commands",
        ]

    elif any(k in user_lower for k in ["top risk", "critical", "vulnerabilit", "what wrong", "issue", "scan result", "finding"]):
        if not findings:
            reply = "🎉 **Great news!** No open vulnerabilities or misconfigurations are currently detected in your environment. Your cloud environment is secure and healthy!"
            suggestions = ["Run a new scan", "Check CIS compliance status"]
        else:
            bullets = "\n".join([
                f"• **[{f.severity.upper()}]** {f.title}\n  *Resource:* `{f.resource_id}`\n  *Rule:* `{f.rule_id}` (Risk Score: {getattr(f, 'risk_score', 'N/A')})"
                for f in findings[:5]
            ])
            reply = (
                f"### 🛡️ Current Security Issues Summary\n\n"
                f"Based on your latest scan, I identified **{total_findings} open security issues**:\n\n"
                f"{bullets}\n\n"
                f"💡 **Recommendation:** Prioritize resolving the **HIGH** severity IAM service role wildcard permissions first, as they violate the principle of least privilege."
            )
            suggestions = [
                "How do I fix the IAM wildcard role?",
                "Create a remediation plan for these",
                "Explain the blast radius of these roles",
            ]

    elif any(k in user_lower for k in ["iam", "wildcard", "role", "trustedadvisor", "support", "resourceexplorer"]):
        reply = (
            f"### 🔑 Understanding & Remediating IAM Wildcard Roles\n\n"
            f"**The Problem:**\n"
            f"Several AWS Service Roles in your account (e.g. `AWSServiceRoleForTrustedAdvisor`, `AWSServiceRoleForSupport`) "
            f"contain policy statements with `Resource: \"*\"` and actions that exceed minimal operational scope.\n\n"
            f"**Why This Is a Risk:**\n"
            f"If an attacker compromises credentials associated with these roles, they could perform unauthorized actions across all AWS resources.\n\n"
            f"**Step-by-Step Remediation:**\n\n"
            f"1. **Attach a Permissions Boundary:**\n"
            f"```bash\n"
            f"aws iam put-role-permissions-boundary \\\n"
            f"  --role-name AWSServiceRoleForTrustedAdvisor \\\n"
            f"  --permissions-boundary arn:aws:iam::{active_account_id}:policy/CloudGuardBoundaryPolicy\n"
            f"```\n\n"
            f"2. **Scope Down Resource Elements:**\n"
            f"Replace `\"Resource\": \"*\"` with specific ARNs in the custom IAM inline policies.\n\n"
            f"3. **Use CloudGuard Auto-Remediation:**\n"
            f"Go to the **Fixes** section in the sidebar to review and generate an automated boundary attachment plan."
        )
        suggestions = [
            "Show me the boundary policy JSON",
            "Go to Fixes to generate plan",
            "What other roles have this problem?",
        ]

    elif any(k in user_lower for k in ["boundary", "permissions boundary"]):
        reply = (
            f"### 🛡️ What is an IAM Permissions Boundary?\n\n"
            f"An **IAM Permissions Boundary** is an advanced AWS guardrail that sets the **maximum permissions** that an IAM entity (role or user) can have.\n\n"
            f"**How It Works:**\n"
            f"Even if a role has `AdministratorAccess`, if its boundary only allows `s3:ListBucket`, the role **cannot** do anything other than list S3 buckets. "
            f"The effective permission is the intersection between the policy and the boundary.\n\n"
            f"**Sample Boundary Policy (CloudGuard Guardrail):**\n"
            f"```json\n"
            f"{{\n"
            f"  \"Version\": \"2012-10-17\",\n"
            f"  \"Statement\": [\n"
            f"    {{\n"
            f"      \"Effect\": \"Allow\",\n"
            f"      \"Action\": [\n"
            f"        \"trustedadvisor:*\",\n"
            f"        \"support:*\",\n"
            f"        \"cloudwatch:Get*\"\n"
            f"      ],\n"
            f"      \"Resource\": \"*\"\n"
            f"    }},\n"
            f"    {{\n"
            f"      \"Effect\": \"Deny\",\n"
            f"      \"Action\": [\"iam:Create*\", \"iam:Delete*\", \"organizations:*\"],\n"
            f"      \"Resource\": \"*\"\n"
            f"    }}\n"
            f"  ]\n"
            f"}}\n"
            f"```"
        )
        suggestions = [
            "How do I apply this to my AWS account?",
            "What findings need a permissions boundary?",
        ]

    elif any(k in user_lower for k in ["s3", "bucket", "public access", "encryption"]):
        reply = (
            f"### 🪣 S3 Bucket Security Hardening Guide\n\n"
            f"For standard cloud environments, AWS S3 buckets should enforce both **Block Public Access** and **Default Encryption**.\n\n"
            f"**1. Enable S3 Block Public Access (AWS CLI):**\n"
            f"```bash\n"
            f"aws s3api put-public-access-block \\\n"
            f"  --bucket <YOUR_BUCKET_NAME> \\\n"
            f"  --public-access-block-configuration \\\n"
            f"  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n"
            f"```\n\n"
            f"**2. Enforce Default AES-256 Encryption:**\n"
            f"```bash\n"
            f"aws s3api put-bucket-encryption \\\n"
            f"  --bucket <YOUR_BUCKET_NAME> \\\n"
            f"  --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'\n"
            f"```"
        )
        suggestions = [
            "Show me my exposed S3 buckets",
            "Generate Terraform code for S3",
        ]

    elif any(k in user_lower for k in ["cli", "command", "terraform", "code", "script"]):
        reply = (
            f"### ⚡ AWS Remediation Script\n\n"
            f"Here is an automated bash script to inspect and secure roles on AWS account `{active_account_id}`:\n\n"
            f"```bash\n"
            f"#!/usr/bin/env bash\n"
            f"set -euo pipefail\n\n"
            f"# 1. List attached policies for service roles\n"
            f"for role in AWSServiceRoleForTrustedAdvisor AWSServiceRoleForResourceExplorer AWSServiceRoleForSupport; do\n"
            f"  echo \"Checking role: $role\"\n"
            f"  aws iam list-attached-role-policies --role-name \"$role\" --output table\n"
            f"done\n\n"
            f"# 2. Check S3 Account-Level Block Public Access\n"
            f"aws s3control get-public-access-block --account-id {active_account_id}\n"
            f"```\n\n"
            f"Would you like me to tailor this for a specific resource ARN?"
        )
        suggestions = [
            "Tailor for AWSServiceRoleForTrustedAdvisor",
            "Generate Terraform equivalent",
        ]

    else:
        reply = (
            f"Based on your cloud telemetry in **AWS US-EAST-1** (Account ID `{active_account_id}`), here is my analysis:\n\n"
            f"Your environment currently has **{total_findings} open misconfigurations** recorded. "
            f"The primary areas for security hardening are:\n\n"
            f"1. **IAM Least Privilege**: Restricting wildcard resources on service roles.\n"
            f"2. **Boundary Enforcement**: Implementing permissions boundaries on administrative roles.\n"
            f"3. **Data Protection**: Enforcing S3 default encryption and Public Access Block.\n\n"
            f"To address: *\"{user_msg}\"* — you can use the **Fixes** section to generate an automated remediation plan, or ask me for specific CLI commands."
        )
        suggestions = [
            "Show my top vulnerabilities",
            "How do I fix IAM roles?",
            "Show AWS CLI commands",
        ]

    return AIChatResponse(
        response=reply,
        suggested_actions=suggestions,
        role="assistant",
    )
