"""
CloudGuard — Deterministic Policy Evaluation Engine (Phase 9)
Evaluates findings and remediation plans against declarative automation policies.
Guarantees:
- Zero dynamic code execution (no eval, no exec, no shell).
- Strict fail-closed semantics.
- Destructive action unconditional blocking.
- Kill switch supremacy.
- Deterministic priority ordering and cryptographic policy hashing.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.automation.models import AutomationDecisionType
from core.db_models import AutomationPolicyDBModel, FindingDBModel, RemediationPlanDBModel
from core.remediation.state import RemediationSafety, RemediationState


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class PolicyEvaluationResult:
    decision: AutomationDecisionType
    reason: str
    matched_policy: Optional[AutomationPolicyDBModel] = None
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    policy_hash: Optional[str] = None
    decision_context: Dict[str, Any] = field(default_factory=dict)


def compute_policy_hash(policy: AutomationPolicyDBModel) -> str:
    """
    Computes deterministic SHA-256 hash of the policy criteria snapshot.
    Guarantees decision reproducibility and tamper-evident explainability.
    """
    payload = {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "name": policy.name,
        "allowed_providers": sorted(policy.allowed_providers or []),
        "allowed_services": sorted(policy.allowed_services or []),
        "allowed_resource_types": sorted(policy.allowed_resource_types or []),
        "allowed_rule_ids": sorted(policy.allowed_rule_ids or []),
        "allowed_strategies": sorted(policy.allowed_strategies or []),
        "allowed_action_types": sorted(policy.allowed_action_types or []),
        "allowed_safety_levels": sorted(policy.allowed_safety_levels or []),
        "min_severity": policy.min_severity,
        "max_severity": policy.max_severity,
        "auto_progress_validation": policy.auto_progress_validation,
        "auto_progress_approval": policy.auto_progress_approval,
        "auto_progress_execution": policy.auto_progress_execution,
        "require_human_approval": policy.require_human_approval,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


class PolicyEngine:
    """
    Server-controlled, deterministic automation policy evaluator.
    """

    @staticmethod
    def evaluate(
        finding: FindingDBModel,
        plan: RemediationPlanDBModel,
        policies: List[AutomationPolicyDBModel],
        kill_switch_active: bool = False,
        target_transition: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        provider = getattr(finding, "provider", None)
        if not provider and hasattr(finding, "resource") and finding.resource:
            provider = getattr(finding.resource, "provider", None)
        if not provider and hasattr(finding, "scan") and finding.scan:
            provider = getattr(finding.scan, "provider", None)
        if not provider:
            provider = "demo"

        context = {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "provider": provider,
            "service": finding.service,
            "resource_type": finding.resource_type,
            "remediation_id": plan.remediation_id,
            "current_plan_state": plan.state,
            "target_transition": target_transition,
        }

        # ── 1. Kill Switch Invariant ──────────────────────────────────────────
        if kill_switch_active:
            return PolicyEvaluationResult(
                decision=AutomationDecisionType.BLOCKED_BY_KILL_SWITCH,
                reason="Emergency automation kill switch is ACTIVE. All automated progression is halted.",
                decision_context=context,
            )

        # ── 2. Destructive Action Invariant ───────────────────────────────────
        for action in plan.actions:
            if action.safety == RemediationSafety.DESTRUCTIVE.value:
                return PolicyEvaluationResult(
                    decision=AutomationDecisionType.BLOCKED_BY_SAFETY,
                    reason=f"Action '{action.action_type}' has safety level DESTRUCTIVE. Destructive actions are strictly barred from automation.",
                    decision_context=context,
                )

        # ── 3. Filter Enabled Policies ────────────────────────────────────────
        active_policies = [p for p in policies if p.enabled]
        if not active_policies:
            return PolicyEvaluationResult(
                decision=AutomationDecisionType.NOT_ELIGIBLE,
                reason="No active, enabled automation policies found. Defaulting to fail-closed.",
                decision_context=context,
            )

        # ── 4. Deterministic Ordering ─────────────────────────────────────────
        # Priority descending (higher number first), then created_at ascending, then policy_id
        ordered_policies = sorted(
            active_policies,
            key=lambda p: (-(p.priority or 0), p.created_at or datetime.min.replace(tzinfo=timezone.utc), p.policy_id or "")
        )

        finding_sev_rank = SEVERITY_ORDER.get((finding.severity or "").upper(), -1)

        # ── 5. Evaluate Candidate Policies ────────────────────────────────────
        for policy in ordered_policies:
            # Match Provider
            if policy.allowed_providers and provider not in policy.allowed_providers:
                continue

            # Match Service
            if policy.allowed_services and finding.service not in policy.allowed_services:
                continue

            # Match Resource Type
            if policy.allowed_resource_types and finding.resource_type not in policy.allowed_resource_types:
                continue

            # Match Rule ID
            if policy.allowed_rule_ids and finding.rule_id not in policy.allowed_rule_ids:
                continue

            # Match Strategy (plan rule_id or action types)
            if policy.allowed_strategies and plan.rule_id not in policy.allowed_strategies:
                continue

            # Match Action Types (all actions in plan must be allowed if list specified)
            if policy.allowed_action_types:
                if not all(act.action_type in policy.allowed_action_types for act in plan.actions):
                    continue

            # Match Safety Levels (all actions in plan must be within allowed safety levels)
            if policy.allowed_safety_levels:
                if not all(act.safety in policy.allowed_safety_levels for act in plan.actions):
                    continue

            # Match Severity Bounds
            if policy.min_severity:
                min_rank = SEVERITY_ORDER.get(policy.min_severity.upper(), 0)
                if finding_sev_rank < min_rank:
                    continue

            if policy.max_severity:
                max_rank = SEVERITY_ORDER.get(policy.max_severity.upper(), 4)
                if finding_sev_rank > max_rank:
                    continue

            # Match Found!
            p_hash = compute_policy_hash(policy)
            context["matched_policy_id"] = policy.policy_id
            context["matched_policy_version"] = policy.version
            context["matched_policy_priority"] = policy.priority

            # Determine Transition Decision
            transition = (target_transition or "").upper()
            curr_state = plan.state

            if transition == "VALIDATE" or (not transition and curr_state == RemediationState.DRAFT.value):
                if policy.auto_progress_validation:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION,
                        reason=f"Plan matches policy '{policy.name}' and is eligible for automated validation.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )
                else:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.REQUIRE_HUMAN_REVIEW,
                        reason=f"Policy '{policy.name}' requires manual validation for this plan.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )

            if transition == "APPROVE" or (not transition and curr_state == RemediationState.PENDING_APPROVAL.value):
                if policy.require_human_approval or not policy.auto_progress_approval:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.REQUIRE_HUMAN_APPROVAL,
                        reason=f"Policy '{policy.name}' requires explicit human approval before execution.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )
                else:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION,
                        reason=f"Policy '{policy.name}' permits automated approval for low-risk actions.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )

            if transition == "EXECUTE" or (not transition and curr_state == RemediationState.APPROVED.value):
                if policy.auto_progress_execution:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION,
                        reason=f"Policy '{policy.name}' permits automated execution for approved low-risk actions.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )
                else:
                    return PolicyEvaluationResult(
                        decision=AutomationDecisionType.REQUIRE_HUMAN_REVIEW,
                        reason=f"Policy '{policy.name}' requires manual operator execution.",
                        matched_policy=policy,
                        policy_id=policy.policy_id,
                        policy_version=policy.version,
                        policy_hash=p_hash,
                        decision_context=context,
                    )

            # Default fallback for matched policy
            return PolicyEvaluationResult(
                decision=AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION,
                reason=f"Plan matches automation policy '{policy.name}'.",
                matched_policy=policy,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                policy_hash=p_hash,
                decision_context=context,
            )

        # No policy matched all criteria
        return PolicyEvaluationResult(
            decision=AutomationDecisionType.NOT_ELIGIBLE,
            reason="Plan does not satisfy the criteria of any active automation policy. Defaulting to fail-closed.",
            decision_context=context,
        )
