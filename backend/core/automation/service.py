"""
CloudGuard — Automation Orchestration Service (Phase 9)
Coordinates policy evaluation, automated workflow progression, emergency kill switch, and audit logging.
Strictly preserves:
- Phase 7 remediation state machine authority.
- Separation of duties.
- PostgreSQL row-level locking.
- Fail-closed security defaults.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from core.automation.audit import log_automation_event
from core.automation.exceptions import (
    AutomationBlockedError,
    AutomationError,
    KillSwitchActiveError,
    PolicyConflictError,
    PolicyNotFoundError,
)
from core.automation.models import (
    AutomationAuditEventType,
    AutomationDecisionType,
    ProgressionStatus,
)
from core.automation.policy_engine import PolicyEngine, PolicyEvaluationResult
from core.automation.schemas import (
    AutomationPolicyCreateRequest,
    AutomationPolicyUpdateRequest,
)
from core.db_models import (
    AutomationAuditEventDBModel,
    AutomationDecisionDBModel,
    AutomationPolicyDBModel,
    AutomationProgressionDBModel,
    AutomationSettingDBModel,
    FindingDBModel,
    RemediationPlanDBModel,
)
from core.remediation.state import RemediationState
from services.remediation_service import RemediationService


class AutomationService:
    def __init__(self, remediation_service: Optional[RemediationService] = None):
        self.remediation_service = remediation_service or RemediationService()

    # ── 1. Kill Switch Management ─────────────────────────────────────────────

    def is_kill_switch_active(self, session: Session) -> bool:
        """
        Returns True if emergency kill switch is active.
        Defaults to True (fail-closed) on any database read ambiguity or exception.
        """
        try:
            setting = session.scalar(
                select(AutomationSettingDBModel).where(
                    AutomationSettingDBModel.setting_key == "global_kill_switch"
                )
            )
            if not setting:
                return True
            val = setting.setting_value
            if isinstance(val, dict):
                return bool(val.get("enabled", False))
            return False
        except Exception:
            return True

    def get_kill_switch_status(self, session: Session) -> dict:
        setting = session.scalar(
            select(AutomationSettingDBModel).where(
                AutomationSettingDBModel.setting_key == "global_kill_switch"
            )
        )
        if not setting:
            return {"enabled": True, "updated_by": None, "updated_at": datetime.now(timezone.utc)}
        val = setting.setting_value if isinstance(setting.setting_value, dict) else {}
        return {
            "enabled": bool(val.get("enabled", False)),
            "updated_by": setting.updated_by,
            "updated_at": setting.updated_at,
        }

    def set_kill_switch(self, session: Session, enabled: bool, user_id: str, reason: str) -> dict:
        now = datetime.now(timezone.utc)
        setting = session.scalar(
            select(AutomationSettingDBModel).where(
                AutomationSettingDBModel.setting_key == "global_kill_switch"
            )
        )
        if not setting:
            setting = AutomationSettingDBModel(
                setting_key="global_kill_switch",
                setting_value={"enabled": enabled},
                updated_by=user_id,
                updated_at=now,
            )
            session.add(setting)
        else:
            setting.setting_value = {"enabled": enabled}
            setting.updated_by = user_id
            setting.updated_at = now

        ev_type = (
            AutomationAuditEventType.KILL_SWITCH_ENABLED.value
            if enabled
            else AutomationAuditEventType.KILL_SWITCH_DISABLED.value
        )
        log_automation_event(
            session=session,
            event_type=ev_type,
            actor_user_id=user_id,
            safe_details={"enabled": enabled, "reason": reason},
        )
        session.commit()
        session.refresh(setting)
        return {
            "enabled": enabled,
            "updated_by": user_id,
            "updated_at": setting.updated_at,
        }

    # ── 2. Policy CRUD ────────────────────────────────────────────────────────

    def create_policy(
        self, session: Session, req: AutomationPolicyCreateRequest, user_id: str
    ) -> AutomationPolicyDBModel:
        existing = session.scalar(
            select(AutomationPolicyDBModel).where(AutomationPolicyDBModel.name == req.name)
        )
        if existing:
            raise PolicyConflictError(f"An automation policy named '{req.name}' already exists.")

        now = datetime.now(timezone.utc)
        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name=req.name,
            description=req.description,
            enabled=req.enabled,
            priority=req.priority,
            version=1,
            allowed_providers=req.allowed_providers,
            allowed_services=req.allowed_services,
            allowed_resource_types=req.allowed_resource_types,
            allowed_rule_ids=req.allowed_rule_ids,
            allowed_strategies=req.allowed_strategies,
            allowed_action_types=req.allowed_action_types,
            allowed_safety_levels=req.allowed_safety_levels,
            min_severity=req.min_severity,
            max_severity=req.max_severity,
            auto_progress_validation=req.auto_progress_validation,
            auto_progress_approval=req.auto_progress_approval,
            auto_progress_execution=req.auto_progress_execution,
            require_human_approval=req.require_human_approval,
            created_by=user_id,
            updated_by=user_id,
            created_at=now,
            updated_at=now,
        )
        session.add(policy)
        log_automation_event(
            session=session,
            event_type=AutomationAuditEventType.POLICY_CREATED.value,
            actor_user_id=user_id,
            policy_id=policy.policy_id,
            safe_details={"name": policy.name, "priority": policy.priority, "enabled": policy.enabled},
        )
        session.commit()
        session.refresh(policy)
        return policy

    def get_policy(self, session: Session, policy_id: str) -> AutomationPolicyDBModel:
        policy = session.scalar(
            select(AutomationPolicyDBModel).where(AutomationPolicyDBModel.policy_id == policy_id)
        )
        if not policy:
            raise PolicyNotFoundError(policy_id)
        return policy

    def list_policies(self, session: Session, enabled_only: bool = False) -> List[AutomationPolicyDBModel]:
        stmt = select(AutomationPolicyDBModel)
        if enabled_only:
            stmt = stmt.where(AutomationPolicyDBModel.enabled == True)
        stmt = stmt.order_by(desc(AutomationPolicyDBModel.priority), AutomationPolicyDBModel.created_at.asc())
        return list(session.scalars(stmt).all())

    def update_policy(
        self, session: Session, policy_id: str, req: AutomationPolicyUpdateRequest, user_id: str
    ) -> AutomationPolicyDBModel:
        policy = self.get_policy(session, policy_id)

        if req.name and req.name != policy.name:
            dup = session.scalar(
                select(AutomationPolicyDBModel).where(AutomationPolicyDBModel.name == req.name)
            )
            if dup:
                raise PolicyConflictError(f"A policy named '{req.name}' already exists.")
            policy.name = req.name

        if req.description is not None:
            policy.description = req.description
        if req.enabled is not None:
            policy.enabled = req.enabled
        if req.priority is not None:
            policy.priority = req.priority

        if req.allowed_providers is not None:
            policy.allowed_providers = req.allowed_providers
        if req.allowed_services is not None:
            policy.allowed_services = req.allowed_services
        if req.allowed_resource_types is not None:
            policy.allowed_resource_types = req.allowed_resource_types
        if req.allowed_rule_ids is not None:
            policy.allowed_rule_ids = req.allowed_rule_ids
        if req.allowed_strategies is not None:
            policy.allowed_strategies = req.allowed_strategies
        if req.allowed_action_types is not None:
            policy.allowed_action_types = req.allowed_action_types
        if req.allowed_safety_levels is not None:
            policy.allowed_safety_levels = req.allowed_safety_levels

        if req.min_severity is not None:
            policy.min_severity = req.min_severity
        if req.max_severity is not None:
            policy.max_severity = req.max_severity

        if req.auto_progress_validation is not None:
            policy.auto_progress_validation = req.auto_progress_validation
        if req.auto_progress_approval is not None:
            policy.auto_progress_approval = req.auto_progress_approval
        if req.auto_progress_execution is not None:
            policy.auto_progress_execution = req.auto_progress_execution
        if req.require_human_approval is not None:
            policy.require_human_approval = req.require_human_approval

        policy.version += 1
        policy.updated_by = user_id
        policy.updated_at = datetime.now(timezone.utc)

        log_automation_event(
            session=session,
            event_type=AutomationAuditEventType.POLICY_UPDATED.value,
            actor_user_id=user_id,
            policy_id=policy.policy_id,
            safe_details={"name": policy.name, "version": policy.version, "enabled": policy.enabled},
        )
        session.commit()
        session.refresh(policy)
        return policy

    def delete_policy(self, session: Session, policy_id: str, user_id: str) -> None:
        policy = self.get_policy(session, policy_id)
        session.delete(policy)
        log_automation_event(
            session=session,
            event_type=AutomationAuditEventType.POLICY_DELETED.value,
            actor_user_id=user_id,
            policy_id=policy_id,
            safe_details={"name": policy.name},
        )
        session.commit()

    # ── 3. Evaluation ─────────────────────────────────────────────────────────

    def evaluate_remediation(
        self,
        session: Session,
        remediation_id: str,
        user_id: str,
        target_transition: Optional[str] = None,
    ) -> AutomationDecisionDBModel:
        plan = session.scalar(
            select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == remediation_id)
        )
        if not plan:
            raise ValueError(f"Remediation plan '{remediation_id}' not found.")

        finding = session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == plan.finding_id)
        )
        if not finding:
            raise ValueError(f"Finding '{plan.finding_id}' associated with plan does not exist.")

        kill_switch = self.is_kill_switch_active(session)
        policies = self.list_policies(session, enabled_only=True)

        eval_result = PolicyEngine.evaluate(
            finding=finding,
            plan=plan,
            policies=policies,
            kill_switch_active=kill_switch,
            target_transition=target_transition,
        )

        decision = AutomationDecisionDBModel(
            decision_id=str(uuid.uuid4()),
            remediation_id=remediation_id,
            policy_id=eval_result.policy_id,
            policy_version=eval_result.policy_version,
            policy_hash=eval_result.policy_hash,
            decision=eval_result.decision.value,
            reason=eval_result.reason,
            evaluated_by=user_id,
            evaluated_at=datetime.now(timezone.utc),
            decision_context=eval_result.decision_context,
        )
        session.add(decision)

        log_automation_event(
            session=session,
            event_type=AutomationAuditEventType.AUTOMATION_EVALUATED.value,
            actor_user_id=user_id,
            policy_id=eval_result.policy_id,
            remediation_id=remediation_id,
            safe_details={
                "decision": eval_result.decision.value,
                "reason": eval_result.reason,
                "policy_hash": eval_result.policy_hash,
            },
        )
        session.commit()
        session.refresh(decision)
        return decision

    # ── 4. Automated Progression ──────────────────────────────────────────────

    def progress_remediation(
        self,
        session: Session,
        remediation_id: str,
        user_id: str,
        target_transition: Optional[str] = None,
    ) -> AutomationProgressionDBModel:
        """
        Executes a policy-permitted automated transition on a Phase 7 remediation plan.
        Enforces:
        - PostgreSQL row-level locking via with_for_update().
        - Pre-transition policy re-evaluation under lock.
        - Strict adherence to Phase 7 state machine and separation of duties.
        """
        if self.is_kill_switch_active(session):
            raise KillSwitchActiveError()

        # 1. Lock remediation plan row
        db_plan = session.scalar(
            select(RemediationPlanDBModel)
            .where(RemediationPlanDBModel.remediation_id == remediation_id)
            .with_for_update()
        )
        if not db_plan:
            raise ValueError(f"Remediation plan '{remediation_id}' not found.")

        initial_state = db_plan.state

        # 2. Evaluate under lock
        finding = session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == db_plan.finding_id)
        )
        if not finding:
            raise ValueError(f"Finding '{db_plan.finding_id}' associated with plan not found.")

        policies = self.list_policies(session, enabled_only=True)
        eval_result = PolicyEngine.evaluate(
            finding=finding,
            plan=db_plan,
            policies=policies,
            kill_switch_active=False,
            target_transition=target_transition,
        )

        if eval_result.decision != AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION:
            raise AutomationBlockedError(
                f"Plan is not eligible for automated progression. Decision: {eval_result.decision.value}. Reason: {eval_result.reason}"
            )

        # Record decision snapshot
        decision = AutomationDecisionDBModel(
            decision_id=str(uuid.uuid4()),
            remediation_id=remediation_id,
            policy_id=eval_result.policy_id,
            policy_version=eval_result.policy_version,
            policy_hash=eval_result.policy_hash,
            decision=eval_result.decision.value,
            reason=eval_result.reason,
            evaluated_by=user_id,
            evaluated_at=datetime.now(timezone.utc),
            decision_context=eval_result.decision_context,
        )
        session.add(decision)
        session.flush()

        # Initialize progression record
        progression = AutomationProgressionDBModel(
            progression_id=str(uuid.uuid4()),
            remediation_id=remediation_id,
            decision_id=decision.decision_id,
            from_state=initial_state,
            to_state="UNKNOWN",
            status=ProgressionStatus.PROGRESSING.value,
            executed_by=user_id,
            started_at=datetime.now(timezone.utc),
        )
        session.add(progression)
        log_automation_event(
            session=session,
            event_type=AutomationAuditEventType.AUTOMATION_PROGRESSION_START.value,
            actor_user_id=user_id,
            remediation_id=remediation_id,
            policy_id=eval_result.policy_id,
            safe_details={"from_state": initial_state, "target_transition": target_transition},
        )
        session.commit()
        progression_id = progression.progression_id

        # 3. Delegate state transition to Phase 7 Remediation Engine
        try:
            transition = (target_transition or "").upper()

            if initial_state == RemediationState.DRAFT.value or transition == "VALIDATE":
                # Validate plan (transitions DRAFT -> PENDING_APPROVAL)
                self.remediation_service.validate_plan(session, remediation_id, user_id)

            elif initial_state == RemediationState.PENDING_APPROVAL.value or transition == "APPROVE":
                # Enforce Separation of Duties: plan creator cannot approve
                if db_plan.created_by == user_id:
                    raise PermissionError("Separation of duties: plan creator cannot approve their own plan via automation.")
                self.remediation_service.approve_plan(session, remediation_id, user_id)

            elif initial_state == RemediationState.APPROVED.value or transition == "EXECUTE":
                # Execute plan (transitions APPROVED -> EXECUTED or EXECUTION_FAILED)
                self.remediation_service.execute_plan(session, remediation_id, user_id)

            else:
                raise ValueError(f"No automated transition available from state '{initial_state}'.")

            # Reload plan state after Phase 7 operation
            session.refresh(db_plan)
            p_rec = session.scalar(
                select(AutomationProgressionDBModel).where(
                    AutomationProgressionDBModel.progression_id == progression_id
                )
            )
            p_rec.to_state = db_plan.state
            p_rec.status = ProgressionStatus.SUCCESS.value
            p_rec.completed_at = datetime.now(timezone.utc)

            log_automation_event(
                session=session,
                event_type=AutomationAuditEventType.AUTOMATION_PROGRESSION_DONE.value,
                actor_user_id=user_id,
                remediation_id=remediation_id,
                policy_id=eval_result.policy_id,
                safe_details={
                    "from_state": initial_state,
                    "to_state": db_plan.state,
                    "status": "SUCCESS",
                },
            )
            session.commit()
            session.refresh(p_rec)
            return p_rec

        except Exception as exc:
            session.rollback()
            fail_progression = session.scalar(
                select(AutomationProgressionDBModel).where(
                    AutomationProgressionDBModel.progression_id == progression_id
                )
            )
            if fail_progression:
                fail_progression.status = ProgressionStatus.FAILED.value
                fail_progression.error_message = str(exc)
                fail_progression.completed_at = datetime.now(timezone.utc)
            else:
                fail_progression = AutomationProgressionDBModel(
                    progression_id=progression_id,
                    remediation_id=remediation_id,
                    decision_id=decision.decision_id,
                    from_state=initial_state,
                    to_state="FAILED",
                    status=ProgressionStatus.FAILED.value,
                    error_message=str(exc),
                    executed_by=user_id,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                )
                session.add(fail_progression)

            log_automation_event(
                session=session,
                event_type=AutomationAuditEventType.AUTOMATION_PROGRESSION_FAIL.value,
                actor_user_id=user_id,
                remediation_id=remediation_id,
                policy_id=eval_result.policy_id,
                safe_details={"from_state": initial_state, "error": str(exc)},
            )
            session.commit()
            session.refresh(fail_progression)
            if isinstance(exc, (PermissionError, KillSwitchActiveError, AutomationBlockedError)):
                raise exc
            raise AutomationError(f"Automated progression failed: {exc}")

    # ── 5. Decisions & Audit Queries ──────────────────────────────────────────

    def get_decision(self, session: Session, decision_id: str) -> AutomationDecisionDBModel:
        decision = session.scalar(
            select(AutomationDecisionDBModel).where(
                AutomationDecisionDBModel.decision_id == decision_id
            )
        )
        if not decision:
            raise ValueError(f"Automation decision '{decision_id}' not found.")
        return decision

    def list_decisions(
        self, session: Session, remediation_id: Optional[str] = None
    ) -> List[AutomationDecisionDBModel]:
        stmt = select(AutomationDecisionDBModel)
        if remediation_id:
            stmt = stmt.where(AutomationDecisionDBModel.remediation_id == remediation_id)
        stmt = stmt.order_by(desc(AutomationDecisionDBModel.evaluated_at))
        return list(session.scalars(stmt).all())

    def list_audit_events(
        self,
        session: Session,
        remediation_id: Optional[str] = None,
        policy_id: Optional[str] = None,
    ) -> List[AutomationAuditEventDBModel]:
        stmt = select(AutomationAuditEventDBModel)
        if remediation_id:
            stmt = stmt.where(AutomationAuditEventDBModel.remediation_id == remediation_id)
        if policy_id:
            stmt = stmt.where(AutomationAuditEventDBModel.policy_id == policy_id)
        stmt = stmt.order_by(desc(AutomationAuditEventDBModel.sequence_number))
        return list(session.scalars(stmt).all())
