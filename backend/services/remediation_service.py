"""
CloudGuard — Remediation Service
"""
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select

_remediation_lock = threading.Lock()

from core.remediation.models import RemediationPlan, RemediationAction, RemediationAuditEvent
from core.remediation.state import RemediationState, is_valid_transition, RemediationSafety
from core.remediation.strategy import get_strategy, RemediationStrategyContext
from core.remediation.audit import log_remediation_event, verify_audit_chain
from core.db_models import (
    RemediationPlanDBModel, RemediationActionDBModel,
    RemediationExecutionDBModel, RemediationAuditEventDBModel, FindingDBModel
)
from core.security.models import FindingStatus
from core.providers.demo.remediation import DemoRemediationProvider
from core.providers.aws.remediation import AWSRemediationProvider


class RemediationService:
    def __init__(self):
        self._providers = {
            "demo": DemoRemediationProvider(),
            # AWS provider would be initialized with credentials from config in production
        }

    def _get_provider(self, name: str):
        if name == "aws":
            if "aws" not in self._providers:
                from config.settings import settings
                from core.providers.aws.provider import AWSProvider
                aws_prov = AWSProvider(
                    region=settings.aws_default_region,
                    profile=settings.aws_profile,
                    access_key_id=settings.aws_access_key_id,
                    secret_access_key=settings.aws_secret_access_key,
                    role_arn=settings.aws_role_arn,
                    role_session_name=settings.aws_role_session_name,
                    external_id=settings.aws_external_id,
                )
                self._providers["aws"] = AWSRemediationProvider(session=aws_prov._get_session())
            return self._providers["aws"]

        provider = self._providers.get(name)
        if not provider:
            raise ValueError(f"Unknown remediation provider: {name}.")
        return provider

    def _determine_provider(self, account_id: str) -> str:
        """Determine provider based on account context."""
        # Demo account IDs from the demo provider fixtures
        if account_id in ("123456789012", "demo", "demo-account-id"):
            return "demo"
        return "aws"

    def create_plan(
        self, session: Session, finding_id: str, user_id: str
    ) -> RemediationPlan:
        """Create a new deterministic remediation plan for a finding."""
        with _remediation_lock:
            finding_model = session.scalar(
                select(FindingDBModel)
                .where(FindingDBModel.finding_id == finding_id)
                .with_for_update()
            )
            if not finding_model:
                raise ValueError(f"Finding {finding_id} not found.")

            # Check for existing active plan for this finding
            active_plan = session.scalar(
                select(RemediationPlanDBModel)
                .where(RemediationPlanDBModel.finding_id == finding_id)
                .where(RemediationPlanDBModel.state.in_([
                    RemediationState.DRAFT.value,
                    RemediationState.VALIDATED.value,
                    RemediationState.PENDING_APPROVAL.value,
                    RemediationState.APPROVED.value,
                    RemediationState.EXECUTING.value,
                ]))
            )
            if active_plan:
                raise ValueError(
                    f"An active remediation plan (id={active_plan.remediation_id}) "
                    f"already exists for finding {finding_id}."
                )

            strategy = get_strategy(finding_model.rule_id)
            if not strategy:
                raise ValueError(
                    f"No supported remediation strategy for rule '{finding_model.rule_id}'. "
                    f"Only explicitly allowlisted rules can be remediated."
                )

            if strategy.safety == RemediationSafety.DESTRUCTIVE:
                raise ValueError("DESTRUCTIVE actions are strictly blocked and cannot be executed.")

            # Determine provider from account context
            provider_name = self._determine_provider(finding_model.account_id)

            # Build context for strategy
            ctx = RemediationStrategyContext(
                rule_id=finding_model.rule_id,
                resource_id=finding_model.resource_id,
                resource_type=finding_model.resource_type,
                service=finding_model.service,
                account_id=finding_model.account_id,
                region=finding_model.region,
                provider_name=provider_name,
            )

            actions = strategy.generate_actions(ctx)

            plan_id = str(uuid.uuid4())

            db_plan = RemediationPlanDBModel(
                remediation_id=plan_id,
                finding_id=finding_id,
                scan_id=finding_model.scan_id,
                resource_id=finding_model.resource_id,
                rule_id=finding_model.rule_id,
                state=RemediationState.DRAFT.value,
                title=f"Remediate: {finding_model.title}",
                description=f"Deterministic remediation plan for rule '{finding_model.rule_id}'.",
                created_by=user_id,
            )

            for act in actions:
                db_plan.actions.append(RemediationActionDBModel(
                    action_id=act.action_id,
                    action_type=act.action_type,
                    provider=act.provider,
                    service=act.service,
                    resource_identifier=act.resource_identifier,
                    description=act.description,
                    safety=act.safety.value,
                    parameters=act.parameters,
                ))

            session.add(db_plan)
            session.flush()

            log_remediation_event(
                session=session,
                remediation_id=plan_id,
                event_type="PLAN_CREATED",
                actor_user_id=user_id,
                new_state=RemediationState.DRAFT.value,
            )
            session.commit()
            return self.get_plan(session, plan_id)

    def get_plan(self, session: Session, remediation_id: str) -> RemediationPlan:
        """Load a plan from the DB and return as a Pydantic model."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        actions = [
            RemediationAction(
                action_id=a.action_id,
                action_type=a.action_type,
                provider=a.provider,
                service=a.service,
                resource_identifier=a.resource_identifier,
                description=a.description,
                safety=RemediationSafety(a.safety),
                parameters=a.parameters,
            )
            for a in db_plan.actions
        ]

        return RemediationPlan(
            remediation_id=db_plan.remediation_id,
            finding_id=db_plan.finding_id,
            scan_id=db_plan.scan_id,
            resource_id=db_plan.resource_id,
            rule_id=db_plan.rule_id,
            state=RemediationState(db_plan.state),
            title=db_plan.title,
            description=db_plan.description,
            proposed_actions=actions,
            validation_result=db_plan.validation_result,
            error_message=db_plan.error_message,
            created_by=db_plan.created_by,
            created_at=db_plan.created_at,
            updated_at=db_plan.updated_at,
            approved_by=db_plan.approved_by,
            approved_at=db_plan.approved_at,
            execution_started_at=db_plan.execution_started_at,
            execution_completed_at=db_plan.execution_completed_at,
        )

    def list_plans(
        self, session: Session, limit: int = 50, offset: int = 0, state: Optional[str] = None
    ) -> List[RemediationPlan]:
        """List remediation plans with optional filtering and pagination."""
        query = select(RemediationPlanDBModel).order_by(RemediationPlanDBModel.created_at.desc())
        if state:
            query = query.where(RemediationPlanDBModel.state == state)
        query = query.offset(offset).limit(limit)
        db_plans = session.scalars(query).all()
        results = []
        for db_plan in db_plans:
            actions = [
                RemediationAction(
                    action_id=a.action_id,
                    action_type=a.action_type,
                    provider=a.provider,
                    service=a.service,
                    resource_identifier=a.resource_identifier,
                    description=a.description,
                    safety=RemediationSafety(a.safety),
                    parameters=a.parameters,
                )
                for a in db_plan.actions
            ]
            results.append(
                RemediationPlan(
                    remediation_id=db_plan.remediation_id,
                    finding_id=db_plan.finding_id,
                    scan_id=db_plan.scan_id,
                    resource_id=db_plan.resource_id,
                    rule_id=db_plan.rule_id,
                    state=RemediationState(db_plan.state),
                    title=db_plan.title,
                    description=db_plan.description,
                    proposed_actions=actions,
                    validation_result=db_plan.validation_result,
                    error_message=db_plan.error_message,
                    created_by=db_plan.created_by,
                    created_at=db_plan.created_at,
                    updated_at=db_plan.updated_at,
                    approved_by=db_plan.approved_by,
                    approved_at=db_plan.approved_at,
                    execution_started_at=db_plan.execution_started_at,
                    execution_completed_at=db_plan.execution_completed_at,
                )
            )
        return results

    def validate_plan(self, session: Session, remediation_id: str, user_id: str) -> RemediationPlan:
        """Validate actions and transition DRAFT → PENDING_APPROVAL."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        current_state = RemediationState(db_plan.state)

        # We validate to PENDING_APPROVAL directly
        if not is_valid_transition(current_state, RemediationState.VALIDATED):
            raise ValueError(
                f"Cannot validate plan in state '{current_state.value}'. "
                f"Plan must be in DRAFT state."
            )

        # Validate resource binding: finding must still exist and match
        finding_model = session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == db_plan.finding_id)
        )
        if not finding_model:
            db_plan.state = RemediationState.CANCELLED.value
            db_plan.validation_result = "INVALID: Original finding no longer exists."
            session.commit()
            raise ValueError("Validation failed: original finding no longer exists.")

        if finding_model.resource_id != db_plan.resource_id:
            db_plan.state = RemediationState.CANCELLED.value
            db_plan.validation_result = "INVALID: Resource ID mismatch."
            session.commit()
            raise ValueError("Validation failed: resource binding mismatch.")

        # Validate each action against its provider
        for db_action in db_plan.actions:
            provider = self._get_provider(db_action.provider)
            act = RemediationAction(
                action_id=db_action.action_id,
                action_type=db_action.action_type,
                provider=db_action.provider,
                service=db_action.service,
                resource_identifier=db_action.resource_identifier,
                description=db_action.description,
                safety=RemediationSafety(db_action.safety),
                parameters=db_action.parameters,
            )
            try:
                provider.validate_action(act)
            except ValueError as e:
                db_plan.state = RemediationState.DRAFT.value
                db_plan.validation_result = f"INVALID: {e}"
                session.commit()
                raise ValueError(f"Validation failed: {e}")

            if act.safety == RemediationSafety.DESTRUCTIVE:
                raise ValueError("DESTRUCTIVE action blocked during validation.")

        # Transition through VALIDATED → PENDING_APPROVAL
        db_plan.state = RemediationState.PENDING_APPROVAL.value
        db_plan.validation_result = "VALID"

        log_remediation_event(
            session=session,
            remediation_id=remediation_id,
            event_type="PLAN_VALIDATED",
            actor_user_id=user_id,
            previous_state=current_state.value,
            new_state=RemediationState.PENDING_APPROVAL.value,
        )
        session.commit()
        return self.get_plan(session, remediation_id)

    def approve_plan(self, session: Session, remediation_id: str, user_id: str) -> RemediationPlan:
        """Approve a PENDING_APPROVAL plan. Enforces separation of duties."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        # Separation of duties: creator cannot approve their own plan unless holding ADMIN authority
        if db_plan.created_by == user_id:
            from auth.models import UserDBModel
            user = session.scalar(select(UserDBModel).where(UserDBModel.user_id == user_id))
            if not (user and user.role and user.role.name == "ADMIN"):
                raise PermissionError(
                    "Separation of duties: the creator of a remediation plan cannot approve it."
                )

        current_state = RemediationState(db_plan.state)
        target_state = RemediationState.APPROVED

        if not is_valid_transition(current_state, target_state):
            raise ValueError(
                f"Cannot approve plan in state '{current_state.value}'. "
                f"Plan must be in PENDING_APPROVAL state."
            )

        db_plan.state = target_state.value
        db_plan.approved_by = user_id
        db_plan.approved_at = datetime.now(timezone.utc)

        log_remediation_event(
            session=session,
            remediation_id=remediation_id,
            event_type="PLAN_APPROVED",
            actor_user_id=user_id,
            previous_state=current_state.value,
            new_state=target_state.value,
        )
        session.commit()
        return self.get_plan(session, remediation_id)

    def reject_plan(self, session: Session, remediation_id: str, user_id: str, reason: str = "") -> RemediationPlan:
        """Reject a PENDING_APPROVAL plan."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        current_state = RemediationState(db_plan.state)
        target_state = RemediationState.REJECTED

        if not is_valid_transition(current_state, target_state):
            raise ValueError(
                f"Cannot reject plan in state '{current_state.value}'. "
                f"Plan must be in PENDING_APPROVAL state."
            )

        db_plan.state = target_state.value
        db_plan.error_message = reason or "Plan rejected by approver."

        log_remediation_event(
            session=session,
            remediation_id=remediation_id,
            event_type="PLAN_REJECTED",
            actor_user_id=user_id,
            previous_state=current_state.value,
            new_state=target_state.value,
            safe_details={"reason": reason} if reason else {},
        )
        session.commit()
        return self.get_plan(session, remediation_id)

    def cancel_plan(self, session: Session, remediation_id: str, user_id: str, reason: str = "") -> RemediationPlan:
        """Cancel a plan in DRAFT, VALIDATED, PENDING_APPROVAL, or APPROVED state."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        current_state = RemediationState(db_plan.state)
        target_state = RemediationState.CANCELLED

        if not is_valid_transition(current_state, target_state):
            raise ValueError(
                f"Cannot cancel plan in state '{current_state.value}'."
            )

        db_plan.state = target_state.value
        db_plan.error_message = reason or "Plan cancelled."

        log_remediation_event(
            session=session,
            remediation_id=remediation_id,
            event_type="PLAN_CANCELLED",
            actor_user_id=user_id,
            previous_state=current_state.value,
            new_state=target_state.value,
            safe_details={"reason": reason} if reason else {},
        )
        session.commit()
        return self.get_plan(session, remediation_id)

    def execute_plan(self, session: Session, remediation_id: str, user_id: str) -> RemediationPlan:
        """
        Execute an APPROVED plan with row-level locking to prevent race conditions.
        Uses with_for_update() to atomically claim the APPROVED state.
        """
        with _remediation_lock:
            # Lock the row to prevent concurrent execution
            db_plan = session.scalar(
                select(RemediationPlanDBModel)
                .where(RemediationPlanDBModel.remediation_id == remediation_id)
                .with_for_update()
            )
            if not db_plan:
                raise ValueError(f"Plan {remediation_id} not found.")

            current_state = RemediationState(db_plan.state)
            if not is_valid_transition(current_state, RemediationState.EXECUTING):
                raise ValueError(
                    f"Cannot execute plan in state '{current_state.value}'. "
                    f"Plan must be in APPROVED state."
                )

            # Atomically transition to EXECUTING
            db_plan.state = RemediationState.EXECUTING.value
            db_plan.execution_started_at = datetime.now(timezone.utc)

            execution = RemediationExecutionDBModel(
                remediation_id=remediation_id,
                status="EXECUTING",
                started_at=datetime.now(timezone.utc),
            )
            session.add(execution)
            session.commit()  # Commit the lock before executing

            # Execute each action
            success = True
            error_msgs = []

            for db_action in db_plan.actions:
                provider = self._get_provider(db_action.provider)
                act = RemediationAction(
                    action_id=db_action.action_id,
                    action_type=db_action.action_type,
                    provider=db_action.provider,
                    service=db_action.service,
                    resource_identifier=db_action.resource_identifier,
                    description=db_action.description,
                    safety=RemediationSafety(db_action.safety),
                    parameters=db_action.parameters,
                )
                try:
                    result = provider.execute_action(act)
                    if not result.success:
                        success = False
                        error_msgs.append(result.error_message or "Unknown execution error")
                        break
                except Exception as e:
                    success = False
                    error_msgs.append(str(e))
                    break

            # Update final state
            session.refresh(db_plan)
            session.refresh(execution)

            if success:
                db_plan.state = RemediationState.EXECUTED.value
                execution.status = "SUCCESS"
                # Update finding status
                finding = session.scalar(
                    select(FindingDBModel).where(FindingDBModel.finding_id == db_plan.finding_id)
                )
                if finding:
                    finding.status = FindingStatus.VERIFICATION_PENDING.value
            else:
                db_plan.state = RemediationState.EXECUTION_FAILED.value
                execution.status = "FAILED"
                execution.error_message = "; ".join(error_msgs)

            execution.completed_at = datetime.now(timezone.utc)
            db_plan.execution_completed_at = datetime.now(timezone.utc)

            log_remediation_event(
                session=session,
                remediation_id=remediation_id,
                event_type="EXECUTION_COMPLETED",
                actor_user_id=user_id,
                execution_id=execution.execution_id,
                previous_state=RemediationState.EXECUTING.value,
                new_state=db_plan.state,
            )
            session.commit()
            return self.get_plan(session, remediation_id)

    def verify_plan(self, session: Session, remediation_id: str, user_id: str) -> RemediationPlan:
        """
        Independently verify that the remediation actually fixed the finding
        by querying provider state (not reusing execution result).
        """
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        current_state = RemediationState(db_plan.state)
        if not is_valid_transition(current_state, RemediationState.VERIFYING):
            raise ValueError(
                f"Cannot verify plan in state '{current_state.value}'. "
                f"Plan must be in EXECUTED state."
            )

        db_plan.state = RemediationState.VERIFYING.value
        session.commit()

        is_fixed = True

        for db_action in db_plan.actions:
            provider = self._get_provider(db_action.provider)
            act = RemediationAction(
                action_id=db_action.action_id,
                action_type=db_action.action_type,
                provider=db_action.provider,
                service=db_action.service,
                resource_identifier=db_action.resource_identifier,
                description=db_action.description,
                safety=RemediationSafety(db_action.safety),
                parameters=db_action.parameters,
            )
            try:
                result = provider.verify_action(act)
                if not result.is_fixed:
                    is_fixed = False
                    break
            except Exception:
                is_fixed = False
                break

        session.refresh(db_plan)
        finding = session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == db_plan.finding_id)
        )

        if is_fixed:
            db_plan.state = RemediationState.VERIFIED_FIXED.value
            if finding:
                finding.status = FindingStatus.RESOLVED.value
        else:
            db_plan.state = RemediationState.VERIFICATION_FAILED.value
            if finding:
                finding.status = FindingStatus.STILL_VULNERABLE.value

        log_remediation_event(
            session=session,
            remediation_id=remediation_id,
            event_type="VERIFICATION_COMPLETED",
            actor_user_id=user_id,
            previous_state=RemediationState.VERIFYING.value,
            new_state=db_plan.state,
        )
        session.commit()
        return self.get_plan(session, remediation_id)

    def get_audit_events(self, session: Session, remediation_id: str) -> List[RemediationAuditEvent]:
        """Fetch immutable audit events for a remediation plan."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")

        events = session.scalars(
            select(RemediationAuditEventDBModel)
            .where(RemediationAuditEventDBModel.remediation_id == remediation_id)
            .order_by(
                RemediationAuditEventDBModel.sequence_number.asc(),
                RemediationAuditEventDBModel.timestamp.asc()
            )
        ).all()

        return [
            RemediationAuditEvent(
                event_id=e.event_id,
                remediation_id=e.remediation_id,
                execution_id=e.execution_id,
                event_type=e.event_type,
                actor_user_id=e.actor_user_id,
                timestamp=e.timestamp,
                previous_state=e.previous_state,
                new_state=e.new_state,
                request_id=e.request_id,
                safe_details=e.safe_details or {},
                sequence_number=e.sequence_number,
                previous_event_hash=e.previous_event_hash,
                event_hash=e.event_hash,
            )
            for e in events
        ]

    def verify_audit_chain(self, session: Session, remediation_id: str) -> Dict[str, Any]:
        """Verify the cryptographic hash chain and sequence integrity of audit events for a plan."""
        db_plan = session.scalar(
            select(RemediationPlanDBModel).where(
                RemediationPlanDBModel.remediation_id == remediation_id
            )
        )
        if not db_plan:
            raise ValueError(f"Plan {remediation_id} not found.")
        return verify_audit_chain(session, remediation_id)

