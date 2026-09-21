"""
CloudGuard — Automation Domain Models & Enums (Phase 9)
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AutomationDecisionType(str, Enum):
    """
    Deterministic decisions produced by the Policy Engine.
    """
    ELIGIBLE_FOR_AUTOMATION     = "ELIGIBLE_FOR_AUTOMATION"
    REQUIRE_HUMAN_REVIEW        = "REQUIRE_HUMAN_REVIEW"
    REQUIRE_HUMAN_APPROVAL      = "REQUIRE_HUMAN_APPROVAL"
    BLOCKED_BY_KILL_SWITCH      = "BLOCKED_BY_KILL_SWITCH"
    BLOCKED_BY_SAFETY           = "BLOCKED_BY_SAFETY"
    NOT_ELIGIBLE                = "NOT_ELIGIBLE"


class ProgressionStatus(str, Enum):
    PROGRESSING = "PROGRESSING"
    SUCCESS     = "SUCCESS"
    FAILED      = "FAILED"


class AutomationAuditEventType(str, Enum):
    POLICY_CREATED               = "POLICY_CREATED"
    POLICY_UPDATED               = "POLICY_UPDATED"
    POLICY_DELETED               = "POLICY_DELETED"
    POLICY_ENABLED               = "POLICY_ENABLED"
    POLICY_DISABLED              = "POLICY_DISABLED"
    KILL_SWITCH_ENABLED          = "KILL_SWITCH_ENABLED"
    KILL_SWITCH_DISABLED         = "KILL_SWITCH_DISABLED"
    AUTOMATION_EVALUATED         = "AUTOMATION_EVALUATED"
    AUTOMATION_PROGRESSION_START = "AUTOMATION_PROGRESSION_START"
    AUTOMATION_PROGRESSION_DONE  = "AUTOMATION_PROGRESSION_DONE"
    AUTOMATION_PROGRESSION_FAIL  = "AUTOMATION_PROGRESSION_FAIL"
    AUTOMATION_BLOCKED           = "AUTOMATION_BLOCKED"


class AutomationPolicyModel(BaseModel):
    policy_id: str
    name: str
    description: str
    enabled: bool = False
    priority: int = 50
    version: int = 1

    allowed_providers: List[str] = Field(default_factory=list)
    allowed_services: List[str] = Field(default_factory=list)
    allowed_resource_types: List[str] = Field(default_factory=list)
    allowed_rule_ids: List[str] = Field(default_factory=list)
    allowed_strategies: List[str] = Field(default_factory=list)
    allowed_action_types: List[str] = Field(default_factory=list)
    allowed_safety_levels: List[str] = Field(default_factory=list)

    min_severity: Optional[str] = None
    max_severity: Optional[str] = None

    auto_progress_validation: bool = True
    auto_progress_approval: bool = False
    auto_progress_execution: bool = False
    require_human_approval: bool = True

    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class AutomationDecisionModel(BaseModel):
    decision_id: str
    remediation_id: str
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    policy_hash: Optional[str] = None
    decision: AutomationDecisionType
    reason: str
    evaluated_by: str
    evaluated_at: datetime
    decision_context: Dict[str, Any] = Field(default_factory=dict)


class AutomationProgressionModel(BaseModel):
    progression_id: str
    remediation_id: str
    decision_id: str
    from_state: str
    to_state: str
    status: ProgressionStatus
    error_message: Optional[str] = None
    executed_by: str
    started_at: datetime
    completed_at: Optional[datetime] = None


class AutomationAuditEventModel(BaseModel):
    event_id: str
    event_type: str
    actor_user_id: Optional[str] = None
    policy_id: Optional[str] = None
    remediation_id: Optional[str] = None
    timestamp: datetime
    safe_details: Dict[str, Any] = Field(default_factory=dict)
    sequence_number: int = 1
    previous_event_hash: Optional[str] = None
    event_hash: str
