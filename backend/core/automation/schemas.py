"""
CloudGuard — Automation Schemas & API Request/Response Models (Phase 9)
Enforces strict validation and ConfigDict(extra="forbid") across all inputs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from core.automation.models import AutomationDecisionType, ProgressionStatus


class AutomationPolicyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=5, max_length=1000)
    enabled: bool = Field(default=False)
    priority: int = Field(default=50, ge=1, le=1000)

    allowed_providers: List[str] = Field(default_factory=list)
    allowed_services: List[str] = Field(default_factory=list)
    allowed_resource_types: List[str] = Field(default_factory=list)
    allowed_rule_ids: List[str] = Field(default_factory=list)
    allowed_strategies: List[str] = Field(default_factory=list)
    allowed_action_types: List[str] = Field(default_factory=list)
    allowed_safety_levels: List[str] = Field(default_factory=list)

    min_severity: Optional[str] = Field(default=None, max_length=20)
    max_severity: Optional[str] = Field(default=None, max_length=20)

    auto_progress_validation: bool = Field(default=True)
    auto_progress_approval: bool = Field(default=False)
    auto_progress_execution: bool = Field(default=False)
    require_human_approval: bool = Field(default=True)


class AutomationPolicyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, min_length=5, max_length=1000)
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(default=None, ge=1, le=1000)

    allowed_providers: Optional[List[str]] = None
    allowed_services: Optional[List[str]] = None
    allowed_resource_types: Optional[List[str]] = None
    allowed_rule_ids: Optional[List[str]] = None
    allowed_strategies: Optional[List[str]] = None
    allowed_action_types: Optional[List[str]] = None
    allowed_safety_levels: Optional[List[str]] = None

    min_severity: Optional[str] = Field(default=None, max_length=20)
    max_severity: Optional[str] = Field(default=None, max_length=20)

    auto_progress_validation: Optional[bool] = None
    auto_progress_approval: Optional[bool] = None
    auto_progress_execution: Optional[bool] = None
    require_human_approval: Optional[bool] = None


class AutomationPolicyResponse(BaseModel):
    policy_id: str
    name: str
    description: str
    enabled: bool
    priority: int
    version: int

    allowed_providers: List[str]
    allowed_services: List[str]
    allowed_resource_types: List[str]
    allowed_rule_ids: List[str]
    allowed_strategies: List[str]
    allowed_action_types: List[str]
    allowed_safety_levels: List[str]

    min_severity: Optional[str] = None
    max_severity: Optional[str] = None

    auto_progress_validation: bool
    auto_progress_approval: bool
    auto_progress_execution: bool
    require_human_approval: bool

    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class AutomationEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(..., min_length=36, max_length=36)


class AutomationDecisionResponse(BaseModel):
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


class AutomationProgressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_transition: Optional[str] = Field(default=None, description="Optional transition hint, e.g. 'VALIDATE', 'APPROVE', 'EXECUTE'")


class AutomationProgressionResponse(BaseModel):
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


class KillSwitchStatusResponse(BaseModel):
    enabled: bool
    updated_by: Optional[str] = None
    updated_at: datetime


class KillSwitchToggleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=3, max_length=255)


class AutomationAuditEventResponse(BaseModel):
    event_id: str
    event_type: str
    actor_user_id: Optional[str] = None
    policy_id: Optional[str] = None
    remediation_id: Optional[str] = None
    timestamp: datetime
    safe_details: Dict[str, Any]
    sequence_number: int
    previous_event_hash: Optional[str] = None
    event_hash: str
