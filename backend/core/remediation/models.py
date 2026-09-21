"""
CloudGuard — Remediation Domain Models
"""
from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import uuid

from core.remediation.state import RemediationState, RemediationSafety


class RemediationAction(BaseModel):
    """
    A single deterministically generated action to remediate a finding.
    """
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str = Field(description="Explicit allowlisted action type, e.g., 'ENABLE_S3_PUBLIC_ACCESS_BLOCK'")
    provider: str = Field(description="Target provider, e.g., 'aws' or 'demo'")
    service: str = Field(description="Target service, e.g., 's3'")
    resource_identifier: str = Field(description="Target resource ARN or ID")
    description: str
    safety: RemediationSafety
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Strictly validated schema of arguments")


class RemediationPlan(BaseModel):
    """
    A proposed remediation for a finding.
    """
    remediation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    scan_id: str
    resource_id: str
    rule_id: str
    
    state: RemediationState = Field(default=RemediationState.DRAFT)
    
    title: str
    description: str
    
    proposed_actions: List[RemediationAction] = Field(default_factory=list)
    
    validation_result: Optional[str] = None
    error_message: Optional[str] = None
    
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    execution_started_at: Optional[datetime] = None
    execution_completed_at: Optional[datetime] = None


class RemediationExecutionResult(BaseModel):
    """
    Result of an individual action execution.
    """
    action_id: str
    success: bool
    error_message: Optional[str] = None
    safe_details: Dict[str, Any] = Field(default_factory=dict)


class RemediationVerificationResult(BaseModel):
    """
    Independent verification result after execution.
    """
    remediation_id: str
    is_fixed: bool
    details: str


class RemediationAuditEvent(BaseModel):
    """
    Append-only audit event record.
    """
    event_id: str
    remediation_id: str
    execution_id: Optional[str] = None
    event_type: str
    actor_user_id: Optional[str] = None
    timestamp: datetime
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    request_id: Optional[str] = None
    safe_details: Dict[str, Any] = Field(default_factory=dict)
    sequence_number: int = Field(default=1)
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

    model_config = {"from_attributes": True}
