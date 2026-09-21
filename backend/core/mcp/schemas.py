"""
CloudGuard — MCP Pydantic Schemas (Phase 10)
Strict schemas with extra='forbid' to reject any extraneous fields.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class StrictInputModel(BaseModel):
    """Base model that forbids extraneous fields for strict input validation."""
    model_config = ConfigDict(extra="forbid", strict=True)


# ── Discovery Tool Inputs ─────────────────────────────────────────────────────

class ListCloudAccountsInput(StrictInputModel):
    provider: Optional[str] = Field(default=None, description="Filter by cloud provider (e.g. 'aws', 'demo').")


class ListResourcesInput(StrictInputModel):
    service: Optional[str] = Field(default=None, description="AWS service filter (e.g. 's3', 'iam', 'ec2').")
    resource_type: Optional[str] = Field(default=None, description="Resource type filter.")
    limit: int = Field(default=50, ge=1, le=100, description="Pagination limit (max 100).")
    offset: int = Field(default=0, ge=0, description="Pagination offset.")


class GetResourceInput(StrictInputModel):
    resource_id: str = Field(min_length=1, max_length=512, description="Target resource identifier or ARN.")


class GetResourceRelationshipsInput(StrictInputModel):
    resource_id: str = Field(min_length=1, max_length=512, description="Target resource identifier or ARN.")


class GetResourceSnapshotInput(StrictInputModel):
    resource_id: str = Field(min_length=1, max_length=512, description="Target resource identifier or ARN.")


class GetScanInput(StrictInputModel):
    scan_id: str = Field(min_length=1, max_length=64, description="Scan identifier.")


class GetScanStatusInput(StrictInputModel):
    scan_id: str = Field(min_length=1, max_length=64, description="Scan identifier.")


# ── Security Tool Inputs ──────────────────────────────────────────────────────

class ListFindingsInput(StrictInputModel):
    scan_id: Optional[str] = Field(default=None, description="Filter findings by scan ID.")
    severity: Optional[str] = Field(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL).")
    status: Optional[str] = Field(default=None, description="Filter by status (OPEN, RESOLVED, SUPPRESSED).")
    limit: int = Field(default=50, ge=1, le=100, description="Pagination limit (max 100).")
    offset: int = Field(default=0, ge=0, description="Pagination offset.")


class GetFindingInput(StrictInputModel):
    finding_id: str = Field(min_length=1, max_length=64, description="Unique finding ID.")


class GetFindingHistoryInput(StrictInputModel):
    canonical_id: str = Field(min_length=1, max_length=128, description="Canonical identity of the finding.")


class ListRulesInput(StrictInputModel):
    service: Optional[str] = Field(default=None, description="Filter rules by service.")
    severity: Optional[str] = Field(default=None, description="Filter rules by severity.")


class GetRuleInput(StrictInputModel):
    rule_id: str = Field(min_length=1, max_length=64, description="Security rule ID (e.g. 'S3-001').")


class GetRiskContextInput(StrictInputModel):
    resource_id: str = Field(min_length=1, max_length=512, description="Resource ID or ARN to compute risk context for.")


class GetPostureInput(StrictInputModel):
    scan_id: Optional[str] = Field(default=None, description="Scan ID to compute security posture for.")


class GetInvestigationContextInput(StrictInputModel):
    finding_id: str = Field(min_length=1, max_length=64, description="Finding ID to investigate.")


# ── Remediation Tool Inputs ───────────────────────────────────────────────────

class GetAllowedStrategiesInput(StrictInputModel):
    rule_id: str = Field(min_length=1, max_length=64, description="Rule ID to inspect allowlisted strategies for.")


class CreateRemediationPlanInput(StrictInputModel):
    finding_id: str = Field(min_length=1, max_length=64, description="Finding ID for which to generate a remediation plan.")


class ValidateRemediationPlanInput(StrictInputModel):
    remediation_id: str = Field(min_length=1, max_length=64, description="Remediation plan ID to validate.")


class GetRemediationStatusInput(StrictInputModel):
    finding_id: str = Field(min_length=1, max_length=64, description="Finding ID to query remediation plan status for.")


class RequestApprovalInput(StrictInputModel):
    remediation_id: str = Field(min_length=1, max_length=64, description="Remediation plan ID to submit for approval.")
    justification: Optional[str] = Field(default=None, max_length=500, description="Optional operational justification.")


class GetApprovalStatusInput(StrictInputModel):
    remediation_id: str = Field(min_length=1, max_length=64, description="Remediation plan ID to check approval state for.")


# ── Control Plane API Request / Response Models ───────────────────────────────

class MCPServerResponse(BaseModel):
    server_id: str
    server_name: str
    version: str
    server_type: str
    status: str
    enabled: bool
    permission_scope: List[str]
    request_count: int
    error_count: int
    avg_latency_ms: float
    last_health_check: Optional[datetime] = None
    last_request_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    last_error_code: Optional[str] = None
    tool_count: int = 0


class MCPToolResponse(BaseModel):
    tool_id: str
    server_id: str
    tool_name: str
    description: str
    operation_class: str
    required_permission: str
    enabled: bool
    version: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]


class MCPServerToggleRequest(BaseModel):
    enabled: bool


class MCPInvokeRequest(BaseModel):
    server_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class MCPInvokeResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    request_id: str


class MCPAuditEventResponse(BaseModel):
    event_id: str
    request_id: str
    correlation_id: str
    user_id: Optional[str] = None
    server_id: str
    tool_name: str
    operation_class: str
    authorized: bool
    status: str
    latency_ms: int
    error_code: Optional[str] = None
    safe_details: Dict[str, Any]
    sequence_number: int
    previous_event_hash: Optional[str] = None
    event_hash: str
    timestamp: datetime
