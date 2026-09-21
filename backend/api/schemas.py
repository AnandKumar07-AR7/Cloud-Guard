"""
CloudGuard — API Response Schemas

Defines all Pydantic models used as FastAPI request/response bodies.
These are the API contract — stable, typed, frontend-ready.

Design principles:
  - All enums serialized as uppercase strings (CRITICAL, HIGH, OPEN, etc.)
  - All timestamps as ISO-8601 UTC strings
  - Severity always from the canonical set: CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
  - No internal implementation details exposed
  - No secrets or credentials in any response model
  - Pagination uses limit/offset with total counts
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


# ──────────────────────────────────────────────────────────────────────────────
# System
# ──────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """GET /health — application health status."""
    status: str = Field(description="'healthy' | 'degraded' | 'unhealthy'")
    mode: str = Field(description="'demo' | 'aws'")
    version: str
    timestamp: str = Field(description="ISO-8601 UTC timestamp")
    ai_enabled: bool = Field(description="True if Anthropic API key is configured")
    uptime_seconds: Optional[float] = None
    database_status: Optional[str] = Field(default=None, description="'available' | 'unavailable'")


class ModeResponse(BaseModel):
    """GET /mode — current operating mode and capability summary."""
    mode: str = Field(description="'demo' | 'aws'")
    is_demo: bool
    is_aws: bool
    ai_enabled: bool
    ai_source: str = Field(description="'claude' | 'template'")
    aws_region: Optional[str] = None
    available_scenarios: Optional[List[str]] = Field(
        default=None,
        description="Available demo scenarios (demo mode only)"
    )
    message: str


# ──────────────────────────────────────────────────────────────────────────────
# Scans
# ──────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """POST /scans — initiate a security scan."""
    model_config = ConfigDict(extra="forbid")

    provider: Optional[str] = Field(
        default=None,
        description="Provider identifier ('demo' | 'aws')."
    )
    regions: Optional[List[str]] = Field(
        default=None,
        description="AWS regions to scan. Demo mode ignores this."
    )
    scenario: Optional[str] = Field(
        default=None,
        description="Demo scenario: 'default' | 'healthy' | 'critical'"
    )
    enrich_with_ai: bool = Field(
        default=False,
        description="Enrich findings with AI explanations. Requires ANTHROPIC_API_KEY."
    )


class SeveritySummary(BaseModel):
    """Breakdown of finding counts by severity."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational


class RiskSummaryResponse(BaseModel):
    """Risk posture summary for a scan."""
    posture_score: float = Field(ge=0.0, le=100.0, description="0=worst, 100=perfect")
    risk_level: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW | MINIMAL")
    severity_counts: SeveritySummary
    top_risk_score: float
    average_risk_score: float
    open_finding_count: int
    total_finding_count: int


class ScanErrorResponse(BaseModel):
    """Non-fatal error encountered during a scan."""
    source: str
    error_type: str
    message: str


class ScanSummaryResponse(BaseModel):
    """
    Scan summary returned by POST /scans and GET /scans/{scan_id}.
    Contains all metadata but not the full finding list.
    Use GET /findings?scan_id={id} to retrieve findings.
    """
    scan_id: str
    correlation_id: str
    provider: str
    account_id: str
    mode: str
    scenario: Optional[str] = None
    status: str = Field(description="CREATED|QUEUED|DISCOVERING|ANALYZING|RISK_SCORING|COMPLETED|FAILED")
    regions: List[str]
    resource_count: int
    finding_count: int
    severity_summary: SeveritySummary
    risk_summary: Optional[RiskSummaryResponse] = None
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_count: int
    error_message: Optional[str] = None


class ScanListResponse(BaseModel):
    """GET /scans — paginated list of scans."""
    items: List[ScanSummaryResponse]
    total: int
    limit: int
    offset: int


# ──────────────────────────────────────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────────────────────────────────────

class EvidenceResponse(BaseModel):
    """Structured evidence that supports a finding."""
    rule_id: str
    field_path: str
    observed_value: Any
    expected_value: Any
    summary: str


class FindingResponse(BaseModel):
    """
    Complete finding detail.
    Suitable for rendering the Obsidian Command Center finding detail view.
    """
    finding_id: str
    rule_id: str
    scan_id: Optional[str] = None

    # Resource identity
    resource_id: str
    resource_type: str
    service: str
    account_id: str
    region: str
    provider: str = "demo"

    # Severity & risk
    severity: str = Field(description="critical|high|medium|low|informational")
    risk_score: float = Field(ge=0.0, le=100.0)
    status: str = Field(description="OPEN|ACKNOWLEDGED|RESOLVED|...")

    # Content
    title: str
    description: str
    remediation_guidance: Optional[str] = None
    evidence: EvidenceResponse
    compliance_mappings: List[str] = Field(default_factory=list)

    # Risk factors
    internet_exposed: bool
    privilege_escalation_risk: bool
    data_exposure_risk: bool

    # AI enrichment (present only when AI was run)
    ai_explanation: Optional[str] = None
    ai_manager_summary: Optional[str] = None
    ai_source: Optional[str] = None  # "claude" | "template" | None

    # Timestamps
    detected_at: str
    updated_at: str

    # Phase 4 extensions (backward compatible)
    canonical_id: Optional[str] = None
    rule_version: Optional[str] = None
    resource_name: Optional[str] = None
    resource_arn: Optional[str] = None
    category: Optional[str] = None
    remediation_safety: Optional[str] = None
    resource_relationships: List[str] = Field(default_factory=list)
    security_context: Optional[Dict[str, Any]] = None
    risk_context: Optional[Dict[str, Any]] = None
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_context: Optional[Dict[str, Any]] = None
    remediation_context: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[Dict[str, Any]] = None

class FindingHistoryItem(BaseModel):
    finding_id: str
    scan_id: str
    status: str
    severity: str
    risk_score: float
    observed_at: Union[datetime, str]

class FindingHistoryResponse(BaseModel):
    canonical_id: str
    resource_id: str
    rule_id: str
    history: List[FindingHistoryItem]

class FindingListResponse(BaseModel):
    """GET /findings — paginated, filterable finding list."""
    items: List[FindingResponse]
    total: int
    limit: int
    offset: int
    filters_applied: Dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Structured API error response."""
    error_code: str
    message: str
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ──────────────────────────────────────────────────────────────────────────────
# Rules
# ──────────────────────────────────────────────────────────────────────────────

class RuleResponse(BaseModel):
    """
    Full metadata for a single security rule.
    Returned by GET /rules and GET /rules/{rule_id}.
    """
    rule_id: str
    name: str
    description: str

    # Scope
    provider: str
    service: str
    resource_type: str

    # Classification
    severity: str = Field(description="critical|high|medium|low|informational")
    category: str = Field(description="encryption|access-control|network|logging|configuration|monitoring")
    version: str

    # Risk factors
    internet_exposure_risk: bool
    privilege_escalation_risk: bool
    data_exposure_risk: bool

    # Remediation
    remediation_safety: str = Field(description="SAFE|REVIEW_REQUIRED|HIGH_IMPACT|DESTRUCTIVE")
    remediation_available: bool
    remediation_guidance: Optional[str] = None

    # Compliance
    compliance_mappings: List[str]

    # References
    references: List[str]

    # Lifecycle
    enabled: bool


class RuleCatalogSummary(BaseModel):
    """Summary statistics about the rule catalog."""
    total_rules: int
    enabled_rules: int
    severity_distribution: Dict[str, int]
    service_distribution: Dict[str, int]
    category_distribution: Dict[str, int]


class RuleListResponse(BaseModel):
    """GET /rules — paginated list of security rules."""
    items: List[RuleResponse]
    total: int
    limit: int
    offset: int
    filters_applied: Dict[str, Any] = Field(default_factory=dict)
    catalog_summary: Optional[RuleCatalogSummary] = None


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Investigation
# ──────────────────────────────────────────────────────────────────────────────

class InvestigationResponse(BaseModel):
    """GET /findings/{finding_id}/investigation — full investigation context."""
    finding: FindingResponse
    rule: Optional[RuleResponse] = None
    resource: Optional[Dict[str, Any]] = None
    evidence: EvidenceResponse
    risk_context: Optional[Dict[str, Any]] = None
    security_context: Optional[Dict[str, Any]] = None
    related_resources: List[Dict[str, Any]] = Field(default_factory=list)
    related_findings: List[FindingResponse] = Field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None
    remediation_context: Optional[Dict[str, Any]] = None
    compliance_context: Optional[Dict[str, Any]] = None


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Resource Explorer
# ──────────────────────────────────────────────────────────────────────────────

class ResourceResponse(BaseModel):
    """Resource summary for Resource Explorer list."""
    resource_id: str
    resource_type: str
    service: str
    provider: str
    account_id: str
    region: str
    name: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    security_posture: str = Field(description="SECURE|AT_RISK|HIGH_RISK|CRITICAL|UNKNOWN")
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    relationships: List[Dict[str, Any]] = Field(default_factory=list)


class ResourceDetailResponse(ResourceResponse):
    """Resource detail for Resource Explorer single resource view."""
    config: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingResponse] = Field(default_factory=list)


class ResourceListResponse(BaseModel):
    """GET /resources — paginated, filterable resource list."""
    items: List[ResourceResponse]
    total: int
    limit: int
    offset: int
    filters_applied: Dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Security Posture
# ──────────────────────────────────────────────────────────────────────────────

class PostureResponse(BaseModel):
    """GET /posture — environment and service security posture breakdown."""
    posture_score: float = Field(ge=0.0, le=100.0)
    risk_level: str = Field(description="CRITICAL|HIGH|MEDIUM|LOW|NONE")
    total_resources: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    service_posture: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    resource_posture_summary: Dict[str, int] = Field(default_factory=dict)
    last_scanned_at: Optional[str] = None

