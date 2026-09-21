"""
CloudGuard — Security Engine Data Models (Phase 4)

Defines Finding, Severity, FindingStatus and all supporting models.
These are the canonical contracts used across detection, risk, AI and reporting.

Phase 4 additions (all additive, backward-compatible):
  - SecurityContext  — evidence-based security classification of a finding
  - RiskContext      — explainable risk score breakdown
  - ResourceRelationship — typed edge between cloud resources
  - AIAnalysis       — structured output from AI Security Analyst
  - ComplianceContext — framework/control references
  - RemediationContext — structured remediation metadata
  - canonical_id     — deterministic finding identity across scans
  - Extensive new optional fields on Finding
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field


# ==============================================================================
# Enumerations
# ==============================================================================

class Severity(str, Enum):
    """Finding severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def display(self) -> str:
        return self.value.upper()

    @property
    def numeric(self) -> int:
        """Numeric weight for sorting (higher = more severe)."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}[self.value]


class FindingStatus(str, Enum):
    """
    Lifecycle status of a finding.

    Currently supported: OPEN
    Prepared for future: ACKNOWLEDGED, REMEDIATION_PENDING, REMEDIATING,
                         VERIFYING, RESOLVED, FAILED_REMEDIATION, SUPPRESSED
    """
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class RelationshipType(str, Enum):
    """
    Types of relationships between cloud resources.

    Only use a type when its semantics are unambiguous.
    """
    USES = "USES"                          # Resource uses another (e.g., EC2 uses Security Group)
    ASSUMES = "ASSUMES"                    # Identity assumes a role
    ATTACHED_TO = "ATTACHED_TO"            # Resource is directly attached (e.g., EBS to EC2)
    MEMBER_OF = "MEMBER_OF"               # Belongs to a group/VPC/subnet
    LOCATED_IN = "LOCATED_IN"             # Physically located in (region/VPC/subnet)
    PROTECTED_BY = "PROTECTED_BY"         # Protected via security control
    EXPOSED_THROUGH = "EXPOSED_THROUGH"   # Reachable through another resource
    DEPENDS_ON = "DEPENDS_ON"             # Logical dependency


class ResourcePosture(str, Enum):
    """
    Derived security posture of a single resource.

    Derived from actual findings — never manually assigned.
    """
    SECURE = "SECURE"         # No open findings
    AT_RISK = "AT_RISK"       # Has medium/low findings only
    HIGH_RISK = "HIGH_RISK"   # Has high findings
    CRITICAL = "CRITICAL"     # Has critical finding(s)
    UNKNOWN = "UNKNOWN"       # Insufficient scan data


# ==============================================================================
# Evidence Model
# ==============================================================================

class Evidence(BaseModel):
    """
    Structured evidence that supports a finding.

    Every finding must have evidence. The AI is NOT the source of evidence —
    the detector establishes evidence by inspecting actual resource configuration.
    """
    rule_id: str
    observed_value: Any = Field(description="The configuration value that triggered the rule.")
    expected_value: Any = Field(description="What the value should be for the resource to be compliant.")
    field_path: str = Field(description="JSON path to the configuration field (e.g. 'config.public_access_block.BlockPublicAcls').")
    source: str = Field(default="", description="Human-readable source of the evidence (e.g. 'bucket configuration').")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional structured context.")

    def to_summary(self) -> str:
        """One-line human-readable evidence summary."""
        src = f" [{self.source}]" if self.source else ""
        return (
            f"Field '{self.field_path}' is '{self.observed_value}' "
            f"(expected: '{self.expected_value}'){src}"
        )


# ==============================================================================
# Phase 4: Security Context
# ==============================================================================

class SecurityContext(BaseModel):
    """
    Evidence-based security classification for a finding.

    Properties are ONLY set when the evidence actually supports them.
    Never infer dangerous properties based solely on resource type.
    """
    internet_exposed: bool = Field(
        default=False,
        description="Resource is reachable from the public Internet based on evidence.",
    )
    publicly_accessible: bool = Field(
        default=False,
        description="Resource has public accessibility configured (e.g., RDS publicly_accessible=True).",
    )
    privileged: bool = Field(
        default=False,
        description="Finding involves a privileged identity or administrator-equivalent access.",
    )
    contains_sensitive_data: bool = Field(
        default=False,
        description="Resource is likely to contain sensitive data (database, S3 with PII tags, etc.).",
    )
    cross_account: bool = Field(
        default=False,
        description="Finding involves cross-account trust or access.",
    )
    identity_related: bool = Field(
        default=False,
        description="Finding involves IAM roles, users, or identity configuration.",
    )
    network_exposure: bool = Field(
        default=False,
        description="Finding is related to network-level exposure or misconfigured security groups.",
    )
    data_exposure: bool = Field(
        default=False,
        description="Finding puts data at risk of exposure or exfiltration.",
    )
    persistence_risk: bool = Field(
        default=False,
        description="Finding may allow an attacker to persist in the environment.",
    )
    lateral_movement_relevance: bool = Field(
        default=False,
        description="Finding may facilitate lateral movement to other resources.",
    )


# ==============================================================================
# Phase 4: Risk Context
# ==============================================================================

class RiskContext(BaseModel):
    """
    Explainable risk score breakdown for a finding.

    Documents why a finding received its risk score.
    The AI may explain this, but cannot change the scores.
    """
    base_score: float = Field(description="Base score derived from severity (0-100).")
    severity_factor: str = Field(description="Severity level that determines the base score.")

    internet_exposure_applied: bool = Field(default=False)
    internet_exposure_factor: float = Field(default=1.0, description="Multiplier applied for internet exposure.")

    privilege_applied: bool = Field(default=False)
    privilege_factor: float = Field(default=1.0, description="Multiplier applied for privilege escalation risk.")

    data_exposure_applied: bool = Field(default=False)
    data_exposure_factor: float = Field(default=1.0, description="Multiplier applied for data exposure risk.")

    final_score: float = Field(description="Final capped risk score (0-100).")
    rationale: str = Field(description="Human-readable explanation of the score components.")


# ==============================================================================
# Phase 4: Resource Relationship
# ==============================================================================

class ResourceRelationship(BaseModel):
    """
    A typed, evidence-backed relationship between two cloud resources.

    Only create relationships where actual configuration evidence exists.
    Never fabricate graph edges.
    """
    source_resource_id: str = Field(description="ID of the source resource.")
    relationship_type: RelationshipType = Field(description="Type of relationship.")
    target_resource_id: str = Field(description="ID of the target resource.")
    target_resource_type: str = Field(description="ResourceType of the target.")
    target_service: str = Field(description="AWS service of the target resource.")
    evidence_source: str = Field(
        default="",
        description="Config field or observation that confirms this relationship.",
    )


# ==============================================================================
# Phase 4: AI Analysis
# ==============================================================================

class AIAnalysis(BaseModel):
    """
    Structured output from the AI Security Analyst.

    Always distinguishes AI interpretation from observed evidence.
    The ai_source field is always set — 'claude' or 'template'.

    AI analysis is advisory. It does not create or modify findings.
    """
    ai_source: str = Field(description="'claude' or 'template'. Always set.")
    executive_summary: str = Field(description="1-2 sentence business-level summary.")
    technical_analysis: str = Field(description="Technical explanation of the security issue.")
    business_impact: str = Field(description="Business risk and impact without technical jargon.")
    attack_relevance: str = Field(
        default="",
        description="Potential attack vectors this finding enables. Based only on evidence.",
    )
    recommended_action: str = Field(description="Recommended remediation steps.")
    confidence: str = Field(
        default="high",
        description="'high'|'medium'|'low' — analyst confidence in the assessment.",
    )
    limitations: str = Field(
        default="",
        description="Any limitations in this analysis due to incomplete data.",
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Transparency fields
    observed_facts: List[str] = Field(
        default_factory=list,
        description="Bullet list of what was actually observed (from evidence, not AI inference).",
    )
    ai_inferences: List[str] = Field(
        default_factory=list,
        description="What the AI inferred or interpreted (clearly distinguished from facts).",
    )


# ==============================================================================
# Phase 4: Compliance Context
# ==============================================================================

class ComplianceReference(BaseModel):
    """A single compliance framework control reference."""
    framework: str = Field(description="e.g. 'CIS', 'NIST', 'ISO'")
    control_id: str = Field(description="e.g. 'CIS-3.1', 'NIST-AU-2'")
    control_title: str = Field(default="", description="Human-readable control name.")


class ComplianceContext(BaseModel):
    """Compliance framework references for a finding."""
    references: List[ComplianceReference] = Field(default_factory=list)
    raw_mappings: List[str] = Field(
        default_factory=list,
        description="Original raw mapping strings from rule metadata.",
    )

    @classmethod
    def from_mappings(cls, mappings: List[str]) -> "ComplianceContext":
        """Parse raw compliance mapping strings into structured references."""
        refs = []
        for m in mappings:
            parts = m.split("-", 1)
            if len(parts) == 2:
                refs.append(ComplianceReference(
                    framework=parts[0],
                    control_id=m,
                    control_title="",  # Titles populated on-demand in future
                ))
        return cls(references=refs, raw_mappings=mappings)


# ==============================================================================
# Phase 4: Remediation Context
# ==============================================================================

class RemediationContext(BaseModel):
    """
    Structured remediation information for a finding.

    Does NOT execute remediation. Only documents what should be done.
    The 'after_state' field is always None until remediation is verified.
    """
    available: bool = Field(default=False, description="Whether remediation guidance exists.")
    safety: str = Field(
        default="REVIEW_REQUIRED",
        description="SAFE|REVIEW_REQUIRED|HIGH_IMPACT|DESTRUCTIVE",
    )
    recommended_action: str = Field(default="", description="Step-by-step remediation guidance.")
    affected_fields: List[str] = Field(
        default_factory=list,
        description="Config fields that need to change to resolve this finding.",
    )
    estimated_impact: str = Field(
        default="",
        description="Expected impact of applying the remediation.",
    )
    # Future: before/after state comparison
    before_state: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Config state at time of finding detection (safe subset only).",
    )
    after_state: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Observed config state after remediation. None until verified.",
    )
    verification_criteria: str = Field(
        default="",
        description="How to verify this finding is resolved.",
    )


# ==============================================================================
# Finding Model
# ==============================================================================

def _compute_canonical_id(rule_id: str, resource_id: str, account_id: str, field_path: str) -> str:
    """
    Compute a deterministic canonical finding identity.

    The canonical_id is a SHA-256 hash of (rule_id, resource_id, account_id, field_path).
    It is STABLE across scans — the same underlying security condition on the same
    resource always produces the same canonical_id.

    This enables future:
      - Finding deduplication
      - History tracking (first_seen, last_seen)
      - Resolution tracking
      - Alerting (don't re-alert on known findings)
    """
    payload = f"{rule_id}|{resource_id}|{account_id}|{field_path}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


class Finding(BaseModel):
    """
    A detected security misconfiguration.

    A Finding is created ONLY when a SecurityRule's detection logic fires
    on actual resource configuration data. It is never invented by AI.

    Phase 4 adds: canonical_id, risk_context, security_context,
    relationships, ai_analysis, compliance_context, remediation_context,
    scan_id, rule_version, resource_name, resource_arn.
    All new fields are optional/defaulted for backward compatibility.
    """

    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique per-scan finding identifier (UUID). Use canonical_id for cross-scan identity.",
    )
    scan_id: str = Field(
        default="",
        description="ID of the scan that produced this finding.",
    )

    rule_id: str = Field(description="ID of the SecurityRule that produced this finding.")
    rule_version: str = Field(default="1.0.0", description="Version of the rule at detection time.")
    resource_id: str = Field(description="ID of the affected resource.")
    resource_type: str = Field(description="ResourceType enum value.")
    resource_name: str = Field(default="", description="Human-readable resource name.")
    resource_arn: str = Field(default="", description="ARN of the resource (if available).")
    service: str = Field(description="Cloud service: s3, iam, ec2, etc.")
    account_id: str = Field(description="Cloud account where the resource lives.")
    region: str = Field(description="Region of the resource.")

    severity: Severity = Field(description="Finding severity.")
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Deterministic risk score 0-100. Set by the Risk Engine.",
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Current lifecycle status. Currently only OPEN is actively used.",
    )

    title: str = Field(description="Short title of the finding.")
    description: str = Field(description="Detailed description of the finding.")
    evidence: Evidence = Field(description="Structured evidence from the detector.")
    remediation_guidance: Optional[str] = Field(
        default=None,
        description="Template-based remediation steps (legacy field). See remediation_context for structured version.",
    )

    # Timestamps
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_detected_at: Optional[datetime] = Field(
        default=None,
        description="When this finding was first observed. None until persistence is implemented.",
    )
    last_detected_at: Optional[datetime] = Field(
        default=None,
        description="When this finding was last confirmed present. None until persistence is implemented.",
    )

    # Compliance
    compliance_mappings: List[str] = Field(
        default_factory=list,
        description="List of compliance control IDs this finding maps to.",
    )

    # Classification
    category: str = Field(
        default="configuration",
        description="Rule category: encryption|access-control|network|logging|configuration|monitoring",
    )
    remediation_safety: str = Field(
        default="REVIEW_REQUIRED",
        description="SAFE|REVIEW_REQUIRED|HIGH_IMPACT|DESTRUCTIVE — guides future auto-remediation.",
    )
    references: List[str] = Field(
        default_factory=list,
        description="Links to AWS docs, CIS/NIST references.",
    )
    resource_relationships: List[str] = Field(
        default_factory=list,
        description="Related resource IDs (legacy flat list). See relationships for typed version.",
    )

    # Risk factors (set by Risk Engine)
    internet_exposed: bool = Field(default=False)
    privilege_escalation_risk: bool = Field(default=False)
    data_exposure_risk: bool = Field(default=False)

    # Phase 4: Rich Context (all optional for backward compat)
    security_context: Optional[SecurityContext] = Field(
        default=None,
        description="Evidence-based security classification. Set by scan pipeline.",
    )
    risk_context: Optional[RiskContext] = Field(
        default=None,
        description="Explainable risk score breakdown. Set by Risk Engine.",
    )
    relationships: List[ResourceRelationship] = Field(
        default_factory=list,
        description="Typed resource relationships derived from configuration.",
    )
    compliance_context: Optional[ComplianceContext] = Field(
        default=None,
        description="Structured compliance framework references.",
    )
    remediation_context: Optional[RemediationContext] = Field(
        default=None,
        description="Structured remediation information.",
    )
    ai_analysis: Optional[AIAnalysis] = Field(
        default=None,
        description="Structured AI Security Analyst output. None until AI enrichment is requested.",
    )

    # Legacy AI fields (kept for backward compatibility with Phase 2/3 API)
    ai_explanation: Optional[str] = None
    ai_manager_summary: Optional[str] = None

    @property
    def is_open(self) -> bool:
        return self.status == FindingStatus.OPEN

    @property
    def is_resolved(self) -> bool:
        return self.status == FindingStatus.RESOLVED

    @property
    def canonical_id(self) -> str:
        """
        Deterministic cross-scan finding identity.

        Same rule + resource + account + field → same canonical_id.
        Use this to track finding history and prevent duplicate alerts.
        """
        return _compute_canonical_id(
            self.rule_id,
            self.resource_id,
            self.account_id,
            self.evidence.field_path,
        )

    def derive_security_context(self) -> SecurityContext:
        """
        Derive SecurityContext from the finding's own evidence and risk factors.

        Only sets properties where evidence supports them.
        """
        return SecurityContext(
            internet_exposed=self.internet_exposed,
            publicly_accessible=self.internet_exposed,
            privileged=self.privilege_escalation_risk,
            contains_sensitive_data=self.data_exposure_risk,
            cross_account="IAM-006" in self.rule_id or "trust" in self.title.lower(),
            identity_related=self.service == "iam",
            network_exposure=self.service in ("ec2", "vpc") or self.category == "network",
            data_exposure=self.data_exposure_risk,
            persistence_risk=self.privilege_escalation_risk,
            lateral_movement_relevance=self.privilege_escalation_risk or self.internet_exposed,
        )

    def derive_resource_posture(self, all_findings: "List[Finding]" = None) -> ResourcePosture:
        """
        Derive posture for this finding's resource from all findings on that resource.
        """
        if all_findings is None:
            all_findings = [self]

        resource_findings = [f for f in all_findings if f.resource_id == self.resource_id and f.is_open]

        if not resource_findings:
            return ResourcePosture.SECURE
        severities = {f.severity for f in resource_findings}
        if Severity.CRITICAL in severities:
            return ResourcePosture.CRITICAL
        if Severity.HIGH in severities:
            return ResourcePosture.HIGH_RISK
        return ResourcePosture.AT_RISK


# ==============================================================================
# Scan Result
# ==============================================================================

class ScanResult(BaseModel):
    """Aggregated result of a security scan."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: str
    account_id: str
    regions: List[str]
    mode: str = Field(description="'demo' or 'aws'.")

    findings: List[Finding] = Field(default_factory=list)
    resource_count: int = 0
    error_count: int = 0
    errors: List[Dict[str, Any]] = Field(default_factory=list)

    # Phase 4: Store discovered resources for Resource Explorer
    resources: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Discovered resources (serialized CloudResource). Set by scan pipeline.",
    )

    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def open_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_open]

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def severity_summary(self) -> Dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
        }

    def findings_for_resource(self, resource_id: str) -> List[Finding]:
        """Return all findings for a specific resource."""
        return [f for f in self.findings if f.resource_id == resource_id]
