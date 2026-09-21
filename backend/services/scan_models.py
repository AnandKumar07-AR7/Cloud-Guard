"""
CloudGuard — Scan Lifecycle Models

Defines the canonical scan lifecycle status and the full ScanRecord
that represents an executed scan with all metadata, findings, and risk summary.

These models are the source of truth for scan state throughout the system.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from core.providers.base import CloudResource
from core.security.models import Finding, Severity


class ScanStatus(str, Enum):
    """Formal scan lifecycle states."""
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    DISCOVERING = "DISCOVERING"
    ANALYZING = "ANALYZING"
    RISK_SCORING = "RISK_SCORING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    # Future states (architecture-ready but not yet implemented):
    # REMEDIATING = "REMEDIATING"
    # VERIFYING = "VERIFYING"
    # RESCANNING = "RESCANNING"


class ScanScenario(str, Enum):
    """Demo mode scenario selector."""
    DEFAULT = "default"      # Mixed secure + vulnerable
    HEALTHY = "healthy"      # No meaningful findings
    CRITICAL = "critical"    # Multiple critical/high findings


class RiskSummary(BaseModel):
    """Structured risk summary produced by the Risk Engine."""
    posture_score: float = Field(ge=0.0, le=100.0)
    risk_level: str
    severity_counts: Dict[str, int]
    top_risk_score: float
    average_risk_score: float
    open_finding_count: int
    total_finding_count: int


class ScanError(BaseModel):
    """Structured representation of a non-fatal scan error."""
    source: str
    error_type: str
    message: str
    # Never include stack traces or credential details in the serialized form


class ScanRecord(BaseModel):
    """
    Complete record of an executed (or in-progress) security scan.

    This is the primary domain object for scan state.
    It is stored in-memory in Phase 2 and will move to PostgreSQL in Phase 5.
    """
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])

    # Identity
    provider: str
    account_id: str
    mode: str                           # "demo" | "aws"
    scenario: Optional[str] = None      # Demo scenario name

    # Scope
    regions: List[str] = Field(default_factory=list)

    # Lifecycle
    status: ScanStatus = ScanStatus.CREATED
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    # Results
    resource_count: int = 0
    resources: List[CloudResource] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    risk_summary: Optional[RiskSummary] = None
    errors: List[ScanError] = Field(default_factory=list)
    error_message: Optional[str] = None  # Only set on FAILED status

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 2)
        return None

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def mark_status(self, status: ScanStatus) -> None:
        """Transition to a new status (mutates in place)."""
        self.status = status
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            self.completed_at = datetime.now(timezone.utc)

    def add_error(self, source: str, error_type: str, message: str) -> None:
        """Record a non-fatal error without failing the whole scan."""
        self.errors.append(ScanError(
            source=source,
            error_type=error_type,
            message=_sanitize_error_message(message),
        ))


def _sanitize_error_message(message: str) -> str:
    """
    Remove potentially sensitive information from error messages.
    Prevents credential material from appearing in scan error records.
    """
    import re
    # Remove anything that looks like an AWS key or secret
    message = re.sub(r'AKIA[0-9A-Z]{16}', '[AWS_KEY_REDACTED]', message)
    message = re.sub(r'(?i)(secret[_\s]*key|aws[_\s]*secret)[^\s]{10,}', '[SECRET_REDACTED]', message)
    # Truncate very long messages
    if len(message) > 500:
        message = message[:500] + "...[truncated]"
    return message
