"""
CloudGuard — Security Rule Base Classes

Defines the SecurityRule abstract base and RuleMetadata descriptor.
All security rules extend SecurityRule and implement detect().
Rules are pure Python — they receive CloudResource objects and
return Findings. They never call AWS APIs directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.providers.base import CloudResource, ResourceType
from core.security.models import Evidence, Finding, Severity


# ==============================================================================
# Remediation Safety Classification
# ==============================================================================

class RemediationSafety(str, Enum):
    """
    Safety classification for future remediation actions.

    Used by the Remediation Planning Agent (Phase 7+) to determine how much
    authorization is required before executing a remediation action.

    SAFE             — Non-destructive, easily reversible (e.g., enable logging).
    REVIEW_REQUIRED  — Requires human review before execution (default).
    HIGH_IMPACT      — Could affect service availability or access.
    DESTRUCTIVE      — Irreversible or data-destroying — always require approval.
    """
    SAFE = "SAFE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    HIGH_IMPACT = "HIGH_IMPACT"
    DESTRUCTIVE = "DESTRUCTIVE"


# ==============================================================================
# Rule Metadata
# ==============================================================================

@dataclass
class RuleMetadata:
    """
    Metadata descriptor for a SecurityRule.

    All fields are static per rule class and describe the rule's intent,
    scope, risk profile, and compliance mappings.
    """
    rule_id: str
    name: str
    description: str
    provider: str                       # "aws", "azure", "gcp", "*"
    service: str                        # "s3", "iam", "ec2", etc.
    resource_type: str                  # ResourceType enum value
    severity: Severity

    # Category — groups related rules for the Detection Rules UI
    category: str = "configuration"     # encryption, access-control, network, logging, configuration, monitoring

    # Rule lifecycle
    enabled: bool = True
    version: str = "1.0"

    # Risk factors — used by the Risk Engine
    internet_exposure_risk: bool = False
    privilege_escalation_risk: bool = False
    data_exposure_risk: bool = False

    # Future remediation guidance
    remediation_safety: RemediationSafety = RemediationSafety.REVIEW_REQUIRED

    # Can this be auto-remediated?
    remediation_available: bool = True

    # Compliance control references
    compliance_mappings: List[str] = field(default_factory=list)

    # Brief remediation template (AI may supplement)
    remediation_template: Optional[str] = None

    # Links to AWS/CIS/NIST documentation
    references: List[str] = field(default_factory=list)


# ==============================================================================
# Security Rule Base
# ==============================================================================

class SecurityRule(ABC):
    """
    Abstract base for all CloudGuard security rules.

    Subclasses implement detect() to inspect a CloudResource and return
    a Finding if the rule fires, or None if the resource is compliant.

    Design constraints:
      - detect() must NOT make any network/AWS API calls.
      - detect() must NOT invoke AI or LLMs.
      - detect() must NOT have side effects.
      - detect() must be deterministic: same input → same output.
      - Evidence must be grounded in the resource's actual config.
    """

    def __init__(self) -> None:
        if not hasattr(self, "metadata"):
            raise TypeError(
                f"SecurityRule subclass '{type(self).__name__}' must define "
                "a 'metadata: RuleMetadata' class attribute."
            )

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def severity(self) -> Severity:
        return self.metadata.severity

    @property
    def is_enabled(self) -> bool:
        return self.metadata.enabled

    def applies_to(self, resource: CloudResource) -> bool:
        """
        Return True if this rule applies to the given resource.
        Override for more complex scoping logic.
        """
        if not self.metadata.enabled:
            return False
        return resource.resource_type.value == self.metadata.resource_type

    @abstractmethod
    def detect(self, resource: CloudResource) -> Optional[Finding]:
        """
        Inspect the resource and return a Finding if a violation is detected.

        Args:
            resource: The normalized CloudResource to inspect.

        Returns:
            A Finding if the rule fires, None if the resource is compliant.
        """
        ...

    def _make_finding(
        self,
        resource: CloudResource,
        title: str,
        description: str,
        evidence: Evidence,
        severity_override: Optional[Severity] = None,
    ) -> Finding:
        """
        Helper to construct a Finding with all required fields populated.
        Avoids boilerplate in detect() implementations.
        """
        return Finding(
            rule_id=self.metadata.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type.value,
            service=resource.service,
            account_id=resource.account_id,
            region=resource.region,
            severity=severity_override or self.metadata.severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation_guidance=self.metadata.remediation_template,
            compliance_mappings=list(self.metadata.compliance_mappings),
            internet_exposed=self.metadata.internet_exposure_risk,
            privilege_escalation_risk=self.metadata.privilege_escalation_risk,
            data_exposure_risk=self.metadata.data_exposure_risk,
            category=self.metadata.category,
            remediation_safety=self.metadata.remediation_safety.value,
            references=list(self.metadata.references),
        )
