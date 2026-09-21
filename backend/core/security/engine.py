"""
CloudGuard — Security Rule Engine

The SecurityRuleEngine orchestrates all registered rules against a collection
of CloudResource objects, producing Finding records.

Key design properties:
  - Rules are pure Python functions — no AWS calls, no AI calls.
  - The engine is stateless. It is safe to call from multiple threads.
  - Results are deterministic: same resources → same findings.
  - Errors in individual rules are caught and logged, never silently dropped.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from core.providers.base import CloudResource, ResourceType
from core.security.models import Finding, ScanResult, Severity
from core.security.rules.base import SecurityRule
from core.utils.logging import get_logger

log = get_logger(__name__)


class SecurityRuleEngine:
    """
    Runs a registry of SecurityRule objects against CloudResource collections.

    Usage:
        engine = SecurityRuleEngine(rules=[...all rules...])
        scan_result = engine.scan(discovery_result)
    """

    def __init__(self, rules: Optional[List[SecurityRule]] = None) -> None:
        if rules is None:
            rules = _default_rules()
        self._rules = rules
        log.info(
            "rule_engine_initialized",
            rule_count=len(self._rules),
            rule_ids=[r.rule_id for r in self._rules],
        )

    @property
    def rules(self) -> List[SecurityRule]:
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def scan_resource(self, resource: CloudResource) -> List[Finding]:
        """
        Run all applicable rules against a single CloudResource.

        Args:
            resource: The resource to evaluate.

        Returns:
            List of findings. Empty list means the resource is compliant
            against all applicable rules.
        """
        findings: List[Finding] = []

        for rule in self._rules:
            if not rule.applies_to(resource):
                continue
            try:
                finding = rule.detect(resource)
                if finding is not None:
                    updates = {}
                    if not finding.rule_version:
                        updates["rule_version"] = rule.metadata.version
                    if not finding.resource_name:
                        updates["resource_name"] = resource.display_name
                    if not finding.resource_arn and "arn" in resource.config:
                        updates["resource_arn"] = str(resource.config["arn"])
                    if updates:
                        finding = finding.model_copy(update=updates)
                    findings.append(finding)
                    log.debug(
                        "rule_fired",
                        rule_id=rule.rule_id,
                        resource_id=resource.resource_id,
                        severity=finding.severity.value,
                    )
            except Exception as exc:
                log.error(
                    "rule_error",
                    rule_id=rule.rule_id,
                    resource_id=resource.resource_id,
                    error=str(exc),
                    exc_info=True,
                )

        return findings

    def scan_resources(self, resources: List[CloudResource]) -> List[Finding]:
        """
        Run all applicable rules against every resource in a list.

        Args:
            resources: Resources to evaluate.

        Returns:
            All findings across all resources.
        """
        all_findings: List[Finding] = []
        for resource in resources:
            all_findings.extend(self.scan_resource(resource))
        return all_findings

    def scan(
        self,
        resources: List[CloudResource],
        provider: str = "unknown",
        account_id: str = "unknown",
        regions: Optional[List[str]] = None,
        mode: str = "demo",
    ) -> ScanResult:
        """
        Full scan: discover → detect → return ScanResult.

        Args:
            resources: All collected CloudResource objects.
            provider:  Provider name ('aws' or 'demo').
            account_id: Cloud account ID.
            regions: Regions that were scanned.
            mode: Operating mode label for the result.

        Returns:
            ScanResult containing all findings with counts and metadata.
        """
        t0 = time.monotonic()
        log.info(
            "scan_started",
            provider=provider,
            account_id=account_id,
            resource_count=len(resources),
            rule_count=self.rule_count,
        )

        findings = self.scan_resources(resources)

        elapsed = round(time.monotonic() - t0, 2)
        log.info(
            "scan_completed",
            resource_count=len(resources),
            finding_count=len(findings),
            elapsed_seconds=elapsed,
        )

        return ScanResult(
            provider=provider,
            account_id=account_id,
            regions=regions or [],
            mode=mode,
            findings=findings,
            resource_count=len(resources),
        )

    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Look up a rule by ID."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def rules_for_service(self, service: str) -> List[SecurityRule]:
        """Return all rules scoped to a given service."""
        return [r for r in self._rules if r.metadata.service == service]


def _default_rules() -> List[SecurityRule]:
    """Return the full default rule registry (all supported AWS services)."""
    from core.security.rules.s3_rules import S3_RULES
    from core.security.rules.iam_rules import IAM_RULES
    from core.security.rules.sg_rules import SG_RULES
    from core.security.rules.lambda_rules import LAMBDA_RULES
    from core.security.rules.ec2_rules import EC2_RULES
    from core.security.rules.rds_rules import RDS_RULES
    from core.security.rules.vpc_rules import VPC_RULES
    from core.security.rules.cloudtrail_rules import CLOUDTRAIL_RULES

    return [
        *S3_RULES,
        *IAM_RULES,
        *SG_RULES,
        *LAMBDA_RULES,
        *EC2_RULES,
        *RDS_RULES,
        *VPC_RULES,
        *CLOUDTRAIL_RULES,
    ]


# Module-level default engine instance (lazy-loaded)
_engine: Optional[SecurityRuleEngine] = None


def get_engine() -> SecurityRuleEngine:
    """Return the singleton SecurityRuleEngine with all default rules loaded."""
    global _engine
    if _engine is None:
        _engine = SecurityRuleEngine()
    return _engine


def reset_engine() -> None:
    """Reset the singleton engine (used in tests and when rules change)."""
    global _engine
    _engine = None

