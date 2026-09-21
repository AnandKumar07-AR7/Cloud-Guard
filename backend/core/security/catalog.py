"""
CloudGuard — Rule Catalog

Central registry that exposes all security rules and their metadata.

The RuleCatalog introspects the SecurityRuleEngine to produce
structured metadata about every registered rule, suitable for
the GET /rules and GET /rules/{rule_id} API endpoints.

Design:
  - Rules are owned by SecurityRuleEngine — the catalog reads from it.
  - Catalog is read-only: no rule state is modified here.
  - Catalog is computed fresh from the engine each call (engine is cached).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from core.security.engine import get_engine
from core.security.rules.base import SecurityRule


def get_all_rules(
    service: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    enabled_only: bool = True,
) -> List[SecurityRule]:
    """
    Return all registered security rules, optionally filtered.

    Args:
        service:      Filter by AWS service (e.g. "s3", "iam", "ec2").
        severity:     Filter by severity level (e.g. "critical", "high").
        category:     Filter by rule category (e.g. "encryption", "network").
        enabled_only: If True, only return enabled rules.

    Returns:
        List of SecurityRule instances matching all specified filters.
    """
    engine = get_engine()
    rules = engine.rules

    if enabled_only:
        rules = [r for r in rules if r.metadata.enabled]

    if service:
        rules = [r for r in rules if r.metadata.service.lower() == service.lower()]

    if severity:
        rules = [r for r in rules if r.metadata.severity.value.lower() == severity.lower()]

    if category:
        rules = [r for r in rules if r.metadata.category.lower() == category.lower()]

    return rules


def get_rule(rule_id: str) -> Optional[SecurityRule]:
    """
    Look up a single rule by its canonical rule ID (e.g. "S3-001").

    Returns None if no rule with that ID is registered.
    """
    engine = get_engine()
    return engine.get_rule(rule_id.upper())


def get_catalog_summary() -> Dict:
    """
    Return a high-level summary of the rule catalog.

    Useful for the GET /rules response metadata.
    """
    engine = get_engine()
    rules = engine.rules

    from core.security.models import Severity
    severity_counts: Dict[str, int] = {s.value: 0 for s in Severity}
    service_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for rule in rules:
        if not rule.metadata.enabled:
            continue
        sev = rule.metadata.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        svc = rule.metadata.service
        service_counts[svc] = service_counts.get(svc, 0) + 1

        cat = rule.metadata.category
        category_counts[cat] = category_counts.get(cat, 0) + 1

    enabled_rules = [r for r in rules if r.metadata.enabled]

    return {
        "total_rules": len(rules),
        "enabled_rules": len(enabled_rules),
        "severity_distribution": severity_counts,
        "service_distribution": service_counts,
        "category_distribution": category_counts,
    }
