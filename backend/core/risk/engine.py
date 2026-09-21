"""
CloudGuard — Risk Scoring Engine

Calculates deterministic, evidence-based risk scores for findings.

The LLM is never the source of the risk score.
Risk is calculated from:
  - Severity (base score)
  - Internet exposure (multiplier)
  - Privilege escalation potential (multiplier)
  - Data exposure risk (multiplier)

Output: risk_score (0-100), enriched Finding with risk factors set.

Security Posture Score (0-100) is also calculated from a collection
of findings, where 100 means fully secure and 0 means critically exposed.

Phase 4: Added build_risk_context() for explainable score breakdown,
         and calculate_service_posture() for per-service posture.
"""
from __future__ import annotations

from typing import Any, Dict, List

from core.security.models import Finding, RiskContext, ScanResult, Severity


# ==============================================================================
# Risk Score Configuration
# ==============================================================================

# Base scores per severity level (before multipliers)
_SEVERITY_BASE: Dict[str, float] = {
    Severity.CRITICAL.value:      92.0,
    Severity.HIGH.value:          72.0,
    Severity.MEDIUM.value:        45.0,
    Severity.LOW.value:           18.0,
    Severity.INFORMATIONAL.value:  5.0,
}

# Multiplicative risk factors (applied on top of base score)
_INTERNET_EXPOSURE_FACTOR:       float = 1.20   # +20% if internet exposed
_PRIVILEGE_ESCALATION_FACTOR:    float = 1.15   # +15% if priv-esc risk
_DATA_EXPOSURE_FACTOR:           float = 1.10   # +10% if data at risk

# Maximum risk score cap
_MAX_SCORE: float = 100.0

# Posture score: weight per severity when computing the security posture
_POSTURE_SEVERITY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value:      10.0,
    Severity.HIGH.value:           6.0,
    Severity.MEDIUM.value:         3.0,
    Severity.LOW.value:            1.0,
    Severity.INFORMATIONAL.value:  0.2,
}

# Ideal starting posture (no findings = 100)
_POSTURE_BASE = 100.0
# Maximum total weight before posture reaches 0
_POSTURE_MAX_WEIGHT = 150.0


# ==============================================================================
# Core Scoring Functions
# ==============================================================================

def calculate_risk_score(finding: Finding) -> float:
    """
    Calculate a deterministic risk score (0-100) for a single finding.

    The score is derived from:
      1. Severity base value
      2. Internet exposure multiplier
      3. Privilege escalation potential multiplier
      4. Data exposure multiplier

    Args:
        finding: The Finding to score. Must have severity and risk factors set.

    Returns:
        Risk score between 0.0 and 100.0 (rounded to 1 decimal place).
    """
    base = _SEVERITY_BASE.get(finding.severity.value, 45.0)

    score = base

    if finding.internet_exposed:
        score *= _INTERNET_EXPOSURE_FACTOR

    if finding.privilege_escalation_risk:
        score *= _PRIVILEGE_ESCALATION_FACTOR

    if finding.data_exposure_risk:
        score *= _DATA_EXPOSURE_FACTOR

    return round(min(score, _MAX_SCORE), 1)


def build_risk_context(finding: Finding) -> RiskContext:
    """
    Build an explainable RiskContext for a finding.

    Documents every factor that contributed to the final score so the UI
    can display: "Why is this finding's risk score X?"

    The calculation is IDENTICAL to calculate_risk_score() — they
    must never diverge.

    Args:
        finding: The Finding to analyze.

    Returns:
        RiskContext with full breakdown and rationale.
    """
    base = _SEVERITY_BASE.get(finding.severity.value, 45.0)
    score = base

    inet_applied = finding.internet_exposed
    priv_applied = finding.privilege_escalation_risk
    data_applied = finding.data_exposure_risk

    inet_factor = _INTERNET_EXPOSURE_FACTOR if inet_applied else 1.0
    priv_factor = _PRIVILEGE_ESCALATION_FACTOR if priv_applied else 1.0
    data_factor = _DATA_EXPOSURE_FACTOR if data_applied else 1.0

    if inet_applied:
        score *= _INTERNET_EXPOSURE_FACTOR
    if priv_applied:
        score *= _PRIVILEGE_ESCALATION_FACTOR
    if data_applied:
        score *= _DATA_EXPOSURE_FACTOR

    final = round(min(score, _MAX_SCORE), 1)

    # Build human-readable rationale
    factors = []
    factors.append(f"Base score ({finding.severity.value}): {base:.0f}")
    if inet_applied:
        factors.append(
            f"Internet exposure: x{_INTERNET_EXPOSURE_FACTOR} "
            f"(+{(_INTERNET_EXPOSURE_FACTOR - 1) * 100:.0f}%)"
        )
    if priv_applied:
        factors.append(
            f"Privilege escalation risk: x{_PRIVILEGE_ESCALATION_FACTOR} "
            f"(+{(_PRIVILEGE_ESCALATION_FACTOR - 1) * 100:.0f}%)"
        )
    if data_applied:
        factors.append(
            f"Data exposure risk: x{_DATA_EXPOSURE_FACTOR} "
            f"(+{(_DATA_EXPOSURE_FACTOR - 1) * 100:.0f}%)"
        )
    if final < score:
        factors.append(f"Capped at maximum score: {_MAX_SCORE:.0f}")
    factors.append(f"Final score: {final:.1f}/100")

    rationale = " -> ".join(factors)

    return RiskContext(
        base_score=base,
        severity_factor=finding.severity.value,
        internet_exposure_applied=inet_applied,
        internet_exposure_factor=inet_factor,
        privilege_applied=priv_applied,
        privilege_factor=priv_factor,
        data_exposure_applied=data_applied,
        data_exposure_factor=data_factor,
        final_score=final,
        rationale=rationale,
    )


def enrich_finding_with_risk(finding: Finding) -> Finding:
    """
    Calculate and set the risk_score and risk_context on a finding.

    Returns a new Finding with risk_score and risk_context populated.
    """
    score = calculate_risk_score(finding)
    context = build_risk_context(finding)
    return finding.model_copy(update={"risk_score": score, "risk_context": context})


def enrich_all_findings(findings: List[Finding]) -> List[Finding]:
    """
    Enrich every finding in a list with its risk score and context.
    Returns a new list — does not mutate input findings.
    """
    return [enrich_finding_with_risk(f) for f in findings]


def calculate_security_posture_score(findings: List[Finding]) -> float:
    """
    Calculate a Security Posture Score (0-100) for an environment.

    Score starts at 100 (fully secure) and decreases based on the
    weighted count of findings by severity.

      100  ->  No findings (fully secure)
        0  ->  Maximum weighted finding count reached

    Args:
        findings: List of findings (should have risk_score populated).

    Returns:
        Posture score between 0.0 and 100.0.
    """
    if not findings:
        return 100.0

    total_weight = sum(
        _POSTURE_SEVERITY_WEIGHTS.get(f.severity.value, 0.5)
        for f in findings
        if f.is_open
    )

    # Logarithmic decay: makes the score drop quickly for critical issues
    # but not instantly to 0 for many low findings
    ratio = min(total_weight / _POSTURE_MAX_WEIGHT, 1.0)
    posture = _POSTURE_BASE * (1.0 - ratio)

    return round(max(0.0, posture), 1)


def calculate_risk_summary(findings: List[Finding]) -> Dict[str, Any]:
    """
    Produce a complete risk summary for a collection of findings.

    Args:
        findings: All findings to summarize (should have risk_score populated).

    Returns:
        Dictionary with:
          - posture_score: Security Posture Score (0-100)
          - risk_level: CRITICAL / HIGH / MEDIUM / LOW / NONE
          - severity_counts: {critical, high, medium, low, informational}
          - top_risk_score: Highest individual risk score
          - average_risk_score: Mean of all risk scores
          - open_finding_count: Count of OPEN findings only
          - total_finding_count: All findings
    """
    open_findings = [f for f in findings if f.is_open]
    posture = calculate_security_posture_score(findings)

    severity_counts: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in open_findings:
        severity_counts[f.severity.value] += 1

    risk_scores = [f.risk_score for f in open_findings if f.risk_score > 0]

    if posture >= 90:
        risk_level = "NONE"
    elif posture >= 70:
        risk_level = "LOW"
    elif posture >= 45:
        risk_level = "MEDIUM"
    elif posture >= 20:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "posture_score": posture,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "top_risk_score": round(max(risk_scores, default=0.0), 1),
        "average_risk_score": round(
            sum(risk_scores) / len(risk_scores) if risk_scores else 0.0, 1
        ),
        "open_finding_count": len(open_findings),
        "total_finding_count": len(findings),
    }


def calculate_service_posture(findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
    """
    Calculate per-service security posture breakdown.

    Args:
        findings: All findings from a scan.

    Returns:
        Dict mapping service name to posture dict:
          {service: {posture_score, finding_count, critical, high, medium, low}}
    """
    by_service: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.is_open:
            by_service.setdefault(f.service, []).append(f)

    result = {}
    for svc, svc_findings in by_service.items():
        result[svc] = {
            "posture_score": calculate_security_posture_score(svc_findings),
            "finding_count": len(svc_findings),
            "critical": sum(1 for f in svc_findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in svc_findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in svc_findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in svc_findings if f.severity == Severity.LOW),
        }
    return result
