"""
Markdown report generator for scan results.
"""

from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def generate_markdown_report(
    findings: List[Dict[str, Any]],
    output_path: str = "output/report.md"
) -> None:
    """
    Generate a human-readable Markdown report.

    Args:
        findings: List of finding dictionaries with explanations
        output_path: Path to write the Markdown report
    """
    # Create output directory if it doesn't exist
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Build report sections
    report_lines = []

    # Header
    report_lines.extend(_generate_header())

    # Executive Summary
    report_lines.extend(_generate_executive_summary(findings))

    # Severity Breakdown
    report_lines.extend(_generate_severity_breakdown(findings))

    # Developer Checklist
    report_lines.extend(_generate_developer_checklist(findings))

    # Detailed Findings
    report_lines.extend(_generate_detailed_findings(findings))

    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))

    logger.info(f"Markdown report written to {output_path}")
    print(f"✓ Markdown report saved: {output_path}")


def _generate_header() -> List[str]:
    """Generate report header."""
    scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return [
        "# CloudGuard Copilot - Security Scan Report",
        "",
        f"**Scan Date:** {scan_date}",
        "",
        "---",
        ""
    ]


def _generate_executive_summary(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate executive summary section."""
    lines = [
        "## Executive Summary",
        ""
    ]

    if not findings:
        lines.extend([
            "**Status:** ✓ No security issues detected",
            "",
            "All scanned resources are compliant with security best practices.",
            "",
            "---",
            ""
        ])
        return lines

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    total = len(findings)

    # Risk assessment
    if severity_counts["critical"] > 0:
        risk_level = "CRITICAL"
        risk_icon = "🔴"
    elif severity_counts["high"] > 0:
        risk_level = "HIGH"
        risk_icon = "🟠"
    elif severity_counts["medium"] > 0:
        risk_level = "MEDIUM"
        risk_icon = "🟡"
    else:
        risk_level = "LOW"
        risk_icon = "🟢"

    lines.extend([
        f"**Overall Risk Level:** {risk_icon} {risk_level}",
        "",
        f"**Total Issues Found:** {total}",
        "",
        "### Summary by Severity",
        ""
    ])

    if severity_counts["critical"] > 0:
        lines.append(f"- 🔴 **Critical:** {severity_counts['critical']} issue(s) - Immediate action required")
    if severity_counts["high"] > 0:
        lines.append(f"- 🟠 **High:** {severity_counts['high']} issue(s) - Address within 24-48 hours")
    if severity_counts["medium"] > 0:
        lines.append(f"- 🟡 **Medium:** {severity_counts['medium']} issue(s) - Address within 1 week")
    if severity_counts["low"] > 0:
        lines.append(f"- 🟢 **Low:** {severity_counts['low']} issue(s) - Address during next maintenance cycle")

    lines.extend([
        "",
        "### Manager Summaries",
        ""
    ])

    # Include unique manager summaries
    seen_summaries = set()
    for finding in findings:
        explanation = finding.get("explanation", {})
        summary = explanation.get("manager_summary", "")
        if summary and summary not in seen_summaries:
            lines.append(f"- {summary}")
            seen_summaries.add(summary)

    lines.extend([
        "",
        "---",
        ""
    ])

    return lines


def _generate_severity_breakdown(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate severity breakdown by resource type."""
    if not findings:
        return []

    lines = [
        "## Findings by Resource Type",
        ""
    ]

    # Group by resource type
    by_resource_type = {}
    for finding in findings:
        resource_type = finding.get("resource_type", "unknown")
        if resource_type not in by_resource_type:
            by_resource_type[resource_type] = []
        by_resource_type[resource_type].append(finding)

    # Create table
    lines.extend([
        "| Resource Type | Critical | High | Medium | Low | Total |",
        "|--------------|----------|------|--------|-----|-------|"
    ])

    for resource_type, type_findings in sorted(by_resource_type.items()):
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in type_findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        total = len(type_findings)
        resource_display = resource_type.replace("_", " ").title()

        lines.append(
            f"| {resource_display} | {severity_counts['critical']} | "
            f"{severity_counts['high']} | {severity_counts['medium']} | "
            f"{severity_counts['low']} | {total} |"
        )

    lines.extend([
        "",
        "---",
        ""
    ])

    return lines


def _generate_developer_checklist(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate developer checklist section."""
    if not findings:
        return []

    lines = [
        "## Developer Checklist",
        "",
        "Use this checklist to track remediation progress:",
        ""
    ]

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 2)
    )

    for i, finding in enumerate(sorted_findings, 1):
        severity = finding.get("severity", "medium").upper()
        resource_id = finding.get("resource_id", "unknown")
        issue = finding.get("issue", "Security issue")

        # Severity emoji
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(severity, "⚪")

        lines.append(f"- [ ] {severity_emoji} **[{severity}]** {resource_id}: {issue}")

    lines.extend([
        "",
        "---",
        ""
    ])

    return lines


def _generate_detailed_findings(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate detailed findings section."""
    if not findings:
        return [
            "## Detailed Findings",
            "",
            "No security issues detected.",
            ""
        ]

    lines = [
        "## Detailed Findings",
        ""
    ]

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 2)
    )

    for i, finding in enumerate(sorted_findings, 1):
        lines.extend(_format_finding(i, finding))

    return lines


def _format_finding(index: int, finding: Dict[str, Any]) -> List[str]:
    """Format a single finding for the report."""
    severity = finding.get("severity", "medium").upper()
    resource_type = finding.get("resource_type", "unknown").replace("_", " ").title()
    resource_id = finding.get("resource_id", "unknown")
    issue = finding.get("issue", "Security issue detected")
    finding_id = finding.get("id", "N/A")

    # Severity emoji
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }.get(severity, "⚪")

    lines = [
        f"### {index}. {severity_emoji} {resource_type}: {resource_id}",
        "",
        f"**Severity:** {severity}  ",
        f"**Issue:** {issue}  ",
        f"**Finding ID:** `{finding_id}`",
        ""
    ]

    # Add explanation if available
    explanation = finding.get("explanation", {})

    if explanation.get("developer_explanation"):
        lines.extend([
            "#### Technical Details",
            "",
            explanation["developer_explanation"],
            ""
        ])

    if explanation.get("remediation_steps"):
        lines.extend([
            "#### Remediation Steps",
            "",
            explanation["remediation_steps"],
            ""
        ])

    lines.extend([
        "---",
        ""
    ])

    return lines
