"""
JSON report generator for scan results.
"""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def generate_json_report(
    findings: List[Dict[str, Any]],
    output_path: str = "output/findings.json"
) -> None:
    """
    Generate a JSON report of all findings.

    Args:
        findings: List of finding dictionaries with explanations
        output_path: Path to write the JSON report
    """
    # Create output directory if it doesn't exist
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Build report structure
    report = {
        "scan_metadata": {
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "scanner_version": "0.1.0",
            "total_findings": len(findings)
        },
        "summary": _generate_summary(findings),
        "findings": findings
    }

    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"JSON report written to {output_path}")
    print(f"✓ JSON report saved: {output_path}")


def _generate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate summary statistics for findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        Summary dictionary with counts by severity and resource type
    """
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    resource_type_counts = {}

    for finding in findings:
        # Count by severity
        severity = finding.get("severity", "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

        # Count by resource type
        resource_type = finding.get("resource_type", "unknown")
        resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1

    return {
        "by_severity": severity_counts,
        "by_resource_type": resource_type_counts
    }
