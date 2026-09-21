"""
Comprehensive logging utility for CloudGuard Copilot.
Saves detailed scan logs including resources, policies, and findings.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import os


class ScanLogger:
    """
    Comprehensive logger for security scans.

    Saves detailed logs including:
    - Scan metadata
    - All collected resources with full configurations
    - All policies and configurations
    - Detection findings
    - AI explanations
    """

    def __init__(self, output_dir: str = "logs"):
        """
        Initialize scan logger.

        Args:
            output_dir: Directory to save log files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate timestamp for this scan
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_timestamp = datetime.now().isoformat()

        # Log file paths
        self.detailed_log_file = self.output_dir / f"scan_{self.scan_id}_detailed.json"
        self.summary_log_file = self.output_dir / f"scan_{self.scan_id}_summary.txt"
        self.resources_log_file = self.output_dir / f"scan_{self.scan_id}_resources.json"

        # Scan data
        self.scan_data = {
            "scan_id": self.scan_id,
            "scan_timestamp": self.scan_timestamp,
            "scan_completed_at": None,
            "aws_account": None,
            "aws_identity": None,
            "regions_scanned": [],
            "resources": {},
            "findings": [],
            "statistics": {}
        }

        self.logger = logging.getLogger(__name__)

    def log_scan_start(self, aws_identity: Dict[str, Any] = None, regions: List[str] = None):
        """
        Log scan start with AWS identity information.

        Args:
            aws_identity: AWS STS GetCallerIdentity response
            regions: List of regions being scanned
        """
        if aws_identity:
            self.scan_data["aws_account"] = aws_identity.get("Account")
            self.scan_data["aws_identity"] = aws_identity.get("Arn")

        if regions:
            self.scan_data["regions_scanned"] = regions
        else:
            self.scan_data["regions_scanned"] = ["all"]

        self.logger.info(f"Scan started: {self.scan_id}")
        self.logger.info(f"AWS Account: {self.scan_data['aws_account']}")
        self.logger.info(f"Identity: {self.scan_data['aws_identity']}")

    def log_resources(self, resources: Dict[str, List[Dict[str, Any]]]):
        """
        Log all collected resources with full configurations.

        Args:
            resources: Dictionary of resource types to resource lists
        """
        self.scan_data["resources"] = resources

        # Calculate statistics
        stats = {}
        for resource_type, resource_list in resources.items():
            stats[resource_type] = {
                "count": len(resource_list),
                "resource_ids": [r.get("resource_id") for r in resource_list]
            }

        self.scan_data["statistics"]["resources"] = stats

        # Save detailed resources to separate file
        with open(self.resources_log_file, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_id": self.scan_id,
                "scan_timestamp": self.scan_timestamp,
                "resources": resources
            }, f, indent=2, default=str)

        self.logger.info(f"Resources logged to {self.resources_log_file}")

    def log_findings(self, findings: List[Dict[str, Any]]):
        """
        Log all security findings.

        Args:
            findings: List of finding dictionaries
        """
        self.scan_data["findings"] = findings

        # Calculate severity statistics
        severity_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        resource_type_stats = {}

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_stats:
                severity_stats[severity] += 1

            resource_type = finding.get("resource_type", "unknown")
            resource_type_stats[resource_type] = resource_type_stats.get(resource_type, 0) + 1

        self.scan_data["statistics"]["findings"] = {
            "total": len(findings),
            "by_severity": severity_stats,
            "by_resource_type": resource_type_stats
        }

        self.logger.info(f"Findings logged: {len(findings)} total")
        self.logger.info(f"Severity breakdown: {severity_stats}")

    def log_explanations(self, enriched_findings: Dict[str, Dict[str, Any]]):
        """
        Log AI-generated explanations.

        Args:
            enriched_findings: Dictionary mapping finding IDs to explanations
        """
        # Add explanations to findings
        for finding in self.scan_data["findings"]:
            finding_id = finding.get("id")
            if finding_id in enriched_findings:
                finding["explanation"] = enriched_findings[finding_id]

        self.logger.info(f"Explanations added: {len(enriched_findings)} findings")

    def log_scan_complete(self):
        """Mark scan as complete and save all logs."""
        self.scan_data["scan_completed_at"] = datetime.now().isoformat()

        # Save detailed JSON log
        with open(self.detailed_log_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_data, f, indent=2, default=str)

        # Save summary text log
        self._save_summary_log()

        self.logger.info(f"Scan complete: {self.scan_id}")
        self.logger.info(f"Detailed log: {self.detailed_log_file}")
        self.logger.info(f"Summary log: {self.summary_log_file}")

    def _save_summary_log(self):
        """Save human-readable summary log."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("CloudGuard Copilot - Security Scan Summary")
        lines.append("=" * 80)
        lines.append("")

        # Scan metadata
        lines.append(f"Scan ID: {self.scan_id}")
        lines.append(f"Started: {self.scan_timestamp}")
        lines.append(f"Completed: {self.scan_data['scan_completed_at']}")
        lines.append(f"AWS Account: {self.scan_data['aws_account']}")
        lines.append(f"AWS Identity: {self.scan_data['aws_identity']}")
        lines.append(f"Regions Scanned: {', '.join(self.scan_data['regions_scanned'])}")
        lines.append("")

        # Resource statistics
        lines.append("-" * 80)
        lines.append("Resources Collected")
        lines.append("-" * 80)

        resource_stats = self.scan_data["statistics"].get("resources", {})
        total_resources = sum(s.get("count", 0) for s in resource_stats.values())

        lines.append(f"Total Resources: {total_resources}")
        lines.append("")

        for resource_type, stats in resource_stats.items():
            lines.append(f"  {resource_type.replace('_', ' ').title()}: {stats['count']}")
            for resource_id in stats['resource_ids'][:10]:  # Show first 10
                lines.append(f"    - {resource_id}")
            if len(stats['resource_ids']) > 10:
                lines.append(f"    ... and {len(stats['resource_ids']) - 10} more")
            lines.append("")

        # Findings statistics
        lines.append("-" * 80)
        lines.append("Security Findings")
        lines.append("-" * 80)

        finding_stats = self.scan_data["statistics"].get("findings", {})
        severity_stats = finding_stats.get("by_severity", {})
        resource_type_stats = finding_stats.get("by_resource_type", {})

        lines.append(f"Total Findings: {finding_stats.get('total', 0)}")
        lines.append("")

        lines.append("By Severity:")
        lines.append(f"  🔴 Critical: {severity_stats.get('critical', 0)}")
        lines.append(f"  🟠 High: {severity_stats.get('high', 0)}")
        lines.append(f"  🟡 Medium: {severity_stats.get('medium', 0)}")
        lines.append(f"  🟢 Low: {severity_stats.get('low', 0)}")
        lines.append("")

        lines.append("By Resource Type:")
        for resource_type, count in resource_type_stats.items():
            lines.append(f"  {resource_type.replace('_', ' ').title()}: {count}")
        lines.append("")

        # Detailed findings
        if self.scan_data["findings"]:
            lines.append("-" * 80)
            lines.append("Detailed Findings")
            lines.append("-" * 80)
            lines.append("")

            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_findings = sorted(
                self.scan_data["findings"],
                key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 2)
            )

            for idx, finding in enumerate(sorted_findings, 1):
                severity = finding.get("severity", "medium").upper()
                resource_type = finding.get("resource_type", "unknown").replace("_", " ").title()
                resource_id = finding.get("resource_id", "unknown")
                issue = finding.get("issue", "Security issue detected")
                finding_id = finding.get("id")

                lines.append(f"{idx}. [{severity}] {resource_type}: {resource_id}")
                lines.append(f"   Issue: {issue}")
                lines.append(f"   Finding ID: {finding_id}")

                # Add explanation if available
                if "explanation" in finding:
                    explanation = finding["explanation"]
                    lines.append(f"   Developer Explanation: {explanation.get('developer_explanation', 'N/A')[:200]}...")

                lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append(f"Log Files:")
        lines.append(f"  Detailed JSON: {self.detailed_log_file}")
        lines.append(f"  Resources JSON: {self.resources_log_file}")
        lines.append(f"  Summary Text: {self.summary_log_file}")
        lines.append("=" * 80)

        # Write to file
        with open(self.summary_log_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def get_log_files(self) -> Dict[str, Path]:
        """
        Get paths to all log files.

        Returns:
            Dictionary of log file names to paths
        """
        return {
            "detailed_json": self.detailed_log_file,
            "summary_text": self.summary_log_file,
            "resources_json": self.resources_log_file
        }


def cleanup_old_logs(output_dir: str = "logs", keep_days: int = 30):
    """
    Clean up old log files.

    Args:
        output_dir: Directory containing log files
        keep_days: Number of days to keep logs (default: 30)
    """
    log_dir = Path(output_dir)
    if not log_dir.exists():
        return

    import time
    cutoff_time = time.time() - (keep_days * 24 * 60 * 60)

    deleted_count = 0
    for log_file in log_dir.glob("scan_*"):
        if log_file.stat().st_mtime < cutoff_time:
            log_file.unlink()
            deleted_count += 1

    if deleted_count > 0:
        logging.getLogger(__name__).info(f"Cleaned up {deleted_count} old log files")
