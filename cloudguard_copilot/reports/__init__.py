"""
Report generators for scan results.
"""

from cloudguard_copilot.reports.json_report import generate_json_report
from cloudguard_copilot.reports.markdown_report import generate_markdown_report

__all__ = ["generate_json_report", "generate_markdown_report"]
