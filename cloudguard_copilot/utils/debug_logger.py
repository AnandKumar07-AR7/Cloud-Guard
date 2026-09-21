"""
Debug logging utility for CloudGuard Copilot.
Logs all internal operations, API calls, data transformations, and LLM interactions.
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import sys


class DebugLogger:
    """
    Comprehensive debug logger that traces all operations.

    Logs:
    - AWS API raw responses
    - Data parsing and normalization steps
    - Detection logic decisions
    - LLM prompts and responses
    - All data transformations
    """

    def __init__(self, log_dir: str = "logs/debug", enable_console: bool = True):
        """
        Initialize debug logger.

        Args:
            log_dir: Directory for debug log files
            enable_console: Whether to also log to console
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create timestamped log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"debug_{timestamp}.log"

        # Setup logger
        self.logger = logging.getLogger(f"cloudguard_debug_{timestamp}")
        self.logger.setLevel(logging.DEBUG)

        # File handler with detailed format
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)

        # Detailed formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        # Console handler (optional)
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        self.logger.info("=" * 100)
        self.logger.info("DEBUG LOGGING SESSION STARTED")
        self.logger.info("=" * 100)

    def log_aws_api_call(self, service: str, operation: str, params: Dict = None):
        """Log AWS API call being made."""
        self.logger.info(f"AWS API CALL → {service}.{operation}")
        if params:
            self.logger.debug(f"  Parameters: {json.dumps(params, indent=2, default=str)}")

    def log_aws_api_response(self, service: str, operation: str, response: Any, truncate: bool = False):
        """Log AWS API response received."""
        self.logger.info(f"AWS API RESPONSE ← {service}.{operation}")

        if truncate and isinstance(response, (dict, list)):
            # Truncate large responses
            response_str = json.dumps(response, indent=2, default=str)
            if len(response_str) > 5000:
                self.logger.debug(f"  Response (truncated): {response_str[:5000]}... [TRUNCATED]")
            else:
                self.logger.debug(f"  Response: {response_str}")
        else:
            self.logger.debug(f"  Response: {json.dumps(response, indent=2, default=str)}")

    def log_resource_collection_start(self, resource_type: str, region: str = None):
        """Log start of resource collection."""
        region_info = f" in {region}" if region else ""
        self.logger.info(f"COLLECTING {resource_type.upper()}{region_info}")
        self.logger.info("-" * 80)

    def log_resource_collected(self, resource_type: str, resource_id: str, config: Dict):
        """Log individual resource collected."""
        self.logger.info(f"  ✓ Collected {resource_type}: {resource_id}")
        self.logger.debug(f"    Raw Config: {json.dumps(config, indent=4, default=str)}")

    def log_normalization(self, resource_type: str, raw_data: Dict, normalized_data: Dict):
        """Log data normalization process."""
        self.logger.info(f"NORMALIZING {resource_type}")
        self.logger.debug(f"  Before (raw): {json.dumps(raw_data, indent=4, default=str)}")
        self.logger.debug(f"  After (normalized): {json.dumps(normalized_data, indent=4, default=str)}")

    def log_detection_start(self, resource_type: str, resource_count: int):
        """Log start of misconfiguration detection."""
        self.logger.info(f"DETECTING MISCONFIGURATIONS in {resource_count} {resource_type}")
        self.logger.info("-" * 80)

    def log_detection_check(self, check_name: str, resource_id: str, passed: bool, details: str = None):
        """Log individual detection check."""
        status = "PASS ✓" if passed else "FAIL ✗"
        self.logger.info(f"  [{status}] {check_name} | {resource_id}")
        if details:
            self.logger.debug(f"    Details: {details}")

    def log_finding_created(self, finding: Dict):
        """Log creation of a security finding."""
        severity = finding.get("severity", "unknown").upper()
        resource_id = finding.get("resource_id", "unknown")
        issue = finding.get("issue", "unknown")

        self.logger.warning(f"FINDING CREATED [{severity}] {resource_id}")
        self.logger.warning(f"  Issue: {issue}")
        self.logger.debug(f"  Full Finding: {json.dumps(finding, indent=4, default=str)}")

    def log_llm_request_start(self, finding_id: str, resource_type: str):
        """Log start of LLM explanation request."""
        self.logger.info(f"LLM REQUEST START → Finding: {finding_id} ({resource_type})")
        self.logger.info("-" * 80)

    def log_llm_prompt(self, prompt: str):
        """Log the full LLM prompt being sent."""
        self.logger.info("LLM PROMPT:")
        self.logger.debug(f"\n{'-' * 80}\n{prompt}\n{'-' * 80}")

    def log_llm_config(self, config: Dict):
        """Log LLM configuration (model, temperature, etc)."""
        self.logger.info(f"LLM CONFIG: {json.dumps(config, indent=2)}")

    def log_llm_response_raw(self, response: str):
        """Log raw LLM response."""
        self.logger.info("LLM RESPONSE (RAW):")
        self.logger.debug(f"\n{'-' * 80}\n{response}\n{'-' * 80}")

    def log_llm_response_parsed(self, parsed: Dict):
        """Log parsed LLM response."""
        self.logger.info("LLM RESPONSE (PARSED):")
        self.logger.debug(f"{json.dumps(parsed, indent=2)}")

    def log_llm_error(self, error: Exception):
        """Log LLM error."""
        self.logger.error(f"LLM ERROR: {type(error).__name__}: {str(error)}")
        import traceback
        self.logger.debug(f"Traceback:\n{traceback.format_exc()}")

    def log_template_fallback(self, reason: str):
        """Log fallback to template-based explanation."""
        self.logger.warning(f"TEMPLATE FALLBACK: {reason}")

    def log_data_transformation(self, step: str, input_data: Any, output_data: Any):
        """Log data transformation step."""
        self.logger.info(f"DATA TRANSFORM: {step}")
        self.logger.debug(f"  Input: {json.dumps(input_data, indent=2, default=str)[:500]}...")
        self.logger.debug(f"  Output: {json.dumps(output_data, indent=2, default=str)[:500]}...")

    def log_statistics(self, stats: Dict):
        """Log statistics."""
        self.logger.info(f"STATISTICS: {json.dumps(stats, indent=2)}")

    def log_section_start(self, section_name: str):
        """Log start of a major section."""
        self.logger.info("")
        self.logger.info("=" * 100)
        self.logger.info(f"  {section_name.upper()}")
        self.logger.info("=" * 100)

    def log_section_end(self, section_name: str):
        """Log end of a major section."""
        self.logger.info("=" * 100)
        self.logger.info(f"  END {section_name.upper()}")
        self.logger.info("=" * 100)
        self.logger.info("")

    def log_error(self, operation: str, error: Exception):
        """Log error during operation."""
        self.logger.error(f"ERROR in {operation}: {type(error).__name__}: {str(error)}")
        import traceback
        self.logger.debug(f"Traceback:\n{traceback.format_exc()}")

    def log_custom(self, message: str, level: str = "INFO"):
        """Log custom message."""
        level_map = {
            "DEBUG": self.logger.debug,
            "INFO": self.logger.info,
            "WARNING": self.logger.warning,
            "ERROR": self.logger.error,
            "CRITICAL": self.logger.critical
        }
        log_func = level_map.get(level.upper(), self.logger.info)
        log_func(message)

    def get_log_file_path(self) -> Path:
        """Get path to the debug log file."""
        return self.log_file


# Global debug logger instance
_debug_logger = None


def get_debug_logger(enable: bool = True, console: bool = False) -> DebugLogger:
    """
    Get or create global debug logger.

    Args:
        enable: Whether to enable debug logging
        console: Whether to also log to console

    Returns:
        DebugLogger instance or None if disabled
    """
    global _debug_logger

    if not enable:
        return None

    if _debug_logger is None:
        _debug_logger = DebugLogger(enable_console=console)

    return _debug_logger


def enable_debug_logging(console: bool = False) -> DebugLogger:
    """
    Enable debug logging globally.

    Args:
        console: Whether to also log to console

    Returns:
        DebugLogger instance
    """
    return get_debug_logger(enable=True, console=console)
