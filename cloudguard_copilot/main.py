"""
CloudGuard Copilot - Main entry point for AWS security scanning.
"""

import argparse
import logging
import sys
from typing import List, Dict, Any
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)
    logging.getLogger(__name__).debug(f"Loaded environment variables from {env_path}")

from cloudguard_copilot.collectors.aws import S3Collector, IAMCollector, SecurityGroupCollector, LambdaCollector
from cloudguard_copilot.detectors import (
    detect_s3_misconfigurations,
    detect_iam_misconfigurations,
    detect_sg_misconfigurations,
    detect_lambda_misconfigurations
)
from cloudguard_copilot.explainers import explain_finding
from cloudguard_copilot.reports import generate_json_report, generate_markdown_report


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the application.

    Args:
        verbose: Enable verbose (DEBUG) logging
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def collect_resources(session: boto3.Session, regions: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Collect all AWS resources.

    Args:
        session: boto3 Session object
        regions: List of AWS regions to scan for Security Groups

    Returns:
        Dictionary mapping resource types to collected resources
    """
    logger = logging.getLogger(__name__)

    logger.info("Starting AWS resource collection...")

    resources = {
        "s3_buckets": [],
        "iam_roles": [],
        "security_groups": [],
        "lambda_functions": []
    }

    # Collect S3 buckets
    try:
        logger.info("Collecting S3 buckets...")
        s3_collector = S3Collector(session)
        resources["s3_buckets"] = s3_collector.collect()
        logger.info(f"Collected {len(resources['s3_buckets'])} S3 buckets")
    except Exception as e:
        logger.error(f"Failed to collect S3 buckets: {e}")

    # Collect IAM roles
    try:
        logger.info("Collecting IAM roles...")
        iam_collector = IAMCollector(session)
        resources["iam_roles"] = iam_collector.collect()
        logger.info(f"Collected {len(resources['iam_roles'])} IAM roles")
    except Exception as e:
        logger.error(f"Failed to collect IAM roles: {e}")

    # Collect Security Groups
    try:
        logger.info("Collecting Security Groups...")
        sg_collector = SecurityGroupCollector(session, regions=regions)
        resources["security_groups"] = sg_collector.collect()
        logger.info(f"Collected {len(resources['security_groups'])} Security Groups")
    except Exception as e:
        logger.error(f"Failed to collect Security Groups: {e}")

    # Collect Lambda Functions
    try:
        logger.info("Collecting Lambda functions...")
        lambda_collector = LambdaCollector(session, regions=regions)
        resources["lambda_functions"] = lambda_collector.collect()
        logger.info(f"Collected {len(resources['lambda_functions'])} Lambda functions")
    except Exception as e:
        logger.error(f"Failed to collect Lambda functions: {e}")

    logger.info("Resource collection complete")
    return resources


def detect_misconfigurations(resources: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Run all detectors on collected resources.

    Args:
        resources: Dictionary of collected resources

    Returns:
        List of all findings
    """
    logger = logging.getLogger(__name__)

    logger.info("Running misconfiguration detectors...")

    all_findings = []

    # Detect S3 misconfigurations
    s3_findings = detect_s3_misconfigurations(resources.get("s3_buckets", []))
    all_findings.extend(s3_findings)

    # Detect IAM misconfigurations
    iam_findings = detect_iam_misconfigurations(resources.get("iam_roles", []))
    all_findings.extend(iam_findings)

    # Detect Security Group misconfigurations
    sg_findings = detect_sg_misconfigurations(resources.get("security_groups", []))
    all_findings.extend(sg_findings)

    # Detect Lambda misconfigurations
    lambda_findings = detect_lambda_misconfigurations(resources.get("lambda_functions", []))
    all_findings.extend(lambda_findings)

    logger.info(f"Detection complete: {len(all_findings)} total findings")
    return all_findings


def explain_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate explanations for all findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of findings with explanations added
    """
    logger = logging.getLogger(__name__)

    logger.info("Generating explanations for findings...")

    enriched_findings = []

    for finding in findings:
        explanation = explain_finding(finding)
        finding["explanation"] = explanation
        enriched_findings.append(finding)

    logger.info("Explanations generated")
    return enriched_findings


def generate_reports(findings: List[Dict[str, Any]], output_dir: str = "output") -> None:
    """
    Generate JSON and Markdown reports.

    Args:
        findings: List of findings with explanations
        output_dir: Directory to save reports
    """
    logger = logging.getLogger(__name__)

    logger.info("Generating reports...")

    # Generate JSON report
    json_path = f"{output_dir}/findings.json"
    generate_json_report(findings, json_path)

    # Generate Markdown report
    markdown_path = f"{output_dir}/report.md"
    generate_markdown_report(findings, markdown_path)

    logger.info("Reports generated successfully")


def verify_aws_credentials(session: boto3.Session) -> bool:
    """
    Verify AWS credentials are configured and valid.

    Args:
        session: boto3 Session object

    Returns:
        True if credentials are valid, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"AWS credentials verified for account: {identity['Account']}")
        logger.info(f"Using IAM identity: {identity['Arn']}")
        return True
    except NoCredentialsError:
        logger.error("No AWS credentials found. Please configure credentials using:")
        logger.error("  - AWS CLI: aws configure")
        logger.error("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        logger.error("  - IAM role (if running on EC2)")
        return False
    except ClientError as e:
        logger.error(f"AWS credential error: {e}")
        return False


def scan_aws(
    profile: str = None,
    regions: List[str] = None,
    output_dir: str = "output",
    verbose: bool = False
) -> int:
    """
    Execute full AWS security scan.

    Args:
        profile: AWS profile name to use
        regions: List of AWS regions to scan
        output_dir: Directory to save reports
        verbose: Enable verbose logging

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    print("=" * 60)
    print("CloudGuard Copilot - AWS Security Scanner")
    print("=" * 60)
    print()

    # Create boto3 session
    try:
        if profile:
            logger.info(f"Using AWS profile: {profile}")
            session = boto3.Session(profile_name=profile)
        else:
            logger.info("Using default AWS credentials")
            session = boto3.Session()
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        return 1

    # Verify credentials
    if not verify_aws_credentials(session):
        return 1

    print()

    try:
        # Step 1: Collect resources
        print("📦 Collecting AWS resources...")
        resources = collect_resources(session, regions)

        total_resources = sum(len(r) for r in resources.values())
        print(f"   Found {total_resources} total resources")
        print()

        # Step 2: Detect misconfigurations
        print("🔍 Scanning for misconfigurations...")
        findings = detect_misconfigurations(resources)

        if findings:
            print(f"   Found {len(findings)} security issues")
        else:
            print("   ✓ No security issues detected!")
        print()

        # Step 3: Generate explanations
        print("💡 Generating explanations...")
        enriched_findings = explain_findings(findings)
        print("   ✓ Explanations generated")
        print()

        # Step 4: Generate reports
        print("📄 Generating reports...")
        generate_reports(enriched_findings, output_dir)
        print()

        # Summary
        print("=" * 60)
        print("Scan Summary")
        print("=" * 60)
        print(f"Total resources scanned: {total_resources}")
        print(f"Total findings: {len(findings)}")

        if findings:
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in findings:
                severity = finding.get("severity", "medium").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            print()
            print("Findings by severity:")
            if severity_counts["critical"] > 0:
                print(f"  🔴 Critical: {severity_counts['critical']}")
            if severity_counts["high"] > 0:
                print(f"  🟠 High: {severity_counts['high']}")
            if severity_counts["medium"] > 0:
                print(f"  🟡 Medium: {severity_counts['medium']}")
            if severity_counts["low"] > 0:
                print(f"  🟢 Low: {severity_counts['low']}")

        print()
        print(f"Reports saved to: {output_dir}/")
        print("=" * 60)

        return 0

    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        print(f"\n❌ Scan failed: {e}")
        return 1


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="CloudGuard Copilot - AWS Security Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan AWS with default credentials
  python -m cloudguard_copilot.main --scan aws

  # Scan with specific profile
  python -m cloudguard_copilot.main --scan aws --profile my-profile

  # Scan specific regions only
  python -m cloudguard_copilot.main --scan aws --regions us-east-1 us-west-2

  # Enable verbose logging
  python -m cloudguard_copilot.main --scan aws --verbose
        """
    )

    parser.add_argument(
        "--scan",
        choices=["aws"],
        required=True,
        help="Cloud provider to scan (currently only 'aws' is supported)"
    )

    parser.add_argument(
        "--profile",
        type=str,
        help="AWS profile name to use (default: default profile)"
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        help="AWS regions to scan for Security Groups (default: all regions)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="output",
        help="Output directory for reports (default: output)"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.scan == "aws":
        exit_code = scan_aws(
            profile=args.profile,
            regions=args.regions,
            output_dir=args.output,
            verbose=args.verbose
        )
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
