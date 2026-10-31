"""
CloudGuard — AWS Cloud Provider

Orchestrates all AWS collectors to discover resources using real boto3 API calls.
Requires valid AWS credentials in environment or ~/.aws/credentials.

Performance: Collectors run in parallel using ThreadPoolExecutor since each
collector makes independent I/O-bound AWS API calls. This typically reduces
total scan time by 3-4x compared to sequential execution.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from core.providers.base import CloudProvider, CloudResource, DiscoveryResult
from core.utils.logging import get_logger

log = get_logger(__name__)

# Maximum concurrent collector threads. Each collector creates its own
# boto3 client which is thread-safe. Keep this ≤ number of collectors
# to avoid unnecessary thread overhead.
_MAX_COLLECTOR_WORKERS = 4


class AWSProvider(CloudProvider):
    """
    Real AWS cloud provider using boto3.

    Requires AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or
    an IAM role attached to the running compute, or ~/.aws/credentials.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        role_arn: Optional[str] = None,
        role_session_name: Optional[str] = None,
        external_id: Optional[str] = None,
    ) -> None:
        self._region = region
        self._profile = profile
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._role_arn = role_arn
        self._role_session_name = role_session_name
        self._external_id = external_id
        self._session: Optional[boto3.Session] = None
        self._account_id: Optional[str] = None

    def _get_session(self) -> boto3.Session:
        if self._session is None:
            kwargs: Dict[str, Any] = {"region_name": self._region}
            if self._profile:
                kwargs["profile_name"] = self._profile
            if self._access_key_id and self._secret_access_key:
                kwargs["aws_access_key_id"] = self._access_key_id
                kwargs["aws_secret_access_key"] = self._secret_access_key
            base_session = boto3.Session(**kwargs)

            # If target STS Role ARN is provided, assume role for temporary session credentials
            if self._role_arn:
                log.info("aws_assuming_role", role_arn=self._role_arn)
                sts_client = base_session.client("sts")
                assume_args: Dict[str, Any] = {
                    "RoleArn": self._role_arn,
                    "RoleSessionName": self._role_session_name or "CloudGuardAuditSession",
                }
                if self._external_id:
                    assume_args["ExternalId"] = self._external_id
                assumed_role = sts_client.assume_role(**assume_args)
                creds = assumed_role["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self._region,
                )
            else:
                self._session = base_session
        return self._session

    @property
    def provider_name(self) -> str:
        return "aws"

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            self._account_id = self._fetch_account_id()
        return self._account_id

    def _fetch_account_id(self) -> str:
        try:
            sts = self._get_session().client("sts")
            identity = sts.get_caller_identity()
            return identity["Account"]
        except Exception as exc:
            log.warning("aws_account_id_fetch_failed", error=str(exc))
            return "unknown"

    def validate_connection(self) -> bool:
        """Verify AWS credentials are valid by calling STS GetCallerIdentity."""
        try:
            session = self._get_session()
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
            log.info(
                "aws_connection_valid",
                account_id=self._account_id,
                arn=identity.get("Arn", ""),
            )
            return True
        except NoCredentialsError:
            raise ConnectionError(
                "No AWS credentials found. Set AWS_ACCESS_KEY_ID and "
                "AWS_SECRET_ACCESS_KEY, or configure an IAM role, or use "
                "AWS CLI profiles. Alternatively, set CLOUDGUARD_MODE=demo."
            )
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            raise ConnectionError(
                f"AWS credential validation failed [{error_code}]: {exc}. "
                "Check that your credentials have the sts:GetCallerIdentity permission."
            )

    def discover(self, regions: Optional[List[str]] = None) -> DiscoveryResult:
        """
        Discover all supported AWS resources across specified regions.

        Collectors run in parallel for maximum throughput. Each collector
        creates its own boto3 client (thread-safe by design).

        Args:
            regions: List of AWS regions to scan. Defaults to [self._region].
        """
        scan_regions = regions or [self._region]
        session = self._get_session()
        account_id = self.account_id

        log.info(
            "aws_discovery_started",
            account_id=account_id,
            regions=scan_regions,
        )

        resources: List[CloudResource] = []
        errors: List[Dict[str, Any]] = []

        # Import collectors here to avoid circular imports at module load
        from core.providers.aws.collectors.s3 import S3Collector
        from core.providers.aws.collectors.iam import IAMCollector
        from core.providers.aws.collectors.sg import SecurityGroupCollector
        from core.providers.aws.collectors.lambda_ import LambdaCollector

        collectors = [
            S3Collector(session, account_id),
            IAMCollector(session, account_id),
            SecurityGroupCollector(session, account_id, regions=scan_regions),
            LambdaCollector(session, account_id, regions=scan_regions),
        ]

        # ── Parallel collection ───────────────────────────────────────────
        # Each collector makes independent AWS API calls (S3, IAM, EC2, Lambda).
        # Running them concurrently cuts total wall-clock time from the sum of
        # all collector durations to approximately the duration of the slowest one.
        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=_MAX_COLLECTOR_WORKERS) as executor:
            future_to_collector = {
                executor.submit(collector.collect): collector
                for collector in collectors
            }

            for future in as_completed(future_to_collector):
                collector = future_to_collector[future]
                collector_name = type(collector).__name__
                try:
                    collected = future.result()
                    resources.extend(collected)
                    log.info(
                        "aws_collector_completed",
                        collector=collector_name,
                        count=len(collected),
                    )
                except Exception as exc:
                    error_info = {
                        "collector": collector_name,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    }
                    errors.append(error_info)
                    log.error("aws_collector_failed", **error_info, exc_info=True)

        elapsed = round(time.monotonic() - t0, 2)
        log.info(
            "aws_discovery_completed",
            account_id=account_id,
            resource_count=len(resources),
            error_count=len(errors),
            elapsed_seconds=elapsed,
        )

        return DiscoveryResult(
            provider=self.provider_name,
            account_id=account_id,
            regions=scan_regions,
            resources=resources,
            errors=errors,
            completed_at=datetime.now(timezone.utc),
        )
