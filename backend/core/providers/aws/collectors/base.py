"""
CloudGuard — AWS Collector Base Class

Provides common patterns for all AWS collectors:
  - Structured logging
  - Error handling (per-call, per-region)
  - Retry via @aws_retry decorator
  - Normalized CloudResource construction
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import boto3

from core.providers.base import CloudResource
from core.utils.logging import get_logger
from core.utils.retry import aws_retry


class AWSCollector(ABC):
    """
    Abstract base for all AWS resource collectors.

    Subclasses implement collect() to call AWS APIs and return
    a list of normalized CloudResource objects.
    """

    def __init__(
        self,
        session: boto3.Session,
        account_id: str,
        regions: Optional[List[str]] = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.regions = regions or []
        self.log = get_logger(type(self).__name__)

    def client(self, service: str, region: Optional[str] = None) -> Any:
        """Get a boto3 client for the given service."""
        kwargs: Dict[str, Any] = {}
        if region:
            kwargs["region_name"] = region
        return self.session.client(service, **kwargs)

    @abstractmethod
    def collect(self) -> List[CloudResource]:
        """
        Collect resources from AWS and return normalized CloudResource objects.

        Implementations should:
          - Catch and log individual API errors without aborting the entire run.
          - Use @aws_retry for retryable operations.
          - Return partial results on failure rather than raising.
        """
        ...

    def _safe_collect(
        self,
        operation_name: str,
        fn,
        *args,
        **kwargs,
    ) -> Optional[Any]:
        """
        Execute an AWS API call safely, logging errors without raising.

        Returns the result, or None on failure.
        """
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            self.log.warning(
                "aws_api_call_failed",
                operation=operation_name,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None
