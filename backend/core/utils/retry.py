"""
CloudGuard — Retry / Resilience Utilities

Provides tenacity-based retry decorators for AWS API calls.
All retries are logged for observability.
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Tuple, Type

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
    RetryError,
)
import logging

logger = logging.getLogger(__name__)

# Default exceptions that warrant a retry (AWS throttling / transient errors)
_DEFAULT_RETRY_EXCEPTIONS: Tuple[Type[Exception], ...] = ()

try:
    from botocore.exceptions import ClientError, EndpointResolutionError

    def _is_retryable_aws_error(exc: Exception) -> bool:
        """Return True for transient AWS errors worth retrying."""
        if isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            return code in {
                "Throttling",
                "ThrottlingException",
                "RequestLimitExceeded",
                "TooManyRequestsException",
                "ServiceUnavailable",
                "InternalError",
                "RequestTimeout",
            }
        return False

except ImportError:
    def _is_retryable_aws_error(exc: Exception) -> bool:  # type: ignore
        return False


def aws_retry(
    max_attempts: int = 3,
    wait_min: float = 1.0,
    wait_max: float = 10.0,
) -> Callable:
    """
    Decorator that retries AWS API calls on transient errors with exponential backoff.

    Args:
        max_attempts: Maximum number of total attempts (including first).
        wait_min:     Minimum wait in seconds between retries.
        wait_max:     Maximum wait in seconds between retries.

    Usage:
        @aws_retry(max_attempts=3)
        def my_aws_call():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            attempt = 0
            last_exc: Exception | None = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if not _is_retryable_aws_error(exc):
                        raise
                    import time
                    wait = min(wait_min * (2 ** attempt), wait_max)
                    logger.warning(
                        "AWS call failed (retryable), retrying",
                        extra={
                            "function": func.__name__,
                            "attempt": attempt + 1,
                            "max_attempts": max_attempts,
                            "wait_seconds": wait,
                            "error": str(exc),
                        },
                    )
                    time.sleep(wait)

            # Exhausted retries
            raise last_exc  # type: ignore

        return wrapper
    return decorator
