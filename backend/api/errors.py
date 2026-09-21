"""
CloudGuard — API Error Handling

Provides consistent structured error responses.

Rules:
  - Never expose stack traces to API consumers
  - Never expose AWS credentials, API keys, or secrets
  - Never expose internal filesystem paths
  - All errors include a request_id for tracing
  - Error codes are human-readable and stable
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from core.utils.logging import get_logger

log = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Error Codes
# ──────────────────────────────────────────────────────────────────────────────

class ErrorCode:
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SCAN_FAILED = "SCAN_FAILED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    AWS_AUTH_FAILED = "AWS_AUTH_FAILED"
    AWS_PERMISSION_DENIED = "AWS_PERMISSION_DENIED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_SCENARIO = "INVALID_SCENARIO"
    INVALID_FILTER = "INVALID_FILTER"


# ──────────────────────────────────────────────────────────────────────────────
# CloudGuard Exception Types
# ──────────────────────────────────────────────────────────────────────────────

class CloudGuardAPIError(HTTPException):
    """Base class for all CloudGuard API errors."""

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> None:
        self.error_code = error_code
        self.cg_message = message
        self.cg_details = details
        self.request_id = request_id or str(uuid.uuid4())[:8]
        super().__init__(
            status_code=status_code,
            detail={
                "error_code": error_code,
                "message": message,
                "request_id": self.request_id,
                "details": details,
            },
        )


class NotFoundError(CloudGuardAPIError):
    def __init__(self, resource_type: str, resource_id: str, request_id: Optional[str] = None):
        super().__init__(
            status_code=404,
            error_code=ErrorCode.NOT_FOUND,
            message=f"{resource_type} '{resource_id}' not found.",
            request_id=request_id,
        )


class InvalidScenarioError(CloudGuardAPIError):
    def __init__(self, scenario: str, available: list, request_id: Optional[str] = None):
        super().__init__(
            status_code=400,
            error_code=ErrorCode.INVALID_SCENARIO,
            message=f"Unknown demo scenario '{scenario}'.",
            details={"available_scenarios": available},
            request_id=request_id,
        )


class AWSAuthError(CloudGuardAPIError):
    def __init__(self, request_id: Optional[str] = None):
        super().__init__(
            status_code=403,
            error_code=ErrorCode.AWS_AUTH_FAILED,
            message=(
                "AWS credential validation failed. "
                "Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set, "
                "or switch to DEMO mode with CLOUDGUARD_MODE=demo."
            ),
            request_id=request_id,
        )


class ScanFailedError(CloudGuardAPIError):
    def __init__(self, message: str = "Scan execution failed.", request_id: Optional[str] = None):
        super().__init__(
            status_code=500,
            error_code=ErrorCode.SCAN_FAILED,
            message=message,
            request_id=request_id,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Global Exception Handlers
# ──────────────────────────────────────────────────────────────────────────────

async def cloudguard_exception_handler(request: Request, exc: CloudGuardAPIError) -> JSONResponse:
    """Handler for CloudGuardAPIError — returns clean structured JSON."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "message": exc.cg_message,
            "request_id": exc.request_id,
            "details": exc.cg_details,
        },
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handler for standard FastAPI HTTPException — normalises to CloudGuard format."""
    request_id = str(uuid.uuid4())[:8]
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": "HTTP_ERROR",
            "message": str(detail),
            "request_id": request_id,
            "details": None,
        },
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all for unhandled exceptions.
    Logs the full error internally but returns a safe generic message to callers.
    """
    request_id = str(uuid.uuid4())[:8]
    log.error(
        "unhandled_exception",
        request_id=request_id,
        path=str(request.url.path),
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error_code": ErrorCode.INTERNAL_ERROR,
            "message": "An unexpected error occurred. Please check logs with the request_id.",
            "request_id": request_id,
            "details": None,
        },
    )


def _sanitize_for_client(message: str) -> str:
    """Strip any accidental credential/path leakage from error messages."""
    import re
    message = re.sub(r'AKIA[0-9A-Z]{16}', '[KEY_REDACTED]', message)
    message = re.sub(r'(?i)secret.{0,5}=\S+', '[SECRET_REDACTED]', message)
    # Strip Windows/Unix paths that might expose filesystem layout
    message = re.sub(r'[A-Za-z]:\\[\\A-Za-z0-9_. -]+', '[PATH_REDACTED]', message)
    message = re.sub(r'/home/[^\s]+', '[PATH_REDACTED]', message)
    return message
