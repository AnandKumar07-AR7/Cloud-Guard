"""
CloudGuard — Structured Logging Utilities

Uses structlog for JSON-formatted structured logging.
All log records include a correlation_id for request tracing.
"""
from __future__ import annotations

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog

# Context variable to propagate correlation IDs across async call stacks
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

# Track whether we've configured structlog so we never configure twice
_configured: bool = False


def get_correlation_id() -> str:
    """Return the current correlation ID, or generate one if absent."""
    cid = _correlation_id.get()
    if not cid:
        cid = str(uuid.uuid4())[:8]
        _correlation_id.set(cid)
    return cid


def set_correlation_id(cid: str) -> None:
    """Set the correlation ID for the current context."""
    _correlation_id.set(cid)


def new_correlation_id() -> str:
    """Generate and set a fresh correlation ID."""
    cid = str(uuid.uuid4())[:8]
    _correlation_id.set(cid)
    return cid


def _add_logger_name_safe(logger, method_name, event_dict):
    """
    Safe replacement for structlog.stdlib.add_logger_name.

    structlog.stdlib.add_logger_name requires a stdlib Logger which has a
    .name attribute. When using PrintLoggerFactory the logger is a
    PrintLogger which has no .name, causing AttributeError.

    This processor safely adds the logger name without assuming the
    underlying logger type.
    """
    name = getattr(logger, "name", None)
    if name is not None:
        event_dict["logger"] = name
    return event_dict


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """
    Configure structlog for the application.

    This function is idempotent — calling it multiple times (e.g., from
    pytest conftest and from main.py) is safe because of the _configured
    guard.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        fmt:   Output format. "json" for structured JSON, "text" for console.
    """
    global _configured
    if _configured:
        return
    _configured = True

    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        _add_logger_name_safe,           # safe for PrintLogger
        structlog.processors.format_exc_info,
    ]

    if fmt == "json":
        processors = shared_processors + [structlog.processors.JSONRenderer()]
    else:
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=False)  # colors=False for Windows
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so boto3/botocore logs are captured.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    # Quiet noisy libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a bound structlog logger with correlation_id automatically injected.

    Usage:
        log = get_logger(__name__)
        log.info("scan_started", scan_id="abc123", resource_count=42)
    """
    return structlog.get_logger(name)
