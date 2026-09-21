"""
CloudGuard — Server-Controlled Tool Dispatcher (Phase 8)

Controls all tool execution server-side.
The AI provider has ZERO direct execution capabilities.
Validates requests against the strict allowlist, validates input schemas with extra='forbid',
enforces output byte limits, and records append-only audit events.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Tuple
from sqlalchemy.orm import Session
from pydantic import ValidationError

from core.ai.tools.registry import READ_ONLY_TOOL_REGISTRY
from core.db_models import AIToolEventDBModel
from config.settings import settings
from core.utils.logging import get_logger

log = get_logger(__name__)


class ServerToolDispatcher:
    """
    Server-side dispatcher for AI-requested tool execution.
    """

    def __init__(self, session: Session, run_id: str):
        self.session = session
        self.run_id = run_id

    def execute_tool(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any], str]:
        """
        Executes a declarative tool request from an AI provider.

        Returns:
            Tuple of (success: bool, result_or_error: Dict, error_category: str)
        """
        start_time = time.monotonic()
        event_id = str(uuid.uuid4())

        # 1. Allowlist Validation
        tool = READ_ONLY_TOOL_REGISTRY.get(tool_name)
        if not tool:
            log.warning("unauthorized_tool_rejected", tool_name=tool_name, run_id=self.run_id)
            err_dict = {"error": f"Tool '{tool_name}' is not in the approved read-only tool allowlist."}
            self._record_event(
                event_id=event_id,
                tool_name=tool_name,
                status="BLOCKED",
                input_summary=self._sanitize_summary(arguments),
                output_summary=err_dict,
                error_category="tool_not_allowed",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
            return False, err_dict, "tool_not_allowed"

        # 2. Input Schema Validation (extra='forbid')
        try:
            validated_args = tool.input_schema(**arguments).model_dump()
        except ValidationError as val_err:
            log.warning("tool_parameter_validation_failed", tool_name=tool_name, errors=str(val_err))
            err_dict = {"error": "Invalid tool arguments.", "details": val_err.errors()}
            self._record_event(
                event_id=event_id,
                tool_name=tool_name,
                status="FAILED",
                input_summary=self._sanitize_summary(arguments),
                output_summary={"error": "Parameter schema validation failed."},
                error_category="tool_validation_failed",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
            return False, err_dict, "tool_validation_failed"

        # 3. Read-Only Execution
        try:
            raw_result = tool.handler(self.session, validated_args)
            success = True
            error_cat = ""
            status = "SUCCESS"
        except Exception as exc:
            log.error("tool_execution_failed", tool_name=tool_name, error=type(exc).__name__)
            raw_result = {"error": f"Execution error in tool '{tool_name}'."}
            success = False
            error_cat = "tool_execution_failed"
            status = "FAILED"

        # 4. Enforce Output Limit
        serialized = json.dumps(raw_result)
        max_bytes = settings.max_ai_tool_output_bytes
        if len(serialized.encode("utf-8")) > max_bytes:
            log.warning("tool_output_truncated", tool_name=tool_name, size=len(serialized))
            raw_result = {
                "truncated": True,
                "warning": f"Tool output exceeded limit of {max_bytes} bytes.",
                "sample": serialized[:1024] + " ... [TRUNCATED]",
            }

        # 5. Persist Audit Event
        duration_ms = int((time.monotonic() - start_time) * 1000)
        self._record_event(
            event_id=event_id,
            tool_name=tool_name,
            status=status,
            input_summary=self._sanitize_summary(validated_args),
            output_summary=self._sanitize_summary(raw_result),
            error_category=error_cat if not success else None,
            duration_ms=duration_ms,
        )

        return success, raw_result, error_cat

    def _record_event(
        self,
        event_id: str,
        tool_name: str,
        status: str,
        input_summary: Dict[str, Any],
        output_summary: Dict[str, Any],
        error_category: str | None,
        duration_ms: int,
    ) -> None:
        try:
            sanitized_input = self._sanitize_summary(input_summary)
            sanitized_output = self._sanitize_summary(output_summary)
            event = AIToolEventDBModel(
                event_id=event_id,
                run_id=self.run_id,
                tool_name=tool_name,
                status=status,
                input_summary=sanitized_input,
                output_summary=sanitized_output,
                error_category=error_category,
                duration_ms=duration_ms,
            )
            self.session.add(event)
            self.session.flush()
        except Exception as exc:
            log.error("failed_to_record_tool_event", error=str(exc))
            self.session.rollback()

    def _sanitize_summary(self, data: Any) -> Dict[str, Any]:
        """Ensures serialized summary does not leak secrets or exceed safe length."""
        if not isinstance(data, dict):
            return {"summary": str(data)[:512]}
        sanitized = {}
        for k, v in data.items():
            if any(s in k.lower() for s in ("secret", "token", "password", "key", "auth", "pass")):
                sanitized[k] = "[MASKED]"
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize_summary(v)
            elif isinstance(v, list):
                sanitized[k] = [self._sanitize_summary(i) if isinstance(i, dict) else str(i)[:128] for i in v]
            elif isinstance(v, str):
                from core.ai.masking import _redact_inline_secrets
                sanitized[k] = _redact_inline_secrets(v)
            else:
                sanitized[k] = str(v)[:256]
        return sanitized
