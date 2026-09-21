"""
CloudGuard — MCP Gateway Layer (Phase 10)
Enforces security boundaries, RBAC authorization, schema validation,
rate limiting, timeout protection, response truncation, and tamper-evident auditing.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from pydantic import ValidationError
from sqlalchemy.orm import Session

from auth.models import UserDBModel
from auth.repository import RoleRepository, UserRepository
from config.settings import settings
import threading
from collections import defaultdict
from core.mcp.audit import log_mcp_event, sanitize_mcp_audit_details
from core.mcp.models import (
    MCPExecutionContext,
    MCPOperationClass,
    MCPServerStatus,
    MCPToolDefinition,
)
from core.mcp.servers.base import BaseCloudGuardMCPServer
from core.utils.logging import get_logger

log = get_logger(__name__)


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding window rate limiter for MCP Gateway."""

    def __init__(self, requests_per_minute: int = 60, window_seconds: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: Dict[str, list[float]] = defaultdict(list)

    def allow_request(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            timestamps = self._requests[key]
            cutoff = now - self.window_seconds
            valid = [ts for ts in timestamps if ts > cutoff]
            self._requests[key] = valid
            if len(valid) >= self.requests_per_minute:
                return False
            self._requests[key].append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()


class MCPGateway:
    """
    Central gateway through which all MCP invocations must pass.
    Guarantees that MCP cannot bypass authentication, RBAC, policy, or audit controls.
    """

    def __init__(self, registry=None):
        from core.mcp.registry import MCPRegistryService
        self.registry = registry or MCPRegistryService()
        self.rate_limiter = InMemoryRateLimiter(
            requests_per_minute=getattr(settings, "mcp_rate_limit_per_minute", 60)
        )
        self.max_output_bytes = getattr(settings, "max_ai_tool_output_bytes", 65536)

    def invoke_tool(
        self,
        session: Session,
        server_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        user: Optional[UserDBModel] = None,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Executes an MCP tool through all security boundaries.

        Returns:
            Tuple of (success: bool, data_or_none: Dict, error_message_or_none: str)
        """
        start_time = time.monotonic()
        req_id = request_id or str(uuid.uuid4())
        corr_id = correlation_id or str(uuid.uuid4())
        user_id = user.user_id if user else None
        role_name = user.role.name if user and user.role else "ANONYMOUS"

        # 1. Rate Limiting Check
        rate_key = user_id or "anonymous"
        if not self.rate_limiter.allow_request(rate_key):
            log.warning("mcp_rate_limit_exceeded", user_id=user_id, tool_name=tool_name)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, "UNKNOWN",
                authorized=True, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="RATE_LIMIT_EXCEEDED",
                details={"error": "Rate limit exceeded."}
            )
            return False, None, "Rate limit exceeded. Please retry later."

        # 2. Server Validation & Enablement
        server = self.registry.get_server(server_id)
        if not server:
            log.warning("mcp_unknown_server_rejected", server_id=server_id)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, "UNKNOWN",
                authorized=False, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="UNKNOWN_SERVER",
                details={"error": f"Server '{server_id}' not found."}
            )
            return False, None, f"MCP server '{server_id}' not found."

        if not server.enabled or server.get_status() == MCPServerStatus.DISABLED:
            log.warning("mcp_disabled_server_rejected", server_id=server_id)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, "UNKNOWN",
                authorized=False, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="SERVER_DISABLED",
                details={"error": f"Server '{server_id}' is disabled."}
            )
            return False, None, f"MCP server '{server_id}' is currently disabled."

        # 3. Tool Validation
        tool = server.get_tool(tool_name)
        if not tool:
            log.warning("mcp_unknown_tool_rejected", server_id=server_id, tool_name=tool_name)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, "UNKNOWN",
                authorized=False, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="UNKNOWN_TOOL",
                details={"error": f"Tool '{tool_name}' not registered on server '{server_id}'."}
            )
            return False, None, f"Tool '{tool_name}' not found on server '{server_id}'."

        op_class = tool.operation_class.value

        # 4. Destructive Action Blocking (Hard boundary)
        if tool.operation_class == MCPOperationClass.DESTRUCTIVE:
            log.error("mcp_destructive_tool_blocked", server_id=server_id, tool_name=tool_name)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, op_class,
                authorized=False, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="DESTRUCTIVE_ACTION_BLOCKED",
                details={"error": "Destructive operations are blocked at the MCP boundary."}
            )
            server.update_metrics(0, is_error=True, error_code="DESTRUCTIVE_ACTION_BLOCKED")
            return False, None, "Operation blocked: DESTRUCTIVE actions are strictly prohibited via MCP."

        # 5. RBAC Authorization Check
        if user:
            role_repo = RoleRepository(session)
            perms = role_repo.get_permissions_for_role(user.role_id)
            has_perm = (tool.required_permission in perms) or ("*" in perms)
        else:
            has_perm = False

        if not has_perm:
            log.warning(
                "mcp_rbac_unauthorized",
                user_id=user_id,
                role=role_name,
                tool_name=tool_name,
                required_perm=tool.required_permission,
            )
            self._audit(
                session, req_id, corr_id, server_id, tool_name, op_class,
                authorized=False, status="BLOCKED", latency_ms=0,
                user_id=user_id, error_code="FORBIDDEN",
                details={
                    "error": "Insufficient permissions.",
                    "required_permission": tool.required_permission,
                }
            )
            server.update_metrics(0, is_error=True, error_code="FORBIDDEN")
            return False, None, f"Forbidden: user lacks required permission '{tool.required_permission}'."

        # 6. Strict Input Schema Validation (extra='forbid')
        try:
            validated_args = tool.input_schema(**arguments).model_dump()
        except ValidationError as val_err:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.warning(
                "mcp_validation_failed",
                server_id=server_id,
                tool_name=tool_name,
                errors=str(val_err),
            )
            self._audit(
                session, req_id, corr_id, server_id, tool_name, op_class,
                authorized=True, status="FAILED", latency_ms=duration_ms,
                user_id=user_id, error_code="VALIDATION_ERROR",
                details={"errors": val_err.errors()}
            )
            server.update_metrics(duration_ms, is_error=True, error_code="VALIDATION_ERROR")
            return False, None, f"Input validation failed: {str(val_err.errors()[0].get('msg'))}"

        # 7. Execution within Context
        ctx = MCPExecutionContext(
            session=session,
            user_id=user_id,
            role=role_name,
            correlation_id=corr_id,
            request_id=req_id,
            is_admin=(role_name == "ADMIN"),
        )

        try:
            raw_result = tool.handler(ctx, validated_args)
            duration_ms = int((time.monotonic() - start_time) * 1000)

            # Check if result indicates internal error
            if isinstance(raw_result, dict) and "error" in raw_result and "remediation_id" not in raw_result:
                # If error occurred inside handler
                err_msg = str(raw_result.get("error"))
                server.update_metrics(duration_ms, is_error=True, error_code="EXECUTION_ERROR")
                self._audit(
                    session, req_id, corr_id, server_id, tool_name, op_class,
                    authorized=True, status="FAILED", latency_ms=duration_ms,
                    user_id=user_id, error_code="EXECUTION_ERROR",
                    details=raw_result
                )
                return False, raw_result, err_msg

            # 8. Output Response Size Enforcement
            serialized = json.dumps(raw_result)
            if len(serialized.encode("utf-8")) > self.max_output_bytes:
                log.warning("mcp_output_truncated", tool_name=tool_name, size=len(serialized))
                raw_result = {
                    "truncated": True,
                    "warning": f"Output exceeded {self.max_output_bytes} bytes.",
                    "sample": raw_result if not isinstance(raw_result, list) else raw_result[:5],
                }

            server.update_metrics(duration_ms, is_error=False)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, op_class,
                authorized=True, status="SUCCESS", latency_ms=duration_ms,
                user_id=user_id, error_code=None,
                details=raw_result
            )
            return True, raw_result, None

        except Exception as exc:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            log.error("mcp_tool_execution_exception", tool_name=tool_name, error=type(exc).__name__)
            server.update_metrics(duration_ms, is_error=True, error_code=type(exc).__name__)
            self._audit(
                session, req_id, corr_id, server_id, tool_name, op_class,
                authorized=True, status="FAILED", latency_ms=duration_ms,
                user_id=user_id, error_code=type(exc).__name__,
                details={"error": f"Execution exception in {tool_name}."}
            )
            return False, None, f"Internal tool execution error: {type(exc).__name__}"

    def _audit(
        self,
        session: Session,
        request_id: str,
        correlation_id: str,
        server_id: str,
        tool_name: str,
        operation_class: str,
        authorized: bool,
        status: str,
        latency_ms: int,
        user_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to record tamper-evident audit log safely."""
        try:
            log_mcp_event(
                session=session,
                request_id=request_id,
                correlation_id=correlation_id,
                server_id=server_id,
                tool_name=tool_name,
                operation_class=operation_class,
                authorized=authorized,
                status=status,
                latency_ms=latency_ms,
                user_id=user_id,
                error_code=error_code,
                details=details,
            )
        except Exception as exc:
            log.error("mcp_audit_failure", error=str(exc))
