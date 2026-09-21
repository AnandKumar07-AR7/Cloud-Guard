"""
CloudGuard — MCP Control Plane API Router (Phase 10)
Exposes endpoints for MCP server inspection, tool cataloging, health monitoring,
administrative toggling, audit log retrieval, and authenticated tool invocation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from auth.dependencies import require_permission, get_current_user
from auth.models import UserDBModel
from auth.permissions import Permission
from core.database import get_db
from core.db_models import MCPAuditEventDBModel, MCPServerDBModel, MCPToolDBModel
from core.mcp.gateway import MCPGateway
from core.mcp.registry import MCPRegistryService
from core.mcp.schemas import (
    MCPAuditEventResponse,
    MCPInvokeRequest,
    MCPInvokeResponse,
    MCPServerResponse,
    MCPServerToggleRequest,
    MCPToolResponse,
)
from core.utils.logging import get_logger

log = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/mcp",
    tags=["mcp"],
)

registry_service = MCPRegistryService()
gateway = MCPGateway(registry=registry_service)


@router.get(
    "/servers",
    response_model=List[MCPServerResponse],
    summary="List all registered MCP servers with live health and metrics",
)
def list_mcp_servers(
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_READ)),
) -> List[MCPServerResponse]:
    """Returns all registered MCP servers with real runtime metrics and health status."""
    registry_service.sync_to_db(db)
    servers = registry_service.list_servers()
    responses = []
    for s in servers:
        health = s.get_health_report()
        responses.append(
            MCPServerResponse(
                server_id=s.server_id,
                server_name=s.server_name,
                version=s.version,
                server_type=s.server_type,
                status=health["status"],
                enabled=s.enabled,
                permission_scope=s.permission_scope,
                request_count=s.request_count,
                error_count=s.error_count,
                avg_latency_ms=s.avg_latency_ms,
                last_health_check=s.last_health_check,
                last_request_at=s.last_request_at,
                last_error_at=s.last_error_at,
                last_error_code=s.last_error_code,
                tool_count=len(s.list_tools()),
            )
        )
    return responses


@router.get(
    "/servers/{server_id}",
    response_model=MCPServerResponse,
    summary="Get detailed metadata for a specific MCP server",
)
def get_mcp_server(
    server_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_READ)),
) -> MCPServerResponse:
    server = registry_service.get_server(server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server '{server_id}' not found.",
        )
    health = server.get_health_report()
    return MCPServerResponse(
        server_id=server.server_id,
        server_name=server.server_name,
        version=server.version,
        server_type=server.server_type,
        status=health["status"],
        enabled=server.enabled,
        permission_scope=server.permission_scope,
        request_count=server.request_count,
        error_count=server.error_count,
        avg_latency_ms=server.avg_latency_ms,
        last_health_check=server.last_health_check,
        last_request_at=server.last_request_at,
        last_error_at=server.last_error_at,
        last_error_code=server.last_error_code,
        tool_count=len(server.list_tools()),
    )


@router.get(
    "/servers/{server_id}/tools",
    response_model=List[MCPToolResponse],
    summary="List all tools exposed by a specific MCP server",
)
def list_server_tools(
    server_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_READ)),
) -> List[MCPToolResponse]:
    server = registry_service.get_server(server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server '{server_id}' not found.",
        )
    return [
        MCPToolResponse(
            tool_id=f"{server.server_id}:{t.name}",
            server_id=server.server_id,
            tool_name=t.name,
            description=t.description,
            operation_class=t.operation_class.value,
            required_permission=t.required_permission,
            enabled=t.enabled,
            version=t.version,
            input_schema=t.input_schema.model_json_schema(),
            output_schema=t.output_schema.model_json_schema() if t.output_schema else {},
        )
        for t in server.list_tools()
    ]


@router.get(
    "/servers/{server_id}/health",
    summary="Retrieve live health and error metrics for an MCP server",
)
def get_server_health(
    server_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_READ)),
) -> Dict[str, Any]:
    server = registry_service.get_server(server_id)
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server '{server_id}' not found.",
        )
    return server.get_health_report()


@router.post(
    "/servers/{server_id}/toggle",
    summary="Admin toggle to enable or disable an MCP server",
)
def toggle_mcp_server(
    server_id: str,
    payload: MCPServerToggleRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_MANAGE)),
) -> Dict[str, Any]:
    success = registry_service.toggle_server(db, server_id, payload.enabled)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server '{server_id}' not found.",
        )
    return {"server_id": server_id, "enabled": payload.enabled, "status": "updated"}


@router.get(
    "/tools",
    response_model=List[MCPToolResponse],
    summary="List all MCP tools across all registered servers",
)
def list_all_mcp_tools(
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_READ)),
) -> List[MCPToolResponse]:
    tools_data = registry_service.get_all_tools()
    return [
        MCPToolResponse(
            tool_id=t["tool_id"],
            server_id=t["server_id"],
            tool_name=t["tool_name"],
            description=t["description"],
            operation_class=t["operation_class"],
            required_permission=t["required_permission"],
            enabled=t["enabled"],
            version=t["version"],
            input_schema=t["input_schema"],
            output_schema=t["output_schema"],
        )
        for t in tools_data
    ]


@router.get(
    "/audit",
    response_model=List[MCPAuditEventResponse],
    summary="Retrieve tamper-evident audit events for MCP operations",
)
def get_mcp_audit_logs(
    server_id: Optional[str] = Query(None, description="Filter audit events by server"),
    limit: int = Query(50, ge=1, le=100, description="Max audit logs to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_AUDIT_READ)),
) -> List[MCPAuditEventResponse]:
    query = select(MCPAuditEventDBModel)
    if server_id:
        query = query.where(MCPAuditEventDBModel.server_id == server_id)
    query = query.order_by(desc(MCPAuditEventDBModel.sequence_number)).limit(limit).offset(offset)
    events = db.scalars(query).all()

    return [
        MCPAuditEventResponse(
            event_id=e.event_id,
            request_id=e.request_id,
            correlation_id=e.correlation_id,
            user_id=e.user_id,
            server_id=e.server_id,
            tool_name=e.tool_name,
            operation_class=e.operation_class,
            authorized=e.authorized,
            status=e.status,
            latency_ms=e.latency_ms,
            error_code=e.error_code,
            safe_details=e.safe_details,
            sequence_number=e.sequence_number,
            previous_event_hash=e.previous_event_hash,
            event_hash=e.event_hash,
            timestamp=e.timestamp,
        )
        for e in events
    ]


@router.post(
    "/invoke",
    response_model=MCPInvokeResponse,
    summary="Invoke an authorized MCP tool via the secure MCP gateway",
)
def invoke_mcp_tool(
    payload: MCPInvokeRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(require_permission(Permission.MCP_EXECUTE)),
) -> MCPInvokeResponse:
    import uuid
    req_id = str(uuid.uuid4())
    corr_id = str(uuid.uuid4())

    success, data, error = gateway.invoke_tool(
        session=db,
        server_id=payload.server_id,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        user=user,
        correlation_id=corr_id,
        request_id=req_id,
    )

    if not success:
        # Map specific gateway errors to appropriate HTTP status codes
        if error and "Forbidden" in error:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=error)
        if error and "not found" in error:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error)
        if error and "disabled" in error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
        if error and "rate limit" in error.lower():
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error)
        if error and "validation failed" in error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=error)
        if error and "blocked" in error.lower():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=error)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error or "Invocation failed")

    return MCPInvokeResponse(
        success=True,
        data=data,
        error=None,
        request_id=req_id,
    )
