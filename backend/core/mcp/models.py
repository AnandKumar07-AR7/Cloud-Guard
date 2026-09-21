"""
CloudGuard — MCP Domain Models and Enums (Phase 10)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel
from sqlalchemy.orm import Session


class MCPOperationClass(str, Enum):
    """
    Classification of MCP tool operations.
    DESTRUCTIVE actions are blocked at the MCP boundary.
    """
    READ = "READ"
    WRITE = "WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"


class MCPServerStatus(str, Enum):
    """
    Runtime health status of an MCP server.
    """
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"


@dataclass
class MCPExecutionContext:
    """
    Security and execution context for an MCP request.
    Carries the authenticated identity, correlation IDs, and active DB session.
    """
    session: Session
    user_id: Optional[str] = None
    role: Optional[str] = None
    organization_id: Optional[str] = None
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    is_admin: bool = False


@dataclass
class MCPToolDefinition:
    """
    Represents an registered MCP tool in CloudGuard.
    """
    name: str
    description: str
    operation_class: MCPOperationClass
    input_schema: Type[BaseModel]
    required_permission: str
    handler: Callable[[MCPExecutionContext, Dict[str, Any]], Dict[str, Any]]
    output_schema: Optional[Type[BaseModel]] = None
    enabled: bool = True
    version: str = "1.0.0"

    def to_metadata_dict(self, server_id: str) -> Dict[str, Any]:
        return {
            "tool_id": f"{server_id}:{self.name}",
            "server_id": server_id,
            "tool_name": self.name,
            "description": self.description,
            "operation_class": self.operation_class.value,
            "input_schema": self.input_schema.model_json_schema(),
            "output_schema": self.output_schema.model_json_schema() if self.output_schema else {},
            "required_permission": self.required_permission,
            "enabled": self.enabled,
            "version": self.version,
        }
