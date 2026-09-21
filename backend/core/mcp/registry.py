"""
CloudGuard — MCP Registry Service (Phase 10)
Maintains in-memory logical MCP servers and synchronizes server/tool metadata with PostgreSQL.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db_models import MCPServerDBModel, MCPToolDBModel
from core.mcp.servers.base import BaseCloudGuardMCPServer
from core.mcp.servers.discovery import DiscoveryMCPServer
from core.mcp.servers.remediation import RemediationMCPServer
from core.mcp.servers.security import SecurityMCPServer
from core.utils.logging import get_logger

log = get_logger(__name__)


class MCPRegistryService:
    """
    Registry management service for CloudGuard MCP servers.
    Handles startup discovery, tool cataloging, database synchronization,
    and server enablement toggles.
    """

    _instance: Optional[MCPRegistryService] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._servers: Dict[str, BaseCloudGuardMCPServer] = {}
        self._bootstrap_servers()
        self._initialized = True

    def _bootstrap_servers(self) -> None:
        """Initializes the three standard CloudGuard MCP servers."""
        disc = DiscoveryMCPServer()
        sec = SecurityMCPServer()
        rem = RemediationMCPServer()

        self._servers[disc.server_id] = disc
        self._servers[sec.server_id] = sec
        self._servers[rem.server_id] = rem
        log.info("mcp_servers_bootstrapped", count=len(self._servers))

    def get_server(self, server_id: str) -> Optional[BaseCloudGuardMCPServer]:
        return self._servers.get(server_id)

    def list_servers(self) -> List[BaseCloudGuardMCPServer]:
        return list(self._servers.values())

    def get_all_tools(self) -> List[Dict[str, Any]]:
        all_tools = []
        for s in self._servers.values():
            for t in s.list_tools():
                all_tools.append(t.to_metadata_dict(s.server_id))
        return all_tools

    def toggle_server(self, session: Session, server_id: str, enabled: bool) -> bool:
        """
        Enables or disables an MCP server in memory and persists state to database.
        """
        server = self.get_server(server_id)
        if not server:
            return False

        server.enabled = enabled

        db_server = session.scalar(
            select(MCPServerDBModel).where(MCPServerDBModel.server_id == server_id)
        )
        if db_server:
            db_server.enabled = enabled
            db_server.status = server.get_status().value
            db_server.updated_at = datetime.now(timezone.utc)
            session.commit()

        log.info("mcp_server_toggled", server_id=server_id, enabled=enabled)
        return True

    def sync_to_db(self, session: Session) -> None:
        """
        Synchronizes all in-memory servers and tools with PostgreSQL.
        Preserves existing runtime counters and admin enablement flags.
        """
        now = datetime.now(timezone.utc)

        for server in self._servers.values():
            db_server = session.scalar(
                select(MCPServerDBModel).where(MCPServerDBModel.server_id == server.server_id)
            )
            if not db_server:
                db_server = MCPServerDBModel(
                    server_id=server.server_id,
                    server_name=server.server_name,
                    version=server.version,
                    server_type=server.server_type,
                    status=server.get_status().value,
                    permission_scope=server.permission_scope,
                    enabled=server.enabled,
                    request_count=server.request_count,
                    error_count=server.error_count,
                    avg_latency_ms=server.avg_latency_ms,
                    last_health_check=server.last_health_check or now,
                    created_at=now,
                    updated_at=now,
                )
                session.add(db_server)
                session.flush()
            else:
                # Sync enabled state from DB to memory (persistence across restart)
                server.enabled = db_server.enabled
                db_server.status = server.get_status().value
                db_server.request_count = server.request_count
                db_server.error_count = server.error_count
                db_server.avg_latency_ms = server.avg_latency_ms
                db_server.last_health_check = server.last_health_check or now
                db_server.updated_at = now

            # Sync tools for this server
            for tool in server.list_tools():
                tool_id = f"{server.server_id}:{tool.name}"
                db_tool = session.scalar(
                    select(MCPToolDBModel).where(MCPToolDBModel.tool_id == tool_id)
                )
                if not db_tool:
                    db_tool = MCPToolDBModel(
                        tool_id=tool_id,
                        server_id=server.server_id,
                        tool_name=tool.name,
                        description=tool.description,
                        operation_class=tool.operation_class.value,
                        input_schema=tool.input_schema.model_json_schema(),
                        output_schema=tool.output_schema.model_json_schema() if tool.output_schema else {},
                        required_permission=tool.required_permission,
                        enabled=tool.enabled,
                        version=tool.version,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(db_tool)
                else:
                    db_tool.description = tool.description
                    db_tool.operation_class = tool.operation_class.value
                    db_tool.input_schema = tool.input_schema.model_json_schema()
                    db_tool.required_permission = tool.required_permission
                    db_tool.updated_at = now

        session.commit()
        log.info("mcp_registry_synced_to_db")
