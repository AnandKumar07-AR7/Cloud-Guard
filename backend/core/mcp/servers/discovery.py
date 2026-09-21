"""
CloudGuard — Discovery MCP Server (Phase 10)
Exposes strictly read-only, deterministic tools for inventory and scan discovery.
"""
from __future__ import annotations

from typing import Any, Dict, List
from sqlalchemy import select, desc

from auth.permissions import Permission
from core.ai.masking import mask_config
from core.db_models import (
    ResourceDBModel,
    ResourceRelationshipDBModel,
    ResourceSnapshotDBModel,
    ScanDBModel,
)
from core.mcp.models import (
    MCPExecutionContext,
    MCPOperationClass,
    MCPToolDefinition,
)
from core.mcp.schemas import (
    GetResourceInput,
    GetResourceRelationshipsInput,
    GetResourceSnapshotInput,
    GetScanInput,
    GetScanStatusInput,
    ListCloudAccountsInput,
    ListResourcesInput,
)
from core.mcp.servers.base import BaseCloudGuardMCPServer


class DiscoveryMCPServer(BaseCloudGuardMCPServer):
    """
    CloudGuard Discovery MCP Server.
    Provides read-only access to resources, topology relationships, and scan executions.
    """

    def __init__(self):
        super().__init__(
            server_id="cloudguard-discovery-mcp",
            server_name="CloudGuard Discovery MCP",
            version="1.0.0",
            server_type="discovery",
            description="Read-only MCP server for cloud resources, topology, and scan discovery.",
            permission_scope=[Permission.RESOURCES_READ, Permission.SCANS_READ],
        )
        self._register_discovery_tools()

    def _register_discovery_tools(self) -> None:
        self.register_tool(
            MCPToolDefinition(
                name="list_cloud_accounts",
                description="List discovered cloud accounts and environments.",
                operation_class=MCPOperationClass.READ,
                input_schema=ListCloudAccountsInput,
                required_permission=Permission.RESOURCES_READ,
                handler=self._handle_list_cloud_accounts,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="list_resources",
                description="List discovered cloud resources with optional service filtering and pagination.",
                operation_class=MCPOperationClass.READ,
                input_schema=ListResourcesInput,
                required_permission=Permission.RESOURCES_READ,
                handler=self._handle_list_resources,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_resource",
                description="Retrieve detailed metadata and sanitized tags for a specific cloud resource.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetResourceInput,
                required_permission=Permission.RESOURCES_READ,
                handler=self._handle_get_resource,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_resource_relationships",
                description="Retrieve topology relationships (inbound/outbound edges) for a cloud resource.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetResourceRelationshipsInput,
                required_permission=Permission.RESOURCES_READ,
                handler=self._handle_get_resource_relationships,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_resource_snapshot",
                description="Retrieve the latest sanitized configuration snapshot for a cloud resource.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetResourceSnapshotInput,
                required_permission=Permission.RESOURCES_READ,
                handler=self._handle_get_resource_snapshot,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_scan",
                description="Retrieve comprehensive summary for a specific security scan.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetScanInput,
                required_permission=Permission.SCANS_READ,
                handler=self._handle_get_scan,
            )
        )
        self.register_tool(
            MCPToolDefinition(
                name="get_scan_status",
                description="Retrieve current execution status and timestamps for a security scan.",
                operation_class=MCPOperationClass.READ,
                input_schema=GetScanStatusInput,
                required_permission=Permission.SCANS_READ,
                handler=self._handle_get_scan_status,
            )
        )

    # ── Tool Handlers ─────────────────────────────────────────────────────────

    def _handle_list_cloud_accounts(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        provider_filter = args.get("provider")
        query = select(ScanDBModel.account_id, ScanDBModel.provider).distinct()
        if provider_filter:
            query = query.where(ScanDBModel.provider == provider_filter)

        results = ctx.session.execute(query).all()
        accounts = [
            {"account_id": r.account_id, "provider": r.provider}
            for r in results
            if r.account_id
        ]
        if not accounts:
            accounts = [{"account_id": "123456789012", "provider": "demo"}]
        return {"accounts": accounts, "total": len(accounts)}

    def _handle_list_resources(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        query = select(ResourceDBModel)
        if args.get("service"):
            query = query.where(ResourceDBModel.service == args["service"])
        if args.get("resource_type"):
            query = query.where(ResourceDBModel.resource_type == args["resource_type"])

        limit = min(args.get("limit", 50), 100)
        offset = args.get("offset", 0)

        query = query.order_by(ResourceDBModel.resource_id).limit(limit).offset(offset)
        resources = ctx.session.scalars(query).all()

        items = [
            {
                "resource_id": r.resource_id,
                "provider": r.provider,
                "service": r.service,
                "resource_type": r.resource_type,
                "region": r.region,
                "tags": mask_config(r.tags) if isinstance(r.tags, dict) else {},
            }
            for r in resources
        ]
        return {"items": items, "count": len(items), "limit": limit, "offset": offset}

    def _handle_get_resource(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rid = args["resource_id"]
        res = ctx.session.scalar(
            select(ResourceDBModel).where(ResourceDBModel.resource_id == rid)
        )
        if not res:
            return {"error": f"Resource '{rid}' not found."}

        return {
            "resource_id": res.resource_id,
            "provider": res.provider,
            "service": res.service,
            "resource_type": res.resource_type,
            "region": res.region,
            "tags": mask_config(res.tags) if isinstance(res.tags, dict) else {},
            "created_at": res.created_at.isoformat() if getattr(res, "created_at", None) else None,
        }

    def _handle_get_resource_relationships(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rid = args["resource_id"]
        # Check resource exists
        res = ctx.session.scalar(
            select(ResourceDBModel).where(ResourceDBModel.resource_id == rid)
        )
        if not res:
            return {"error": f"Resource '{rid}' not found."}

        # Query inbound and outbound relationships
        outbound = ctx.session.scalars(
            select(ResourceRelationshipDBModel).where(
                ResourceRelationshipDBModel.source_id == rid
            )
        ).all()
        inbound = ctx.session.scalars(
            select(ResourceRelationshipDBModel).where(
                ResourceRelationshipDBModel.target_id == rid
            )
        ).all()

        return {
            "resource_id": rid,
            "outbound": [
                {
                    "target_id": rel.target_id,
                    "relationship_type": rel.relationship_type,
                    "arn": getattr(rel, "target_arn", None),
                }
                for rel in outbound
            ],
            "inbound": [
                {
                    "source_id": rel.source_id,
                    "relationship_type": rel.relationship_type,
                    "arn": getattr(rel, "source_arn", None),
                }
                for rel in inbound
            ],
        }

    def _handle_get_resource_snapshot(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        rid = args["resource_id"]
        snapshot = ctx.session.scalar(
            select(ResourceSnapshotDBModel)
            .where(ResourceSnapshotDBModel.resource_id == rid)
            .order_by(desc(ResourceSnapshotDBModel.observed_at))
            .limit(1)
        )
        if not snapshot:
            return {"error": f"No snapshot found for resource '{rid}'."}

        return {
            "resource_id": rid,
            "observed_at": snapshot.observed_at.isoformat(),
            "configuration": mask_config(snapshot.configuration)
            if isinstance(snapshot.configuration, dict)
            else {},
        }

    def _handle_get_scan(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        sid = args["scan_id"]
        scan = ctx.session.scalar(
            select(ScanDBModel).where(ScanDBModel.scan_id == sid)
        )
        if not scan:
            return {"error": f"Scan '{sid}' not found."}

        return {
            "scan_id": scan.scan_id,
            "provider": scan.provider,
            "account_id": scan.account_id,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "resources_scanned": scan.resources_scanned,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
        }

    def _handle_get_scan_status(
        self, ctx: MCPExecutionContext, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        sid = args["scan_id"]
        scan = ctx.session.scalar(
            select(ScanDBModel).where(ScanDBModel.scan_id == sid)
        )
        if not scan:
            return {"error": f"Scan '{sid}' not found."}

        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        }
