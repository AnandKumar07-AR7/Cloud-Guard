import { api } from './client'
import type {
  MCPAuditEvent,
  MCPInvokeResponse,
  MCPServer,
  MCPServerHealth,
  MCPTool,
} from '../types/mcp'

export const mcpApi = {
  listServers: async (): Promise<MCPServer[]> => {
    return api.get<MCPServer[]>('/api/v1/mcp/servers')
  },

  getServer: async (serverId: string): Promise<MCPServer> => {
    return api.get<MCPServer>(`/api/v1/mcp/servers/${serverId}`)
  },

  getServerTools: async (serverId: string): Promise<MCPTool[]> => {
    return api.get<MCPTool[]>(`/api/v1/mcp/servers/${serverId}/tools`)
  },

  getServerHealth: async (serverId: string): Promise<MCPServerHealth> => {
    return api.get<MCPServerHealth>(`/api/v1/mcp/servers/${serverId}/health`)
  },

  toggleServer: async (serverId: string, enabled: boolean): Promise<{ server_id: string; enabled: boolean; status: string }> => {
    return api.post(`/api/v1/mcp/servers/${serverId}/toggle`, { enabled })
  },

  listAllTools: async (): Promise<MCPTool[]> => {
    return api.get<MCPTool[]>('/api/v1/mcp/tools')
  },

  listTools: async (): Promise<MCPTool[]> => {
    return api.get<MCPTool[]>('/api/v1/mcp/tools')
  },

  getAuditLogs: async (params?: { server_id?: string; limit?: number; offset?: number }): Promise<MCPAuditEvent[]> => {
    return api.get<MCPAuditEvent[]>('/api/v1/mcp/audit', { params })
  },

  invokeTool: async (serverId: string, toolName: string, args: Record<string, unknown>): Promise<MCPInvokeResponse> => {
    return api.post<MCPInvokeResponse>('/api/v1/mcp/invoke', {
      server_id: serverId,
      tool_name: toolName,
      arguments: args,
    })
  },
}
