export type MCPOperationClass = 'READ' | 'WRITE' | 'DESTRUCTIVE'

export interface MCPTool {
  tool_id: string
  server_id: string
  tool_name: string
  description?: string
  operation_class: MCPOperationClass
  required_permission: string
  enabled: boolean
  version: string
  input_schema: Record<string, unknown>
  output_schema?: Record<string, unknown>
}

export interface MCPServerHealth {
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' | 'DISABLED' | string
  total_requests: number
  error_count: number
  error_rate_percent: number
  avg_latency_ms: number
  uptime_seconds?: number
}

export interface MCPServer {
  server_id: string
  server_name: string
  version: string
  server_type: string
  description?: string
  status: string
  enabled: boolean
  permission_scope: string[]
  request_count: number
  error_count: number
  avg_latency_ms: number
  last_health_check?: string
  last_request_at?: string
  last_error_at?: string
  last_error_code?: string
  tool_count: number
  tools?: MCPTool[]
}

export interface MCPAuditEvent {
  event_id: string
  request_id: string
  correlation_id: string
  user_id?: string
  server_id: string
  tool_name: string
  operation_class: string
  authorized: boolean
  status: 'SUCCESS' | 'FAILED' | 'BLOCKED' | string
  latency_ms: number
  error_code?: string
  safe_details?: Record<string, unknown>
  sequence_number: number
  previous_event_hash: string
  event_hash: string
  timestamp: string
}

export interface MCPInvokeRequest {
  server_id: string
  tool_name: string
  arguments: Record<string, unknown>
}

export interface MCPInvokeResponse {
  success: boolean
  data?: unknown
  error?: string
  request_id: string
}
