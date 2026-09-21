import type { Finding } from './findings'

export interface ResourceRelationship {
  source_resource_id: string
  target_resource_id: string
  target_resource_type?: string
  target_service?: string
  relationship_type: string
  evidence?: Record<string, unknown>
}

export interface Resource {
  resource_id: string
  provider: string
  account_id: string
  region: string
  service: string
  resource_type: string
  name?: string
  resource_name?: string
  resource_arn?: string
  security_posture: 'SECURE' | 'AT_RISK' | 'HIGH_RISK' | 'CRITICAL' | string
  posture?: 'SECURE' | 'AT_RISK' | 'HIGH_RISK' | 'CRITICAL' | string
  severity_counts: {
    critical: number
    high: number
    medium: number
    low: number
  }
  finding_count: number
  created_at?: string
  updated_at?: string
  tags?: Record<string, string>
}

export interface ResourceListResponse {
  items: Resource[]
  resources?: Resource[]
  total: number
  limit: number
  offset: number
}

export interface ResourceDetail {
  resource: Resource
  safe_config: Record<string, unknown>
  security_posture: string
  findings: Finding[]
  relationships: ResourceRelationship[]
}
