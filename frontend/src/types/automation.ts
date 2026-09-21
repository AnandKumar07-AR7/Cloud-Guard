export interface AutomationPolicy {
  policy_id: string
  name: string
  description?: string
  enabled: boolean
  priority: number
  version?: number
  allowed_providers?: string[]
  allowed_services?: string[]
  allowed_resource_types?: string[]
  allowed_rule_ids?: string[]
  allowed_strategies?: string[]
  allowed_safety_levels?: string[]
  rule_ids?: string[]
  execution_mode?: 'MANUAL' | 'ASSISTED' | 'AUTONOMOUS' | string
  auto_progress_validation?: boolean
  auto_progress_approval?: boolean
  auto_progress_execution?: boolean
  require_human_approval?: boolean
  created_by?: string
  updated_by?: string
  created_at: string
  updated_at?: string
}

export interface AutomationPolicyCreateRequest {
  name: string
  description?: string
  enabled?: boolean
  priority?: number
  rule_ids?: string[]
  severities?: string[]
  target_environments?: string[]
  max_blast_radius?: number
  execution_mode: 'MANUAL' | 'ASSISTED' | 'AUTONOMOUS' | string
}

export interface AutomationDecision {
  decision_id: string
  remediation_id: string
  decision: 'APPROVED' | 'REQUIRES_APPROVAL' | 'BLOCKED' | string
  matched_policy_id?: string
  matched_policy_name?: string
  execution_mode?: string
  blast_radius?: number
  reasons: string[]
  created_at: string
}

export interface AutomationAuditEvent {
  event_id: string
  remediation_id?: string
  policy_id?: string
  action: string
  actor_id?: string
  actor?: string
  status?: string
  event_hash?: string
  details?: Record<string, unknown>
  created_at: string
  timestamp?: string
}

export interface KillSwitchStatus {
  enabled: boolean
  active?: boolean
  updated_by?: string
  activated_by?: string
  reason?: string
  updated_at?: string
  activated_at?: string
}
