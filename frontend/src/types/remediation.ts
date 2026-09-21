export type RemediationState =
  | 'DRAFT'
  | 'VALIDATED'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'EXECUTING'
  | 'EXECUTED'
  | 'VERIFYING'
  | 'VERIFIED_FIXED'
  | 'VERIFICATION_FAILED'
  | 'EXECUTION_FAILED'
  | 'CANCELLED'
  | string

export interface RemediationAction {
  action_type: string
  target_resource: string
  target_field?: string
  new_value?: unknown
  old_value?: unknown
  parameters?: Record<string, unknown>
}

export interface PlanSpec {
  strategy_id: string
  description?: string
  safety_classification?: string
  actions: RemediationAction[]
  parameters?: Record<string, unknown>
}

export interface RemediationAuditEvent {
  event_id: string
  remediation_id: string
  action: string
  actor_id: string
  actor?: string
  from_state?: string
  to_state?: string
  timestamp: string
  details?: Record<string, unknown>
  sequence_number?: number
  previous_event_hash?: string
  event_hash?: string
}

export interface RemediationExecution {
  execution_id: string
  remediation_id: string
  action_id: string
  status: string
  started_at: string
  completed_at?: string
  result?: Record<string, unknown>
  error_message?: string
}

export interface RemediationPlan {
  remediation_id: string
  finding_id: string
  state: RemediationState
  strategy_id: string
  strategy_name?: string
  safety?: string
  resource_id?: string
  created_by: string
  plan_spec: PlanSpec
  execution_log?: string
  created_at: string
  updated_at?: string
  validated_at?: string
  approved_at?: string
  approved_by?: string
  executed_at?: string
  executed_by?: string
  verified_at?: string
  verified_by?: string
  cancelled_at?: string
  cancelled_by?: string
  error_message?: string
  actions?: RemediationAction[]
  executions?: RemediationExecution[]
  audit_events?: RemediationAuditEvent[]
}

export interface AuditChainVerification {
  verified: boolean
  event_count: number
  genesis_hash?: string
  latest_hash?: string
  error?: string
}
