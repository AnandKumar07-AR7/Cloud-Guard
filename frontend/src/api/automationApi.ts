import { api } from './client'
import type {
  AutomationAuditEvent,
  AutomationDecision,
  AutomationPolicy,
  AutomationPolicyCreateRequest,
  KillSwitchStatus,
} from '../types/automation'

export const automationApi = {
  listPolicies: async (enabledOnly?: boolean): Promise<AutomationPolicy[]> => {
    return api.get<AutomationPolicy[]>('/api/v1/automation/policies', {
      params: enabledOnly ? { enabled_only: true } : undefined,
    })
  },

  getPolicy: async (policyId: string): Promise<AutomationPolicy> => {
    return api.get<AutomationPolicy>(`/api/v1/automation/policies/${policyId}`)
  },

  createPolicy: async (req: AutomationPolicyCreateRequest): Promise<AutomationPolicy> => {
    return api.post<AutomationPolicy>('/api/v1/automation/policies', req)
  },

  updatePolicy: async (policyId: string, req: Partial<AutomationPolicyCreateRequest>): Promise<AutomationPolicy> => {
    return api.patch<AutomationPolicy>(`/api/v1/automation/policies/${policyId}`, req)
  },

  deletePolicy: async (policyId: string): Promise<void> => {
    return api.delete<void>(`/api/v1/automation/policies/${policyId}`)
  },

  evaluateRemediation: async (remediationId: string): Promise<AutomationDecision> => {
    return api.post<AutomationDecision>('/api/v1/automation/evaluate', { remediation_id: remediationId })
  },

  listDecisions: async (remediationId?: string): Promise<AutomationDecision[]> => {
    return api.get<AutomationDecision[]>('/api/v1/automation/decisions', {
      params: remediationId ? { remediation_id: remediationId } : undefined,
    })
  },

  listAuditEvents: async (params?: { remediation_id?: string; policy_id?: string }): Promise<AutomationAuditEvent[]> => {
    return api.get<AutomationAuditEvent[]>('/api/v1/automation/audit', { params })
  },

  getKillSwitchStatus: async (): Promise<KillSwitchStatus> => {
    return api.get<KillSwitchStatus>('/api/v1/automation/kill-switch')
  },

  enableKillSwitch: async (reason: string): Promise<KillSwitchStatus> => {
    return api.post<KillSwitchStatus>('/api/v1/automation/kill-switch/enable', { reason })
  },

  disableKillSwitch: async (reason: string): Promise<KillSwitchStatus> => {
    return api.post<KillSwitchStatus>('/api/v1/automation/kill-switch/disable', { reason })
  },
}
