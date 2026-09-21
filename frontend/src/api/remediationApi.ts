import { api } from './client'
import type {
  AuditChainVerification,
  RemediationAuditEvent,
  RemediationPlan,
} from '../types/remediation'

export const remediationApi = {
  createPlan: async (findingId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans?finding_id=${encodeURIComponent(findingId)}`)
  },

  getPlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.get<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}`)
  },

  validatePlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/validate`)
  },

  approvePlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/approve`)
  },

  rejectPlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/reject`)
  },

  executePlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/execute`)
  },

  verifyPlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/verify`)
  },

  cancelPlan: async (remediationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/remediations/plans/${remediationId}/cancel`)
  },

  getAuditEvents: async (remediationId: string): Promise<RemediationAuditEvent[]> => {
    return api.get<RemediationAuditEvent[]>(`/api/v1/remediations/plans/${remediationId}/audit`)
  },

  verifyAuditChain: async (remediationId: string): Promise<AuditChainVerification> => {
    return api.get<AuditChainVerification>(`/api/v1/remediations/plans/${remediationId}/audit/verify`)
  },
}
