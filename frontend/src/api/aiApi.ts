import { api } from './client'
import type { AIAgentRun, AIRecommendation, AIToolEvent } from '../types/ai'
import type { RemediationPlan } from '../types/remediation'

export const aiApi = {
  analyze: async (findingId: string): Promise<AIAgentRun> => {
    return api.post<AIAgentRun>('/api/v1/ai/analyze', { finding_id: findingId })
  },

  listRuns: async (params?: { finding_id?: string; limit?: number }): Promise<AIAgentRun[]> => {
    return api.get<AIAgentRun[]>('/api/v1/ai/runs', { params })
  },

  getRun: async (runId: string): Promise<AIAgentRun> => {
    return api.get<AIAgentRun>(`/api/v1/ai/runs/${runId}`)
  },

  getRunRecommendations: async (runId: string): Promise<AIRecommendation[]> => {
    return api.get<AIRecommendation[]>(`/api/v1/ai/runs/${runId}/recommendations`)
  },

  getRecommendation: async (recommendationId: string): Promise<AIRecommendation> => {
    return api.get<AIRecommendation>(`/api/v1/ai/recommendations/${recommendationId}`)
  },

  getRunAudit: async (runId: string): Promise<AIToolEvent[]> => {
    return api.get<AIToolEvent[]>(`/api/v1/ai/runs/${runId}/audit`)
  },

  createRemediationPlanFromRecommendation: async (recommendationId: string): Promise<RemediationPlan> => {
    return api.post<RemediationPlan>(`/api/v1/ai/recommendations/${recommendationId}/remediation-plan`)
  },
}
