import { api } from './client'
import type { RuleListResponse, SecurityRule } from '../types/rules'

export const rulesApi = {
  listRules: async (params?: {
    service?: string
    severity?: string
    category?: string
    enabled_only?: boolean
    limit?: number
    offset?: number
  }): Promise<RuleListResponse> => {
    return api.get<RuleListResponse>('/rules', { params })
  },

  getRule: async (ruleId: string): Promise<SecurityRule> => {
    return api.get<SecurityRule>(`/rules/${ruleId}`)
  },
}
