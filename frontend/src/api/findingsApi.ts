import { api } from './client'
import type {
  Finding,
  FindingHistoryResponse,
  FindingListResponse,
  InvestigationResponse,
} from '../types/findings'

export const findingsApi = {
  listFindings: async (params?: {
    scan_id?: string
    service?: string
    severity?: string
    category?: string
    status?: string
    internet_exposed?: boolean
    limit?: number
    offset?: number
  }): Promise<FindingListResponse> => {
    const res = await api.get<FindingListResponse>('/findings', { params })
    return {
      ...res,
      items: res.items || res.findings || [],
      findings: res.findings || res.items || [],
    }
  },

  getFinding: async (findingId: string): Promise<Finding> => {
    return api.get<Finding>(`/findings/${findingId}`)
  },

  getInvestigation: async (findingId: string): Promise<InvestigationResponse> => {
    return api.get<InvestigationResponse>(`/findings/${findingId}/investigation`)
  },

  getFindingHistory: async (canonicalId: string): Promise<FindingHistoryResponse> => {
    return api.get<FindingHistoryResponse>(`/findings/${canonicalId}/history`)
  },
}
