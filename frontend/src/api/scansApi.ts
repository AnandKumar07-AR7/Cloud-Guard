import { api } from './client'
import type { ScanListResponse, ScanRequest, ScanSummary } from '../types/scans'

export const scansApi = {
  listScans: async (
    limitOrParams?: number | { limit?: number; offset?: number; status?: string },
    offset?: number
  ): Promise<ScanListResponse> => {
    let params: Record<string, string | number | boolean | null | undefined> = {}
    if (typeof limitOrParams === 'number') {
      params = { limit: limitOrParams, offset: offset || 0 }
    } else if (limitOrParams) {
      params = limitOrParams as Record<string, string | number | boolean | null | undefined>
    }
    const res = await api.get<ScanListResponse>('/scans', { params })
    return {
      ...res,
      items: res.items || res.scans || [],
      scans: res.scans || res.items || [],
    }
  },

  getScan: async (scanId: string): Promise<ScanSummary> => {
    return api.get<ScanSummary>(`/scans/${scanId}`)
  },

  runScan: async (req: ScanRequest = {}): Promise<ScanSummary> => {
    return api.post<ScanSummary>('/scans', req)
  },

  createScan: async (req: ScanRequest = {}): Promise<ScanSummary> => {
    return api.post<ScanSummary>('/scans', req)
  },
}
