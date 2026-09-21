import { api } from './client'
import type { ResourceDetail, ResourceListResponse } from '../types/resources'

export const resourcesApi = {
  listResources: async (params?: {
    scan_id?: string
    service?: string
    resource_type?: string
    region?: string
    security_posture?: string
    limit?: number
    offset?: number
  }): Promise<ResourceListResponse> => {
    const res = await api.get<ResourceListResponse>('/resources', { params })
    return {
      ...res,
      items: res.items || res.resources || [],
      resources: res.resources || res.items || [],
    }
  },

  getResource: async (resourceId: string): Promise<ResourceDetail> => {
    return api.get<ResourceDetail>(`/resources/${encodeURIComponent(resourceId)}`)
  },
}
