import { api } from './client'
import type { HealthResponse, ModeResponse } from '../types/system'

export const systemApi = {
  getHealth: async (): Promise<HealthResponse> => {
    return api.get<HealthResponse>('/health')
  },

  getMode: async (): Promise<ModeResponse> => {
    return api.get<ModeResponse>('/mode')
  },
}
