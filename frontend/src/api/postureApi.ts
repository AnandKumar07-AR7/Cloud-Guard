import { api } from './client'
import type { PostureResponse } from '../types/posture'

export const postureApi = {
  getPosture: async (scanId?: string): Promise<PostureResponse> => {
    return api.get<PostureResponse>('/posture', {
      params: scanId ? { scan_id: scanId } : undefined,
    })
  },
}
