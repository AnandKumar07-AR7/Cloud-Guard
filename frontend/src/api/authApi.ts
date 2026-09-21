import { api } from './client'
import type { TokenResponse, User } from '../types/auth'

export const authApi = {
  login: async (username: string, password: string):Promise<TokenResponse> => {
    return api.post<TokenResponse>('/auth/login', { username, password })
  },

  logout: async (): Promise<void> => {
    const refreshToken = localStorage.getItem('cloudguard_refresh_token')
    try {
      await api.post('/auth/logout', refreshToken ? { refresh_token: refreshToken } : undefined)
    } finally {
      localStorage.removeItem('cloudguard_access_token')
      localStorage.removeItem('cloudguard_refresh_token')
    }
  },

  register: async (username: string, email: string, password: string, role?: string): Promise<TokenResponse> => {
    return api.post<TokenResponse>('/auth/register', { username, email, password, role: role || 'VIEWER' })
  },

  getCurrentUser: async (): Promise<User> => {
    return api.get<User>('/auth/me')
  },
}

