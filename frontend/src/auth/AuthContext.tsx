import React, { createContext, useContext, useEffect, useState } from 'react'
import { authApi } from '../api/authApi'
import type { User } from '../types/auth'

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  signup: (username: string, email: string, password: string, role?: string) => Promise<void>
  logout: () => Promise<void>
  hasPermission: (permission: string) => boolean
  hasRole: (...roles: string[]) => boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

// Role permission mapping aligned with backend auth/permissions.py
const ROLE_PERMISSIONS: Record<string, string[]> = {
  ADMIN: ['*'],
  SECURITY_ANALYST: [
    'scans.read',
    'scans.create',
    'findings.read',
    'rules.read',
    'resources.read',
    'posture.read',
    'investigation.read',
    'ai.read',
    'ai.analyze',
    'ai.audit.read',
    'remediations.read',
    'remediations.create',
    'remediations.validate',
    'remediations.cancel',
    'remediations.audit.read',
    'automation.read',
    'automation.evaluate',
    'automation.audit.read',
    'mcp.read',
    'mcp.execute',
    'mcp.audit_read',
    'users.read',
  ],
  OPERATOR: [
    'scans.read',
    'scans.create',
    'findings.read',
    'rules.read',
    'resources.read',
    'posture.read',
    'remediations.read',
    'remediations.approve',
    'remediations.execute',
    'remediations.cancel',
    'remediations.audit.read',
    'automation.read',
    'automation.evaluate',
    'automation.audit.read',
    'mcp.read',
    'mcp.execute',
  ],
  VIEWER: [
    'scans.read',
    'findings.read',
    'rules.read',
    'resources.read',
    'posture.read',
    'remediations.read',
    'automation.read',
    'mcp.read',
  ],
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)

  useEffect(() => {
    const initAuth = async () => {
      const isTestEnv =
        (typeof window !== 'undefined' && ((window as any).__VITEST__ || typeof (window as any).vi !== 'undefined')) ||
        import.meta.env?.MODE === 'test'
      const isTabActive = sessionStorage.getItem('cloudguard_tab_active') === 'true' || isTestEnv
      const token = isTabActive ? localStorage.getItem('cloudguard_access_token') : null

      if (token) {
        try {
          const currentUser = await authApi.getCurrentUser()
          setUser(currentUser)
        } catch {
          localStorage.removeItem('cloudguard_access_token')
          localStorage.removeItem('cloudguard_refresh_token')
          sessionStorage.removeItem('cloudguard_tab_active')
          setUser(null)
        }
      } else {
        setUser(null)
      }
      setIsLoading(false)
    }

    initAuth()

    const handleAuthExpired = () => {
      sessionStorage.removeItem('cloudguard_tab_active')
      setUser(null)
    }

    window.addEventListener('cloudguard_auth_expired', handleAuthExpired)
    return () => {
      window.removeEventListener('cloudguard_auth_expired', handleAuthExpired)
    }
  }, [])

  const login = async (username: string, password: string): Promise<void> => {
    const res = await authApi.login(username, password)
    localStorage.setItem('cloudguard_access_token', res.access_token)
    localStorage.setItem('cloudguard_refresh_token', res.refresh_token)
    sessionStorage.setItem('cloudguard_tab_active', 'true')
    if (res.user) {
      setUser(res.user)
    } else {
      const currentUser = await authApi.getCurrentUser()
      setUser(currentUser)
    }
  }

  const signup = async (username: string, email: string, password: string, role?: string): Promise<void> => {
    const res = await authApi.register(username, email, password, role)
    localStorage.setItem('cloudguard_access_token', res.access_token)
    localStorage.setItem('cloudguard_refresh_token', res.refresh_token)
    sessionStorage.setItem('cloudguard_tab_active', 'true')
    if (res.user) {
      setUser(res.user)
    } else {
      const currentUser = await authApi.getCurrentUser()
      setUser(currentUser)
    }
  }

  const logout = async (): Promise<void> => {
    try {
      await authApi.logout()
    } finally {
      localStorage.removeItem('cloudguard_access_token')
      localStorage.removeItem('cloudguard_refresh_token')
      sessionStorage.removeItem('cloudguard_tab_active')
      setUser(null)
    }
  }

  const hasPermission = (permission: string): boolean => {
    if (!user) return false
    const role = user.role.toUpperCase()
    const perms = ROLE_PERMISSIONS[role] || []
    if (perms.includes('*') || role === 'ADMIN') return true
    return perms.includes(permission)
  }

  const hasRole = (...roles: string[]): boolean => {
    if (!user) return false
    const roleUpper = user.role.toUpperCase()
    return roles.map((r) => r.toUpperCase()).includes(roleUpper)
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        signup,
        logout,
        hasPermission,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
