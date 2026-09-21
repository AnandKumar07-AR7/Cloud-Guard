import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import React from 'react'
import { AuthProvider, useAuth } from '../auth/AuthContext'
import { ProtectedRoute } from '../auth/ProtectedRoute'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { authApi } from '../api/authApi'

vi.mock('../api/authApi', () => ({
  authApi: {
    login: vi.fn(),
    logout: vi.fn(),
    getCurrentUser: vi.fn(),
    refreshToken: vi.fn(),
  },
}))

const TestConsumer: React.FC = () => {
  const { user, isAuthenticated, hasPermission, hasRole } = useAuth()
  return (
    <div>
      <div data-testid="auth-status">{isAuthenticated ? 'LOGGED_IN' : 'LOGGED_OUT'}</div>
      <div data-testid="user-role">{user?.role || 'NONE'}</div>
      <div data-testid="can-create-scan">{hasPermission('scans.create') ? 'YES' : 'NO'}</div>
      <div data-testid="can-approve-rem">{hasPermission('remediations.approve') ? 'YES' : 'NO'}</div>
      <div data-testid="is-admin">{hasRole('ADMIN') ? 'YES' : 'NO'}</div>
    </div>
  )
}

describe('Authentication & RBAC Context', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('starts in logged out state when no token in localStorage', async () => {
    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    )

    expect(screen.getByTestId('auth-status')).toHaveTextContent('LOGGED_OUT')
    expect(screen.getByTestId('user-role')).toHaveTextContent('NONE')
    expect(screen.getByTestId('can-create-scan')).toHaveTextContent('NO')
  })

  it('restores user session on init when token is valid', async () => {
    localStorage.setItem('cloudguard_access_token', 'valid-jwt-token')
    vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce({
      user_id: 'usr-123',
      username: 'analyst',
      email: 'analyst@cloudguard.io',
      role: 'SECURITY_ANALYST',
      is_active: true,
      is_verified: true,
      created_at: new Date().toISOString(),
    })

    await act(async () => {
      render(
        <AuthProvider>
          <TestConsumer />
        </AuthProvider>
      )
    })

    expect(screen.getByTestId('auth-status')).toHaveTextContent('LOGGED_IN')
    expect(screen.getByTestId('user-role')).toHaveTextContent('SECURITY_ANALYST')
    // Analyst can create scans
    expect(screen.getByTestId('can-create-scan')).toHaveTextContent('YES')
    // Analyst CANNOT approve remediations (Separation of duties!)
    expect(screen.getByTestId('can-approve-rem')).toHaveTextContent('NO')
  })

  it('evaluates admin role permissions correctly with wildcard (*)', async () => {
    localStorage.setItem('cloudguard_access_token', 'admin-token')
    vi.mocked(authApi.getCurrentUser).mockResolvedValueOnce({
      user_id: 'usr-admin',
      username: 'admin',
      email: 'admin@cloudguard.io',
      role: 'ADMIN',
      is_active: true,
      is_verified: true,
      created_at: new Date().toISOString(),
    })

    await act(async () => {
      render(
        <AuthProvider>
          <TestConsumer />
        </AuthProvider>
      )
    })

    expect(screen.getByTestId('auth-status')).toHaveTextContent('LOGGED_IN')
    expect(screen.getByTestId('is-admin')).toHaveTextContent('YES')
    expect(screen.getByTestId('can-create-scan')).toHaveTextContent('YES')
    expect(screen.getByTestId('can-approve-rem')).toHaveTextContent('YES')
  })

  it('blocks unauthenticated access on ProtectedRoute and renders login redirect', async () => {
    render(
      <AuthProvider>
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>LOGIN PAGE</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>PROTECTED CONTENT</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    )

    expect(screen.queryByText('PROTECTED CONTENT')).not.toBeInTheDocument()
    expect(screen.getByText('LOGIN PAGE')).toBeInTheDocument()
  })
})
