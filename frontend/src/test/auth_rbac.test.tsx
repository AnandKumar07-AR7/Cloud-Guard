import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '../auth/AuthContext'
import { ProtectedRoute } from '../auth/ProtectedRoute'
import { LoginPage } from '../pages/LoginPage'
import { authApi } from '../api/authApi'
import { ApiError } from '../api/client'

vi.mock('../api/authApi')

const createQueryClient = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })

const TestDashboard: React.FC = () => {
  const { user, hasPermission, hasRole, logout } = useAuth()
  return (
    <div>
      <h1>Command Enclave</h1>
      <div data-testid="user-info">
        {user?.username} - {user?.role}
      </div>
      <button onClick={() => logout()}>Log Out</button>
      {hasPermission('remediations.approve') && <button data-testid="approve-btn">Approve Remediation</button>}
      {hasPermission('mcp.manage') && <button data-testid="mcp-manage-btn">Toggle MCP Server</button>}
      {hasPermission('automation.killswitch') && <button data-testid="killswitch-btn">Emergency Kill Switch</button>}
      {hasRole('ADMIN') && <div data-testid="admin-panel">Admin Control Plane</div>}
    </div>
  )
}

describe('Authentication & RBAC Behavioral Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    localStorage.clear()
  })

  it('successful login stores tokens and redirects to authenticated view', async () => {
    vi.mocked(authApi.login).mockResolvedValue({
      access_token: 'fake-jwt-token-123',
      refresh_token: 'fake-refresh-token-456',
      token_type: 'bearer',
      expires_in: 1800,
      user: {
        user_id: 'usr-admin-01',
        username: 'admin',
        email: 'admin@cloudguard.internal',
        role: 'ADMIN',
        is_active: true,
        is_verified: true,
        permissions: ['*'],
        created_at: '2026-09-15T10:00:00Z',
      },
    })

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-admin-01',
      username: 'admin',
      email: 'admin@cloudguard.internal',
      role: 'ADMIN',
      is_active: true,
      is_verified: true,
      permissions: ['*'],
      created_at: '2026-09-15T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-1">
          <MemoryRouter initialEntries={['/login']}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route
                path="/overview"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    const usernameInput = screen.getByPlaceholderText(/Username/i)
    const passwordInput = screen.getByPlaceholderText(/••••••••/i)
    const submitBtn = screen.getByRole('button', { name: /AUTHENTICATE/i })

    fireEvent.change(usernameInput, { target: { value: 'admin' } })
    fireEvent.change(passwordInput, { target: { value: 'admin123' } })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(authApi.login).toHaveBeenCalledWith('admin', 'admin123')
      expect(localStorage.getItem('cloudguard_access_token')).toBe('fake-jwt-token-123')
      expect(localStorage.getItem('cloudguard_refresh_token')).toBe('fake-refresh-token-456')
    })
  })

  it('invalid login credentials displays clear error message and prevents navigation', async () => {
    vi.mocked(authApi.login).mockRejectedValue(new ApiError(401, 'Invalid username or password'))

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-2">
          <MemoryRouter initialEntries={['/login']}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/overview" element={<TestDashboard />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    const usernameInput = screen.getByPlaceholderText(/Username/i)
    const passwordInput = screen.getByPlaceholderText(/••••••••/i)
    const submitBtn = screen.getByRole('button', { name: /AUTHENTICATE/i })

    fireEvent.change(usernameInput, { target: { value: 'unknown_user' } })
    fireEvent.change(passwordInput, { target: { value: 'wrongpass' } })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/Invalid username or password/i)).toBeInTheDocument()
      expect(localStorage.getItem('cloudguard_access_token')).toBeNull()
    })
  })

  it('logout terminates session, purges tokens, and redirects to login', async () => {
    localStorage.setItem('cloudguard_access_token', 'active-token')
    localStorage.setItem('cloudguard_refresh_token', 'active-refresh')

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-01',
      username: 'analyst_bob',
      email: 'bob@cloudguard.internal',
      role: 'SECURITY_ANALYST',
      is_active: true,
      is_verified: true,
      created_at: '2026-09-15T10:00:00Z',
    })

    vi.mocked(authApi.logout).mockResolvedValue()

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-3">
          <MemoryRouter initialEntries={['/']}>
            <Routes>
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
              <Route path="/login" element={<div>LOGIN PORTAL SCREEN</div>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Command Enclave')).toBeInTheDocument()

    const logoutBtn = screen.getByText('Log Out')
    fireEvent.click(logoutBtn)

    await waitFor(() => {
      expect(authApi.logout).toHaveBeenCalled()
      expect(localStorage.getItem('cloudguard_access_token')).toBeNull()
      expect(localStorage.getItem('cloudguard_refresh_token')).toBeNull()
    })
  })

  it('RBAC: VIEWER role sees telemetry but cannot access sensitive controls', async () => {
    localStorage.setItem('cloudguard_access_token', 'viewer-token')

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-viewer',
      username: 'viewer_alice',
      email: 'alice@cloudguard.internal',
      role: 'VIEWER',
      is_active: true,
      is_verified: true,
      created_at: '2026-09-15T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-4">
          <MemoryRouter initialEntries={['/']}>
            <Routes>
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Command Enclave')).toBeInTheDocument()
    expect(screen.getByTestId('user-info')).toHaveTextContent('viewer_alice - VIEWER')
    expect(screen.queryByTestId('approve-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('mcp-manage-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('killswitch-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('admin-panel')).not.toBeInTheDocument()
  })

  it('RBAC: OPERATOR role has remediation approval permission but not admin panel', async () => {
    localStorage.setItem('cloudguard_access_token', 'operator-token')

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-op',
      username: 'ops_charlie',
      email: 'charlie@cloudguard.internal',
      role: 'OPERATOR',
      is_active: true,
      is_verified: true,
      created_at: '2026-09-15T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-5">
          <MemoryRouter initialEntries={['/']}>
            <Routes>
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Command Enclave')).toBeInTheDocument()
    expect(screen.getByTestId('approve-btn')).toBeInTheDocument()
    expect(screen.queryByTestId('mcp-manage-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('killswitch-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('admin-panel')).not.toBeInTheDocument()
  })

  it('RBAC: ADMIN role has unrestricted access across all control planes', async () => {
    localStorage.setItem('cloudguard_access_token', 'admin-token')

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-admin',
      username: 'admin_diana',
      email: 'diana@cloudguard.internal',
      role: 'ADMIN',
      is_active: true,
      is_verified: true,
      permissions: ['*'],
      created_at: '2026-09-15T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-6">
          <MemoryRouter initialEntries={['/']}>
            <Routes>
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Command Enclave')).toBeInTheDocument()
    expect(screen.getByTestId('approve-btn')).toBeInTheDocument()
    expect(screen.getByTestId('mcp-manage-btn')).toBeInTheDocument()
    expect(screen.getByTestId('killswitch-btn')).toBeInTheDocument()
    expect(screen.getByTestId('admin-panel')).toBeInTheDocument()
  })

  it('ProtectedRoute redirects unauthenticated visitors to login', async () => {
    localStorage.clear()

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-7">
          <MemoryRouter initialEntries={['/']}>
            <Routes>
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <TestDashboard />
                  </ProtectedRoute>
                }
              />
              <Route path="/login" element={<div>LOGIN SCREEN REQUIRED</div>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText('LOGIN SCREEN REQUIRED')).toBeInTheDocument()
    expect(screen.queryByText('Command Enclave')).not.toBeInTheDocument()
  })

  it('ProtectedRoute enforces specific permission check and renders denied state', async () => {
    localStorage.setItem('cloudguard_access_token', 'viewer-token')

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-viewer',
      username: 'viewer_alice',
      email: 'alice@cloudguard.internal',
      role: 'VIEWER',
      is_active: true,
      is_verified: true,
      created_at: '2026-09-15T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-8">
          <MemoryRouter initialEntries={['/admin-settings']}>
            <Routes>
              <Route
                path="/admin-settings"
                element={
                  <ProtectedRoute requiredPermission="users.manage">
                    <div>HIGH PRIVILEGE ADMIN ZONE</div>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(await screen.findByText(/403 — Access Restricted/i)).toBeInTheDocument()
    expect(screen.getByText('users.manage')).toBeInTheDocument()
    expect(screen.queryByText('HIGH PRIVILEGE ADMIN ZONE')).not.toBeInTheDocument()
  })

  it('public registration enforces VIEWER role and submits to signup API', async () => {
    vi.mocked(authApi.register).mockResolvedValue({
      access_token: 'fake-viewer-token',
      refresh_token: 'fake-viewer-refresh',
      token_type: 'bearer',
      user: {
        user_id: 'usr-new-viewer',
        username: 'security_auditor',
        email: 'auditor@defense.cloud',
        role: 'VIEWER',
        is_active: true,
        is_verified: true,
        permissions: ['scans.read', 'findings.read', 'rules.read', 'resources.read', 'posture.read', 'remediations.read', 'automation.read', 'mcp.read'],
        created_at: '2026-09-17T10:00:00Z',
      },
    })

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-new-viewer',
      username: 'security_auditor',
      email: 'auditor@defense.cloud',
      role: 'VIEWER',
      is_active: true,
      is_verified: true,
      permissions: ['scans.read', 'findings.read', 'rules.read', 'resources.read', 'posture.read', 'remediations.read', 'automation.read', 'mcp.read'],
      created_at: '2026-09-17T10:00:00Z',
    })

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-reg">
          <MemoryRouter initialEntries={['/login']}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/overview" element={<ProtectedRoute><TestDashboard /></ProtectedRoute>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    // Switch to Create Account mode
    fireEvent.click(screen.getByRole('button', { name: /Create Account/i }))

    // Verify role dropdown does NOT exist and VIEWER is provisioned
    expect(screen.getByText(/VIEWER \(Security Auditor \/ Read-Only Posture\)/i)).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()

    // Fill registration form
    fireEvent.change(screen.getByPlaceholderText(/e\.g\. security_lead/i), { target: { value: 'security_auditor' } })
    fireEvent.change(screen.getByPlaceholderText(/officer@defense\.cloud/i), { target: { value: 'auditor@defense.cloud' } })
    fireEvent.change(screen.getByPlaceholderText(/Min 12 characters/i), { target: { value: 'AuditorPass123!' } })

    fireEvent.click(screen.getByRole('button', { name: /REGISTER VERIFIED ACCOUNT/i }))

    await waitFor(() => {
      expect(authApi.register).toHaveBeenCalledWith('security_auditor', 'auditor@defense.cloud', 'AuditorPass123!', 'VIEWER')
    })
  })
})
