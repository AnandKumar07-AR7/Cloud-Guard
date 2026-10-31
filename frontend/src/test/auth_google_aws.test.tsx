import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '../auth/AuthContext'
import { LoginPage } from '../pages/LoginPage'
import { authApi } from '../api/authApi'

vi.mock('../api/authApi')

const createQueryClient = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })

const TestEnclaveDashboard: React.FC = () => {
  const { user } = useAuth()
  return (
    <div>
      <h1>Enclave Command Center</h1>
      <div data-testid="user-display">{user?.username} ({user?.email})</div>
    </div>
  )
}

describe('Google OAuth & AWS Account Linking Verification', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    localStorage.clear()
  })

  it('renders Google Sign-In and Enclave Access Policy banner', () => {
    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-policy">
          <MemoryRouter initialEntries={['/login']}>
            <LoginPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    expect(screen.getByText(/Strict Access Policy/i)).toBeInTheDocument()
    expect(screen.getByText(/@gmail\.com/i)).toBeInTheDocument()
    expect(screen.getByText(/12-digit AWS Account ID/i)).toBeInTheDocument()
  })

  it('allows manual Gmail linking, validates 12-digit AWS Account ID, and authenticates', async () => {
    vi.mocked(authApi.googleLogin).mockResolvedValue({
      access_token: 'fake-google-jwt-token',
      refresh_token: 'fake-google-refresh-token',
      token_type: 'bearer',
      expires_in: 1800,
      user: {
        user_id: 'usr-google-01',
        username: 'security_auditor',
        email: 'security.officer@gmail.com',
        role: 'VIEWER',
        is_active: true,
        is_verified: true,
        created_at: '2026-10-30T18:00:00Z',
      },
    })

    vi.mocked(authApi.getCurrentUser).mockResolvedValue({
      user_id: 'usr-google-01',
      username: 'security_auditor',
      email: 'security.officer@gmail.com',
      role: 'VIEWER',
      is_active: true,
      is_verified: true,
      created_at: '2026-10-30T18:00:00Z',
    })

    // Mock window.prompt to return a valid Gmail
    vi.spyOn(window, 'prompt').mockReturnValue('security.officer@gmail.com')

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-google-flow">
          <MemoryRouter initialEntries={['/login']}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/overview" element={<TestEnclaveDashboard />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    // Click "Or link Gmail + AWS Account ID manually"
    const manualBtn = screen.getByText(/Or link Gmail \+ AWS Account ID manually/i)
    fireEvent.click(manualBtn)

    // Should now show Gmail verified badge and AWS input
    expect(await screen.findByText(/Gmail verified: security\.officer@gmail\.com/i)).toBeInTheDocument()
    expect(screen.getByText(/AWS ACCOUNT ID \(12 DIGITS\)/i)).toBeInTheDocument()

    // Click Auto-fill AWS Account ID
    const autoFillBtn = screen.getByRole('button', { name: /Auto-fill (371700247056|817760095153)/i })
    fireEvent.click(autoFillBtn)

    // Click Verify & Access button
    const verifyBtn = screen.getByRole('button', { name: /VERIFY & ACCESS ENCLAVE/i })
    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(authApi.googleLogin).toHaveBeenCalledWith('dev:security.officer@gmail.com', expect.stringMatching(/^(371700247056|817760095153)$/))
      expect(localStorage.getItem('cloudguard_access_token')).toBe('fake-google-jwt-token')
    })
  })

  it('rejects non-gmail addresses during manual linking prompt', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('hacker@corporate.net')

    render(
      <QueryClientProvider client={createQueryClient()}>
        <AuthProvider key="test-reject-nongmail">
          <MemoryRouter initialEntries={['/login']}>
            <LoginPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    const manualBtn = screen.getByText(/Or link Gmail \+ AWS Account ID manually/i)
    fireEvent.click(manualBtn)

    expect(await screen.findByText(/Access restricted: Only '@gmail\.com' accounts linked with an AWS account are permitted/i)).toBeInTheDocument()
  })
})

