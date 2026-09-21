import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { PolicyAutomationPage } from '../pages/system/PolicyAutomationPage'
import { automationApi } from '../api/automationApi'
import * as authModule from '../auth/AuthContext'

vi.mock('../api/automationApi')

const createQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

const mockPolicies = [
  {
    policy_id: 'pol-auto-1',
    name: 'Auto-Remediate Public S3 Buckets',
    description: 'Enforce private ACL and block public access immediately upon discovery',
    require_human_approval: false,
    allowed_rule_ids: ['AWS_S3_PUBLIC_READ'],
    allowed_safety_levels: ['SAFE_AUTOMATIC'],
    priority: 100,
    enabled: true,
    created_at: '2026-09-15T00:00:00Z',
  },
  {
    policy_id: 'pol-auto-2',
    name: 'Enforce IAM Key Rotation Warning',
    description: 'Notify operators when IAM keys exceed 90 days of inactivity',
    require_human_approval: true,
    allowed_rule_ids: ['AWS_IAM_OLD_KEY'],
    allowed_safety_levels: ['MANUAL_REVIEW_REQUIRED'],
    priority: 50,
    enabled: true,
    created_at: '2026-09-15T00:00:00Z',
  },
]

describe('Phase 11 Policy-Governed Automation & Emergency Kill Switch Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders automation policies with deterministic priority and safety tier badges', async () => {
    const queryClient = createQueryClient()
    vi.spyOn(authModule, 'useAuth').mockReturnValue({
      user: { id: 'admin-1', username: 'admin', role: 'ADMIN', email: 'admin@cloudguard.internal' },
      isAuthenticated: true,
      hasPermission: () => true,
      login: vi.fn(),
      logout: vi.fn(),
      token: 'jwt-admin',
      refreshToken: 'refresh-jwt',
      isLoading: false,
    })

    vi.mocked(automationApi.listPolicies).mockResolvedValue(mockPolicies as any)
    vi.mocked(automationApi.getKillSwitchStatus).mockResolvedValue({
      enabled: false,
      reason: null,
      tripped_by: null,
      tripped_at: null,
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <PolicyAutomationPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Policy-Governed Automation & Emergency Controls/i)).toBeInTheDocument()
      expect(screen.getByText('Auto-Remediate Public S3 Buckets')).toBeInTheDocument()
      expect(screen.getByText('Enforce IAM Key Rotation Warning')).toBeInTheDocument()
      expect(screen.getByText(/AWS_S3_PUBLIC_READ/i)).toBeInTheDocument()
      expect(screen.getByText('SAFE_AUTOMATIC')).toBeInTheDocument()
      expect(screen.getByText('MANUAL_REVIEW_REQUIRED')).toBeInTheDocument()
    })
  })

  it('enables emergency kill switch with mandatory audit rationale', async () => {
    const queryClient = createQueryClient()
    vi.spyOn(authModule, 'useAuth').mockReturnValue({
      user: { id: 'admin-1', username: 'admin', role: 'ADMIN', email: 'admin@cloudguard.internal' },
      isAuthenticated: true,
      hasPermission: () => true,
      login: vi.fn(),
      logout: vi.fn(),
      token: 'jwt-admin',
      refreshToken: 'refresh-jwt',
      isLoading: false,
    })

    vi.mocked(automationApi.listPolicies).mockResolvedValue(mockPolicies as any)
    vi.mocked(automationApi.getKillSwitchStatus).mockResolvedValue({
      enabled: false,
      reason: null,
      tripped_by: null,
      tripped_at: null,
    } as any)

    vi.mocked(automationApi.enableKillSwitch).mockResolvedValueOnce({
      enabled: true,
      reason: 'Critical cloud instability detected',
      tripped_by: 'admin-1',
      tripped_at: '2026-09-15T12:00:00Z',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <PolicyAutomationPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Policy-Governed Automation & Emergency Controls/i)).toBeInTheDocument()
    })

    // Click "Halt All Automation"
    const haltBtn = screen.getByRole('button', { name: /Halt All Automation/i })
    fireEvent.click(haltBtn)

    // Modal pops up requiring reason
    await waitFor(() => {
      expect(screen.getByText(/Emergency Kill Switch Confirmation/i)).toBeInTheDocument()
    })

    const reasonInput = screen.getByPlaceholderText(/e\.g\. Production freeze window active\.\.\./i)
    fireEvent.change(reasonInput, { target: { value: 'Critical cloud instability detected' } })

    const confirmBtn = screen.getByRole('button', { name: /Confirm Status Change/i })
    fireEvent.click(confirmBtn)

    await waitFor(() => {
      expect(automationApi.enableKillSwitch).toHaveBeenCalledWith('Critical cloud instability detected')
    })
  })

  it('displays persistent emergency alert banner when Kill Switch is active', async () => {
    const queryClient = createQueryClient()
    vi.spyOn(authModule, 'useAuth').mockReturnValue({
      user: { id: 'admin-1', username: 'admin', role: 'ADMIN', email: 'admin@cloudguard.internal' },
      isAuthenticated: true,
      hasPermission: () => true,
      login: vi.fn(),
      logout: vi.fn(),
      token: 'jwt-admin',
      refreshToken: 'refresh-jwt',
      isLoading: false,
    })

    vi.mocked(automationApi.listPolicies).mockResolvedValue(mockPolicies as any)
    vi.mocked(automationApi.getKillSwitchStatus).mockResolvedValue({
      enabled: true,
      reason: 'Active penetration test in progress',
      tripped_by: 'security-admin',
      tripped_at: '2026-09-15T11:00:00Z',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <PolicyAutomationPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('EMERGENCY HALTED')).toBeInTheDocument()
    })
    expect(screen.getByText(/Active penetration test in progress/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Resume Automation/i })).toBeInTheDocument()
  })

  it('disallows unauthorized Viewer from engaging emergency controls', async () => {
    const queryClient = createQueryClient()
    // Viewer without automation permissions
    vi.spyOn(authModule, 'useAuth').mockReturnValue({
      user: { id: 'viewer-1', username: 'auditor', role: 'VIEWER', email: 'auditor@cloudguard.internal' },
      isAuthenticated: true,
      hasPermission: (perm: string) => perm === 'read' || perm === 'findings.read',
      login: vi.fn(),
      logout: vi.fn(),
      token: 'jwt-viewer',
      refreshToken: 'refresh-jwt',
      isLoading: false,
    })

    vi.mocked(automationApi.listPolicies).mockResolvedValue(mockPolicies as any)
    vi.mocked(automationApi.getKillSwitchStatus).mockResolvedValue({
      enabled: false,
      reason: null,
      tripped_by: null,
      tripped_at: null,
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <PolicyAutomationPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Policy-Governed Automation & Emergency Controls/i)).toBeInTheDocument()
    })

    // Button should not be rendered for viewers
    const haltBtn = screen.queryByRole('button', { name: /Halt All Automation/i })
    expect(haltBtn).toBeNull()
  })
})
