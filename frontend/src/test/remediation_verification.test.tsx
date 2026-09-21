import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RemediationCenterPage } from '../pages/remediation/RemediationCenterPage'
import { VerificationPage } from '../pages/remediation/VerificationPage'
import { remediationApi } from '../api/remediationApi'
import { findingsApi } from '../api/findingsApi'

vi.mock('../api/remediationApi')
vi.mock('../api/findingsApi')
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'admin-1', username: 'admin', role: 'ADMIN', email: 'admin@cloudguard.internal' },
    isAuthenticated: true,
    hasPermission: () => true,
  }),
  AuthProvider: ({ children }: any) => <>{children}</>,
}))

const createQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })

describe('Phase 11 Remediation & 6-Stage Verification Behavioral Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    vi.mocked(remediationApi.verifyAuditChain).mockResolvedValue({ verified: true, chain_length: 1 } as any)
  })

  it('renders Remediation Center and generates plan for finding', async () => {
    const queryClient = createQueryClient()

    vi.mocked(remediationApi.createPlan).mockResolvedValue({
      remediation_id: 'plan-101',
      finding_id: 'f-aws-s3-1',
      state: 'DRAFT',
      strategy_name: 'Apply S3 Encryption',
      resource_id: 'arn:aws:s3:::customer-pii',
      created_by: 'analyst-1',
      created_at: '2026-09-15T00:00:00Z',
    } as any)

    vi.mocked(remediationApi.getPlan).mockResolvedValue({
      remediation_id: 'plan-101',
      finding_id: 'f-aws-s3-1',
      state: 'DRAFT',
      strategy_name: 'Apply S3 Encryption',
      resource_id: 'arn:aws:s3:::customer-pii',
      created_by: 'analyst-1',
      created_at: '2026-09-15T00:00:00Z',
    } as any)

    vi.mocked(remediationApi.getAuditEvents).mockResolvedValue([])

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation?finding_id=f-aws-s3-1']}>
          <Routes>
            <Route path="/remediation" element={<RemediationCenterPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Safe Remediation Center')).toBeInTheDocument()
    const generateBtn = screen.getByRole('button', { name: /Load \/ Create Plan/i })
    fireEvent.click(generateBtn)

    await waitFor(() => {
      expect(remediationApi.createPlan).toHaveBeenCalledWith('f-aws-s3-1')
    })
  })

  it('validates a draft plan and updates state to VALIDATED', async () => {
    const queryClient = createQueryClient()

    const mockPlan = {
      remediation_id: 'plan-102',
      finding_id: 'f-aws-s3-1',
      state: 'DRAFT',
      strategy_name: 'Block S3 Public Access',
      resource_id: 'arn:aws:s3:::customer-pii',
      created_by: 'analyst-1',
      created_at: '2026-09-15T00:00:00Z',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(mockPlan as any)
    vi.mocked(remediationApi.validatePlan).mockResolvedValue({
      ...mockPlan,
      state: 'VALIDATED',
    } as any)
    vi.mocked(remediationApi.getAuditEvents).mockResolvedValue([])

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation?plan_id=plan-102']}>
          <Routes>
            <Route path="/remediation" element={<RemediationCenterPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Block S3 Public Access')).toBeInTheDocument()

    const validateBtn = screen.getByRole('button', { name: /Validate Plan/i })
    fireEvent.click(validateBtn)

    await waitFor(() => {
      expect(remediationApi.validatePlan).toHaveBeenCalledWith('plan-102')
    })
  })

  it('rejects self-approval when creator attempts to approve (Separation of Duties)', async () => {
    const queryClient = createQueryClient()

    const mockPlan = {
      remediation_id: 'plan-103',
      finding_id: 'f-aws-s3-1',
      state: 'PENDING_APPROVAL',
      strategy_name: 'Enable S3 Versioning',
      resource_id: 'arn:aws:s3:::customer-pii',
      created_by: 'admin-1',
      created_at: '2026-09-15T00:00:00Z',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(mockPlan as any)
    vi.mocked(remediationApi.getAuditEvents).mockResolvedValue([])

    vi.mocked(remediationApi.approvePlan).mockRejectedValueOnce(
      new Error('Separation of duties violation: Plan creator cannot approve their own plan')
    )

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation?plan_id=plan-103']}>
          <Routes>
            <Route path="/remediation" element={<RemediationCenterPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Enable S3 Versioning')).toBeInTheDocument()

    const approveBtn = screen.getByRole('button', { name: /Approve Plan/i })
    fireEvent.click(approveBtn)

    await waitFor(() => {
      expect(screen.getByText(/Separation of duties violation/i)).toBeInTheDocument()
    })
  })

  it('executes approved plan and transitions to EXECUTED', async () => {
    const queryClient = createQueryClient()

    const mockPlan = {
      remediation_id: 'plan-104',
      finding_id: 'f-aws-s3-1',
      state: 'APPROVED',
      strategy_name: 'Restrict Security Group SSH',
      resource_id: 'sg-0123456789abcdef0',
      created_by: 'analyst-2',
      approved_by: 'admin-1',
      created_at: '2026-09-15T00:00:00Z',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(mockPlan as any)
    vi.mocked(remediationApi.getAuditEvents).mockResolvedValue([])
    vi.mocked(remediationApi.executePlan).mockResolvedValue({
      ...mockPlan,
      state: 'EXECUTED',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation?plan_id=plan-104']}>
          <Routes>
            <Route path="/remediation" element={<RemediationCenterPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Restrict Security Group SSH')).toBeInTheDocument()

    const executeBtn = screen.getByRole('button', { name: /Execute Remediation/i })
    fireEvent.click(executeBtn)

    await waitFor(() => {
      expect(remediationApi.executePlan).toHaveBeenCalledWith('plan-104')
    })
  })

  it('verifies 6-stage verification pipeline and displays Execution != Verification proof', async () => {
    const queryClient = createQueryClient()

    const mockPlan = {
      remediation_id: 'plan-105',
      finding_id: 'f-105',
      state: 'EXECUTED',
      strategy_name: 'Attach IAM Permission Boundary',
      resource_id: 'arn:aws:iam::123456789012:role/AppRole',
      created_by: 'analyst-1',
      approved_by: 'admin-1',
      created_at: '2026-09-15T00:00:00Z',
    }

    const mockFinding = {
      id: 'f-105',
      title: 'IAM Admin Policy Unrestricted',
      severity: 'HIGH',
      status: 'OPEN',
      resource_id: 'arn:aws:iam::123456789012:role/AppRole',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(mockPlan as any)
    vi.mocked(findingsApi.getFinding).mockResolvedValue(mockFinding as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation/verification?plan_id=plan-105']}>
          <Routes>
            <Route path="/remediation/verification" element={<VerificationPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    // Must clearly state execution != verification principle
    expect(await screen.findByText(/Independent Post-Remediation Verification/i)).toBeInTheDocument()
    expect(screen.getByText(/Remediation execution dispatches the API mutation, but only independent verification/i)).toBeInTheDocument()

    // Check that all 6 verification stages are displayed
    expect(await screen.findByText(/6-Stage Independent Verification Pipeline/i)).toBeInTheDocument()
    expect(screen.getByText('STAGE 01')).toBeInTheDocument()
    expect(screen.getByText('STAGE 02')).toBeInTheDocument()
    expect(screen.getByText('STAGE 03')).toBeInTheDocument()
    expect(screen.getByText('STAGE 04')).toBeInTheDocument()
    expect(screen.getByText('STAGE 05')).toBeInTheDocument()
    expect(screen.getByText('STAGE 06')).toBeInTheDocument()
  })

  it('handles verification success: transitions to VERIFIED_FIXED and confirms security state', async () => {
    const queryClient = createQueryClient()

    const verifiedPlan = {
      remediation_id: 'plan-106',
      finding_id: 'f-106',
      state: 'VERIFIED_FIXED',
      strategy_name: 'Enable CloudTrail Multi-Region',
      resource_id: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/main',
      created_by: 'analyst-1',
      approved_by: 'admin-1',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(verifiedPlan as any)
    vi.mocked(findingsApi.getFinding).mockResolvedValue({
      id: 'f-106',
      title: 'CloudTrail Inactive',
      severity: 'CRITICAL',
      status: 'RESOLVED',
      resource_id: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/main',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation/verification?plan_id=plan-106']}>
          <Routes>
            <Route path="/remediation/verification" element={<VerificationPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Finding Closed')).toBeInTheDocument()
    expect(screen.getByText('✓ Rule Passed')).toBeInTheDocument()
    expect(screen.getByText('✓ Scan Validated')).toBeInTheDocument()
  })

  it('handles verification failure cleanly without false reassurance', async () => {
    const queryClient = createQueryClient()

    const failedPlan = {
      remediation_id: 'plan-107',
      finding_id: 'f-107',
      state: 'VERIFICATION_FAILED',
      strategy_name: 'Disassociate Elastic IP',
      resource_id: 'eipalloc-12345678',
    }

    vi.mocked(remediationApi.getPlan).mockResolvedValue(failedPlan as any)
    vi.mocked(findingsApi.getFinding).mockResolvedValue({
      id: 'f-107',
      title: 'Public IP Attached',
      severity: 'HIGH',
      status: 'OPEN',
      resource_id: 'eipalloc-12345678',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation/verification?plan_id=plan-107']}>
          <Routes>
            <Route path="/remediation/verification" element={<VerificationPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Incomplete')).toBeInTheDocument()
    expect(screen.getByText('Pending Test')).toBeInTheDocument()
  })

  it('renders tamper-evident SHA-256 hash chain audit trail in Remediation Center', async () => {
    const queryClient = createQueryClient()

    const mockPlan = {
      remediation_id: 'plan-108',
      finding_id: 'f-108',
      state: 'VERIFIED_FIXED',
      strategy_name: 'Revoke Unauthorized Ingress CIDR',
      resource_id: 'sg-9876543210',
      created_by: 'analyst-1',
      approved_by: 'admin-1',
      created_at: '2026-09-15T00:00:00Z',
    }

    const mockAuditEvents = [
      {
        event_id: 'aud-1',
        remediation_id: 'plan-108',
        action: 'PLAN_CREATED',
        actor: 'analyst-1',
        sequence_number: 1,
        previous_event_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        event_hash: '3f2b8c9d0e1a2f3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b',
        timestamp: '2026-09-15T00:01:00Z',
      },
      {
        event_id: 'aud-2',
        remediation_id: 'plan-108',
        action: 'PLAN_EXECUTED',
        actor: 'admin-1',
        sequence_number: 2,
        previous_event_hash: '3f2b8c9d0e1a2f3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b',
        event_hash: '8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b3f2b8c9d0e1a2f3b4c5d6e7f',
        timestamp: '2026-09-15T00:02:00Z',
      },
    ]

    vi.mocked(remediationApi.getPlan).mockResolvedValue(mockPlan as any)
    vi.mocked(remediationApi.getAuditEvents).mockResolvedValue(mockAuditEvents as any)
    vi.mocked(remediationApi.verifyAuditChain).mockResolvedValue({ verified: true, chain_length: 2 } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/remediation?plan_id=plan-108']}>
          <Routes>
            <Route path="/remediation" element={<RemediationCenterPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('Tamper-Evident Audit Chain Ledger')).toBeInTheDocument()
    expect(await screen.findByText('SHA-256 Hash Chain Verified')).toBeInTheDocument()

    // Check event types and hashes rendered
    expect(screen.getByText('PLAN_CREATED')).toBeInTheDocument()
    expect(screen.getByText('PLAN_EXECUTED')).toBeInTheDocument()
    expect(screen.getAllByText(/3f2b8c9d0e1a2f3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b/).length).toBeGreaterThanOrEqual(1)
  })
})
