import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FindingsPage } from '../pages/security/FindingsPage'
import { FindingDetailPage } from '../pages/security/FindingDetailPage'
import { FindingInvestigationPage } from '../pages/security/FindingInvestigationPage'
import { findingsApi } from '../api/findingsApi'
import { scansApi } from '../api/scansApi'
import { aiApi } from '../api/aiApi'

vi.mock('../api/findingsApi')
vi.mock('../api/scansApi')
vi.mock('../api/aiApi')
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
    },
  })

const mockFinding = {
  finding_id: 'find-s3-001',
  canonical_id: 'can-s3-001',
  rule_id: 's3-bucket-public-read-prohibited',
  scan_id: 'scan-uuid-101',
  resource_id: 'arn:aws:s3:::customer-pii-data',
  resource_type: 'aws_s3_bucket',
  resource_name: 'customer-pii-data',
  service: 's3',
  account_id: '123456789012',
  region: 'us-east-1',
  provider: 'demo',
  severity: 'critical',
  risk_score: 100,
  status: 'OPEN',
  title: 'S3 Bucket Public Read Access Permitted',
  description: 'Bucket policy or ACL explicitly allows public anonymous access.',
  remediation_guidance: 'Apply S3 Public Access Block and revoke anonymous principals.',
  category: 'access-control',
  evidence: {
    rule_id: 's3-bucket-public-read-prohibited',
    field_path: 'Policy.Statement[0].Principal',
    observed_value: '*',
    expected_value: 'Restricted IAM ARN',
    summary: 'Public anonymous read access enabled on bucket customer-pii-data.',
  },
  internet_exposed: true,
  is_internet_exposed: true,
  detected_at: '2026-09-15T10:00:00Z',
  updated_at: '2026-09-15T10:00:00Z',
}

describe('Findings & Tri-Partite Investigation Behavioral Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('renders Findings list with multi-facet filters and handles filter interactions', async () => {
    const queryClient = createQueryClient()

    vi.mocked(scansApi.listScans).mockResolvedValue({
      items: [
        {
          scan_id: 'scan-uuid-101',
          correlation_id: 'c-101',
          provider: 'demo',
          account_id: '123456789012',
          mode: 'demo',
          status: 'COMPLETED',
          regions: ['us-east-1'],
          resource_count: 5,
          finding_count: 1,
          started_at: '2026-09-15T10:00:00Z',
          error_count: 0,
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    } as any)

    vi.mocked(findingsApi.listFindings).mockResolvedValue({
      findings: [mockFinding],
      items: [mockFinding],
      total: 1,
      limit: 25,
      offset: 0,
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/findings']}>
          <FindingsPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(findingsApi.listFindings).toHaveBeenCalled()
      expect(screen.getByText('Security Findings')).toBeInTheDocument()
      expect(screen.getByText('S3 Bucket Public Read Access Permitted')).toBeInTheDocument()
      expect(screen.getByText('customer-pii-data')).toBeInTheDocument()
    })

    // Verify filter dropdowns exist
    const selects = screen.getAllByRole('combobox')
    expect(selects.length).toBeGreaterThanOrEqual(3)

    // Click Internet Exposed filter button
    const exposedBtn = screen.getByRole('button', { name: /Internet Exposed/i })
    fireEvent.click(exposedBtn)

    await waitFor(() => {
      expect(findingsApi.listFindings).toHaveBeenCalled()
    })
  })

  it('renders Finding Detail page with deterministic technical context and safe JSON evidence', async () => {
    const queryClient = createQueryClient()

    vi.mocked(findingsApi.getFinding).mockResolvedValue(mockFinding as any)
    vi.mocked(findingsApi.getFindingHistory).mockResolvedValue({
      canonical_id: 'can-s3-001',
      occurrences: 1,
      history: [
        {
          finding_id: 'find-s3-001',
          scan_id: 'scan-uuid-101',
          status: 'OPEN',
          severity: 'critical',
          last_detected_at: '2026-09-15T10:00:00Z',
        },
      ],
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/findings/find-s3-001']}>
          <Routes>
            <Route path="/findings/:id" element={<FindingDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('S3 Bucket Public Read Access Permitted')).toBeInTheDocument()
    expect(await screen.findByText('s3-bucket-public-read-prohibited')).toBeInTheDocument()
    const evidenceItems = await screen.findAllByText(/Public anonymous read access enabled on bucket/i)
    expect(evidenceItems.length).toBeGreaterThanOrEqual(1)
    expect(await screen.findByText(/Scan: scan-uuid-101/i)).toBeInTheDocument()
  })

  it('Flagship Investigation screen strictly separates Observed Facts, AI Inferences, and Recommendations', async () => {
    const queryClient = createQueryClient()

    vi.mocked(findingsApi.getInvestigation).mockResolvedValue({
      finding: mockFinding,
      rule: {
        rule_id: 's3-bucket-public-read-prohibited',
        name: 'Prohibit Public S3 Buckets',
        description: 'Enforces private bucket access',
        severity: 'critical',
        service: 's3',
      },
      resource: {
        resource_id: 'arn:aws:s3:::customer-pii-data',
        resource_type: 'aws_s3_bucket',
        service: 's3',
        account_id: '123456789012',
        region: 'us-east-1',
      },
      evidence: mockFinding.evidence,
      related_resources: [],
      related_findings: [],
      ai_analysis: {
        executive_summary: 'Critical data exposure risk requiring immediate S3 Public Access Block.',
        technical_analysis: 'The bucket policy explicitly designates principal * with unrestricted s3:GetObject action.',
        business_impact: 'Unauthorized exfiltration of sensitive regulatory customer records.',
        attack_relevance: 'T1530: Cloud Storage Object Discovery and Mass Data Transfer',
        recommended_action: 'Apply S3 Public Access Block and revoke anonymous principals.',
        confidence: 'HIGH',
        ai_source: 'Gemini Pro SecOps',
      },
    } as any)

    vi.mocked(findingsApi.getFindingHistory).mockResolvedValue({
      canonical_id: 'can-s3-001',
      occurrences: 1,
      history: [],
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/findings/find-s3-001/investigation']}>
          <Routes>
            <Route path="/findings/:id/investigation" element={<FindingInvestigationPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    )

    // Panel 1: Observed Facts (Deterministic Telemetry)
    expect(await screen.findByText('Observed Facts')).toBeInTheDocument()
    expect(await screen.findByText('Deterministic Telemetry')).toBeInTheDocument()
    expect(await screen.findByText('Target Resource Context')).toBeInTheDocument()

    // Panel 2: AI Inferences (Advisory Intelligence)
    expect(await screen.findByText('AI Inferences')).toBeInTheDocument()
    expect(await screen.findByText('Advisory Intelligence')).toBeInTheDocument()
    expect(await screen.findByText(/Critical data exposure risk requiring immediate S3 Public Access Block/i)).toBeInTheDocument()
    expect(await screen.findByText(/Unauthorized exfiltration of sensitive regulatory customer records/i)).toBeInTheDocument()

    // Panel 3: Recommendations (Actionable Control)
    expect(await screen.findByText('Remediation Guidance')).toBeInTheDocument()
    expect(await screen.findByText('Actionable Control')).toBeInTheDocument()
    expect(await screen.findByText(/Apply S3 Public Access Block/i)).toBeInTheDocument()
  })

  it('renders truthful empty state when no findings match the filter criteria', async () => {
    const queryClient = createQueryClient()

    vi.mocked(scansApi.listScans).mockResolvedValue({ items: [], total: 0, limit: 10, offset: 0 } as any)
    vi.mocked(findingsApi.listFindings).mockResolvedValue({
      findings: [],
      items: [],
      total: 0,
      limit: 25,
      offset: 0,
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/findings']}>
          <FindingsPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('No Findings Found')).toBeInTheDocument()
      expect(screen.getByText(/No security misconfigurations detected in the selected scan/i)).toBeInTheDocument()
    })
  })
})
