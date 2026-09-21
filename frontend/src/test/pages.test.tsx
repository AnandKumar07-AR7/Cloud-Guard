import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import React from 'react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '../auth/AuthContext'
import { OverviewPage } from '../pages/overview/OverviewPage'
import { RulesPage } from '../pages/security/RulesPage'
import { MCPServersPage } from '../pages/system/MCPServersPage'
import { PolicyAutomationPage } from '../pages/system/PolicyAutomationPage'

import { postureApi } from '../api/postureApi'
import { scansApi } from '../api/scansApi'
import { findingsApi } from '../api/findingsApi'
import { rulesApi } from '../api/rulesApi'
import { mcpApi } from '../api/mcpApi'
import { automationApi } from '../api/automationApi'
import { aiApi } from '../api/aiApi'

vi.mock('../api/postureApi')
vi.mock('../api/scansApi')
vi.mock('../api/findingsApi')
vi.mock('../api/rulesApi')
vi.mock('../api/mcpApi')
vi.mock('../api/automationApi')
vi.mock('../api/aiApi')

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

describe('Flagship Command Center Pages', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders Command Enclave with real posture score and metrics', async () => {
    vi.mocked(postureApi.getPosture).mockResolvedValue({
      posture_score: 87.5,
      risk_level: 'MEDIUM',
      critical_findings: 1,
      high_findings: 3,
      medium_findings: 5,
      low_findings: 2,
      total_findings: 11,
      total_resources: 42,
      service_posture: {
        s3: {
          posture_score: 90,
          risk_level: 'LOW',
          total_resources: 1,
          total_findings: 2,
          critical_findings: 0,
          high_findings: 0,
          medium_findings: 2,
          low_findings: 0,
        },
      },
      resource_posture_summary: { SECURE: 35, AT_RISK: 7, HIGH_RISK: 0, CRITICAL: 0 },
      last_scanned_at: '2026-09-15T10:00:00Z',
    })

    vi.mocked(scansApi.listScans).mockResolvedValue({
      items: [
        {
          scan_id: 'scan-101',
          correlation_id: 'corr-101',
          provider: 'demo',
          account_id: '123456789012',
          mode: 'demo',
          status: 'COMPLETED',
          regions: ['us-east-1'],
          resource_count: 42,
          finding_count: 11,
          started_at: '2026-09-15T10:00:00Z',
          error_count: 0,
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    })

    vi.mocked(findingsApi.listFindings).mockResolvedValue({
      items: [
        {
          finding_id: 'find-001',
          canonical_id: 'can-001',
          rule_id: 's3-bucket-public-read-prohibited',
          scan_id: 'scan-101',
          resource_id: 'prod-data-bucket',
          resource_type: 'aws_s3_bucket',
          service: 's3',
          account_id: '123456789012',
          region: 'us-east-1',
          provider: 'demo',
          severity: 'critical',
          risk_score: 85,
          status: 'OPEN',
          title: 'S3 Bucket Allows Public Read Access',
          description: 'Bucket policy allows anonymous principals.',
          category: 'access-control',
          evidence: { rule_id: 's3-bucket-public-read-prohibited', summary: 'Public access enabled' },
          internet_exposed: true,
          detected_at: '2026-09-15T10:00:00Z',
          updated_at: '2026-09-15T10:00:00Z',
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    })

    vi.mocked(aiApi.listRuns).mockResolvedValue([
      {
        run_id: 'run-001',
        finding_id: 'find-001',
        initiating_user_id: 'usr-admin',
        status: 'COMPLETED',
        agent_version: '1.0.0',
        agent_name: 'triage_agent',
        created_at: '2026-09-15T10:00:00Z',
        started_at: '2026-09-15T10:00:00Z',
        completed_at: '2026-09-15T10:01:00Z',
        duration_ms: 60000,
      },
    ])

    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <AuthProvider>
          <MemoryRouter>
            <OverviewPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('COMMAND ENCLAVE')).toBeInTheDocument()
      expect(screen.getByText(/RISK LEVEL: MEDIUM/)).toBeInTheDocument()
      expect(screen.getByText('S3 Bucket Allows Public Read Access')).toBeInTheDocument()
    })
  })

  it('renders Detection Rules catalog with real rules list', async () => {
    vi.mocked(rulesApi.listRules).mockResolvedValue({
      items: [
        {
          rule_id: 'iam-root-access-key-prohibited',
          name: 'Root Account Access Keys Should Not Exist',
          description: 'Active access keys on the AWS root user account violate security best practices.',
          provider: 'aws',
          service: 'iam',
          resource_type: 'aws_iam_account_summary',
          severity: 'CRITICAL',
          category: 'access-control',
          rationale: 'Root account credentials possess unrestricted privileges.',
          remediation: 'Delete root access keys immediately.',
          enabled: true,
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    })

    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <AuthProvider>
          <MemoryRouter>
            <RulesPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('Detection Rules Catalog')).toBeInTheDocument()
      expect(screen.getByText('Root Account Access Keys Should Not Exist')).toBeInTheDocument()
      expect(screen.getByText('iam-root-access-key-prohibited')).toBeInTheDocument()
    })
  })

  it('renders MCP Control Center with servers and tool schemas', async () => {
    vi.mocked(mcpApi.listServers).mockResolvedValue([
      {
        server_id: 'cloudguard-security-mcp',
        server_name: 'cloudguard-security-mcp',
        version: '1.0.0',
        server_type: 'in-process',
        status: 'healthy',
        enabled: true,
        permission_scope: ['security.*'],
        request_count: 142,
        error_count: 0,
        avg_latency_ms: 4.2,
        last_health_check: '2026-09-15T10:00:00Z',
        tool_count: 8,
      },
    ])

    vi.mocked(mcpApi.listTools).mockResolvedValue([
      {
        tool_id: 'cloudguard-security-mcp:evaluate_posture',
        server_id: 'cloudguard-security-mcp',
        tool_name: 'evaluate_posture',
        description: 'Calculate mathematical posture score and service risk metrics.',
        operation_class: 'READ',
        required_permission: 'mcp.read',
        enabled: true,
        version: '1.0.0',
        input_schema: { type: 'object', properties: {} },
      },
    ])

    vi.mocked(mcpApi.listAllTools).mockResolvedValue([
      {
        tool_id: 'cloudguard-security-mcp:evaluate_posture',
        server_id: 'cloudguard-security-mcp',
        tool_name: 'evaluate_posture',
        description: 'Calculate mathematical posture score and service risk metrics.',
        operation_class: 'READ',
        required_permission: 'mcp.read',
        enabled: true,
        version: '1.0.0',
        input_schema: { type: 'object', properties: {} },
      },
    ])

    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <AuthProvider>
          <MemoryRouter>
            <MCPServersPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('MCP Control Center')).toBeInTheDocument()
      expect(screen.getAllByText('cloudguard-security-mcp').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('evaluate_posture')).toBeInTheDocument()
    })
  })

  it('renders Policy Automation with Kill Switch status', async () => {
    vi.mocked(automationApi.listPolicies).mockResolvedValue([
      {
        policy_id: 'pol-auto-s3',
        name: 'Auto-Remediate Public S3 Buckets',
        description: 'Automatically validate and progress S3 bucket fixes.',
        enabled: true,
        priority: 10,
        require_human_approval: false,
        allowed_rule_ids: ['s3-bucket-public-read-prohibited'],
        allowed_safety_levels: ['SAFE_AUTOMATIC'],
        created_at: '2026-09-15T10:00:00Z',
      },
    ])

    vi.mocked(automationApi.getKillSwitchStatus).mockResolvedValue({
      enabled: false,
      active: false,
    })

    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <AuthProvider>
          <MemoryRouter>
            <PolicyAutomationPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    )

    await waitFor(() => {
      expect(screen.getByText('Global Automation Kill Switch')).toBeInTheDocument()
      expect(screen.getByText('NORMAL OPERATION')).toBeInTheDocument()
      expect(screen.getByText('Auto-Remediate Public S3 Buckets')).toBeInTheDocument()
    })
  })
})
