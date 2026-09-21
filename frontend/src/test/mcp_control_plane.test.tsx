import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MCPServersPage } from '../pages/system/MCPServersPage'
import { mcpApi } from '../api/mcpApi'

vi.mock('../api/mcpApi')
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'admin-1', username: 'admin', role: 'ADMIN', email: 'admin@cloudguard.internal' },
    isAuthenticated: true,
    hasPermission: () => true,
  }),
}))

const createQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

const mockServers = [
  {
    server_id: 'aws-read-only',
    server_name: 'AWS Read-Only Server',
    description: 'Provides read-only MCP access to AWS services',
    version: '1.0.0',
    server_type: 'READ_ONLY',
    status: 'healthy',
    enabled: true,
    tool_count: 5,
    request_count: 150,
    error_count: 0,
    avg_latency_ms: 24.5,
    permission_scope: ['mcp:read'],
    created_at: '2026-09-15T00:00:00Z',
  },
  {
    server_id: 'aws-remediation',
    server_name: 'AWS Remediation Server',
    description: 'Executes verified remediation actions with strict governance',
    version: '1.0.0',
    server_type: 'REMEDIATION',
    status: 'healthy',
    enabled: true,
    tool_count: 3,
    request_count: 30,
    error_count: 1,
    avg_latency_ms: 45.2,
    permission_scope: ['mcp:write', 'mcp:destructive'],
    created_at: '2026-09-15T00:00:00Z',
  },
]

const mockTools = [
  {
    tool_id: 't-1',
    tool_name: 's3_get_bucket_policy',
    server_id: 'aws-read-only',
    description: 'Retrieve S3 bucket policy and public access configuration',
    operation_class: 'READ',
    required_permission: 'mcp:read',
    enabled: true,
    version: '1.0.0',
    input_schema: {
      type: 'object',
      properties: {
        bucket_name: { type: 'string', description: 'Name of the S3 bucket' },
      },
      required: ['bucket_name'],
    },
  },
  {
    tool_id: 't-2',
    tool_name: 'ec2_describe_instances',
    server_id: 'aws-read-only',
    description: 'Enumerate EC2 instances and network interfaces',
    operation_class: 'READ',
    required_permission: 'mcp:read',
    enabled: true,
    version: '1.0.0',
    input_schema: {
      type: 'object',
      properties: {
        filters: { type: 'object' },
      },
    },
  },
  {
    tool_id: 't-3',
    tool_name: 's3_put_bucket_encryption',
    server_id: 'aws-remediation',
    description: 'Enforce default AES-256 or KMS encryption on S3 bucket',
    operation_class: 'WRITE',
    required_permission: 'mcp:write',
    enabled: true,
    version: '1.0.0',
    input_schema: {
      type: 'object',
      properties: {
        bucket_name: { type: 'string' },
        kms_key_id: { type: 'string' },
      },
      required: ['bucket_name'],
    },
  },
  {
    tool_id: 't-4',
    tool_name: 'iam_delete_access_key',
    server_id: 'aws-remediation',
    description: 'Permanently revoke an active AWS IAM user access key',
    operation_class: 'DESTRUCTIVE',
    required_permission: 'mcp:destructive',
    enabled: true,
    version: '1.0.0',
    input_schema: {
      type: 'object',
      properties: {
        user_name: { type: 'string' },
        access_key_id: { type: 'string' },
      },
      required: ['user_name', 'access_key_id'],
    },
  },
]

describe('Phase 11 MCP Control Plane Behavioral Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(mcpApi.listServers).mockResolvedValue(mockServers as any)
    vi.mocked(mcpApi.listTools).mockResolvedValue(mockTools as any)
    vi.mocked(mcpApi.listAllTools).mockResolvedValue(mockTools as any)
    vi.mocked(mcpApi.getAuditLogs).mockResolvedValue([] as any)
  })

  it('renders MCP Control Center with registered servers, health status, and tool counts', async () => {
    const queryClient = createQueryClient()

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('MCP Control Center')).toBeInTheDocument()

    // Verify servers rendered
    expect(await screen.findByText('AWS Read-Only Server')).toBeInTheDocument()
    expect(screen.getByText('AWS Remediation Server')).toBeInTheDocument()

    // Verify tools rendered with operation class
    expect(screen.getByText('s3_get_bucket_policy')).toBeInTheDocument()
    expect(screen.getByText('s3_put_bucket_encryption')).toBeInTheDocument()
    expect(screen.getByText('iam_delete_access_key')).toBeInTheDocument()
  })

  it('classifies tools into distinct semantic operation classes: READ, WRITE, DESTRUCTIVE', async () => {
    const queryClient = createQueryClient()

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('s3_get_bucket_policy')).toBeInTheDocument()

    // Check operation class tags exist
    const readBadges = screen.getAllByText('READ')
    expect(readBadges.length).toBeGreaterThanOrEqual(2)

    const writeBadges = screen.getAllByText('WRITE')
    expect(writeBadges.length).toBeGreaterThanOrEqual(1)

    const destructiveBadges = screen.getAllByText('DESTRUCTIVE')
    expect(destructiveBadges.length).toBeGreaterThanOrEqual(1)
  })

  it('inspects JSON Schema parameters in the Schema Drawer', async () => {
    const queryClient = createQueryClient()

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('s3_get_bucket_policy')).toBeInTheDocument()

    // Click "Schema" button for s3_get_bucket_policy
    const schemaButtons = screen.getAllByRole('button', { name: /Schema/i })
    fireEvent.click(schemaButtons[0])

    // Drawer should open and display parameters schema
    expect(await screen.findByText(/Tool Specification:/i)).toBeInTheDocument()
    expect(screen.getByText(/bucket_name/i)).toBeInTheDocument()
  })

  it('performs governed tool invocation with valid parameters', async () => {
    const queryClient = createQueryClient()
    vi.mocked(mcpApi.invokeTool).mockResolvedValueOnce({
      success: true,
      request_id: 'req-123',
      data: {
        status: 'SUCCESS',
        result: { Policy: '{"Version":"2012-10-17","Statement":[]}' },
      },
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('s3_get_bucket_policy')).toBeInTheDocument()

    // Click "Test" button
    const testButtons = screen.getAllByRole('button', { name: /Test/i })
    fireEvent.click(testButtons[0])

    expect(await screen.findByText(/Invoke MCP Tool:/i)).toBeInTheDocument()

    // Enter JSON arguments
    const textarea = screen.getByRole('textbox')
    fireEvent.change(textarea, { target: { value: '{"bucket_name": "prod-data"}' } })

    const executeBtn = screen.getByRole('button', { name: /Invoke Tool/i })
    fireEvent.click(executeBtn)

    await waitFor(() => {
      expect(mcpApi.invokeTool).toHaveBeenCalledWith('aws-read-only', 's3_get_bucket_policy', {
        bucket_name: 'prod-data',
      })
    })

    expect(await screen.findByText(/Invocation Result \(Success\):/i)).toBeInTheDocument()
  })

  it('handles invocation rejection when invalid JSON is provided', async () => {
    const queryClient = createQueryClient()

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('s3_get_bucket_policy')).toBeInTheDocument()

    const testButtons = screen.getAllByRole('button', { name: /Test/i })
    fireEvent.click(testButtons[0])

    expect(await screen.findByText(/Invoke MCP Tool:/i)).toBeInTheDocument()

    // Supply malformed JSON
    const textarea = screen.getByRole('textbox')
    fireEvent.change(textarea, { target: { value: '{malformed_json:' } })

    const executeBtn = screen.getByRole('button', { name: /Invoke Tool/i })
    fireEvent.click(executeBtn)

    expect(await screen.findByText(/Invalid JSON format for arguments/i)).toBeInTheDocument()
    expect(mcpApi.invokeTool).not.toHaveBeenCalled()
  })

  it('toggles server enabled status via mutation', async () => {
    const queryClient = createQueryClient()
    vi.mocked(mcpApi.toggleServer).mockResolvedValueOnce({
      server_id: 'aws-read-only',
      enabled: false,
      status: 'disabled',
    } as any)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <MCPServersPage />
        </MemoryRouter>
      </QueryClientProvider>
    )

    expect(await screen.findByText('AWS Read-Only Server')).toBeInTheDocument()

    // Click toggle button for server (initially ENABLED)
    const toggleButtons = screen.getAllByRole('button', { name: 'ENABLED' })
    fireEvent.click(toggleButtons[0])

    await waitFor(() => {
      expect(mcpApi.toggleServer).toHaveBeenCalledWith('aws-read-only', false)
    })
  })
})
