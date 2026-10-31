import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Server,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Plus,
  Copy,
  Check,
  Key,
  Layers,
  Lock,
  RefreshCw,
  Trash2,
  CheckCircle2,
  HelpCircle,
} from 'lucide-react'
import { resourcesApi } from '../../api/resourcesApi'
import { systemApi } from '../../api/systemApi'
import { accountsApi, type ConnectedAccount, type ExternalIdResponse } from '../../api/accountsApi'
import { SeverityBadge, StatusBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Drawer } from '../../components/Drawer'
import { PageHeader } from '../../components/ui/PageHeader'
import { Toolbar } from '../../components/ui/Toolbar'
import { Card, CardBody, CardFooter, CardHeader } from '../../components/ui/Card'
import type { Resource } from '../../types/resources'

interface AccountSummary {
  accountId: string
  accountName?: string
  roleArn?: string
  status?: string
  isCrossAccount?: boolean
  resources: Resource[]
  services: string[]
  regions: string[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalFindings: number
  atRiskCount: number
  secureCount: number
}

export const AccountsPage: React.FC = () => {
  const [search, setSearch] = useState('')
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null)
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false)
  const [connectStep, setConnectStep] = useState<1 | 2 | 3>(1)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  // Form State
  const [newAccountId, setNewAccountId] = useState('')
  const [newAccountName, setNewAccountName] = useState('')
  const [newRegion, setNewRegion] = useState('us-east-1')
  const [newRoleArn, setNewRoleArn] = useState('')
  const [externalIdData, setExternalIdData] = useState<ExternalIdResponse | null>(null)
  const [connectError, setConnectError] = useState<string | null>(null)
  const [connectSuccess, setConnectSuccess] = useState<string | null>(null)

  const queryClient = useQueryClient()

  const { data: modeData } = useQuery({
    queryKey: ['system', 'mode'],
    queryFn: () => systemApi.getMode(),
  })

  const { data: resData, isLoading, error } = useQuery({
    queryKey: ['resources', 'list'],
    queryFn: () => resourcesApi.listResources({ limit: 100 }),
  })

  const { data: connectedAccounts = [] } = useQuery({
    queryKey: ['accounts', 'connected'],
    queryFn: () => accountsApi.listAccounts(),
  })

  // Generate External ID Mutation
  const generateExternalIdMutation = useMutation({
    mutationFn: (targetAccountId: string) => accountsApi.generateExternalId(targetAccountId),
    onSuccess: (data) => {
      setExternalIdData(data)
      setConnectStep(2)
      setConnectError(null)
    },
    onError: (err: any) => {
      setConnectError(err?.response?.data?.detail || err.message || 'Failed to generate external ID.')
    },
  })

  // Connect Account Mutation
  const connectAccountMutation = useMutation({
    mutationFn: (payload: { account_id: string; account_name: string; role_arn: string; external_id: string; default_region: string }) =>
      accountsApi.connectAccount(payload),
    onSuccess: (res) => {
      setConnectSuccess(`Account ${res.account.account_id} connected successfully!`)
      setConnectError(null)
      queryClient.invalidateQueries({ queryKey: ['accounts', 'connected'] })
      setTimeout(() => {
        setIsConnectModalOpen(false)
        resetForm()
      }, 1500)
    },
    onError: (err: any) => {
      setConnectError(err?.response?.data?.detail || err.message || 'Failed to assume role. Check policy.')
    },
  })

  const resetForm = () => {
    setConnectStep(1)
    setNewAccountId('')
    setNewAccountName('')
    setNewRoleArn('')
    setExternalIdData(null)
    setConnectError(null)
    setConnectSuccess(null)
  }

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const resources = resData?.resources || []

  // Aggregate accounts from real resource inventory & cross-account registry
  const accountsMap = new Map<string, AccountSummary>()

  for (const r of resources) {
    const accId = r.account_id || 'unknown-account'
    let acc = accountsMap.get(accId)
    if (!acc) {
      acc = {
        accountId: accId,
        resources: [],
        services: [],
        regions: [],
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        totalFindings: 0,
        atRiskCount: 0,
        secureCount: 0,
      }
      accountsMap.set(accId, acc)
    }
    acc.resources.push(r)
    if (!acc.services.includes(r.service)) acc.services.push(r.service)
    if (r.region && !acc.regions.includes(r.region)) acc.regions.push(r.region)

    const sc = r.severity_counts || {}
    acc.criticalCount += sc.critical || 0
    acc.highCount += sc.high || 0
    acc.mediumCount += sc.medium || 0
    acc.lowCount += sc.low || 0
    acc.totalFindings += (sc.critical || 0) + (sc.high || 0) + (sc.medium || 0) + (sc.low || 0)

    if (r.posture === 'CRITICAL' || r.posture === 'HIGH_RISK' || r.posture === 'AT_RISK') {
      acc.atRiskCount++
    } else {
      acc.secureCount++
    }
  }

  // Merge connected accounts
  for (const ca of connectedAccounts) {
    let acc = accountsMap.get(ca.account_id)
    if (!acc) {
      acc = {
        accountId: ca.account_id,
        accountName: ca.account_name,
        roleArn: ca.role_arn,
        status: ca.status,
        isCrossAccount: true,
        resources: [],
        services: ['iam', 's3', 'securityhub'],
        regions: [ca.default_region || 'us-east-1'],
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        totalFindings: 0,
        atRiskCount: 0,
        secureCount: 0,
      }
      accountsMap.set(ca.account_id, acc)
    } else {
      acc.accountName = ca.account_name
      acc.roleArn = ca.role_arn
      acc.status = ca.status
      acc.isCrossAccount = true
    }
  }

  const accounts = Array.from(accountsMap.values()).filter((a) =>
    a.accountId.toLowerCase().includes(search.toLowerCase()) ||
    (a.accountName && a.accountName.toLowerCase().includes(search.toLowerCase())) ||
    a.services.some((s) => s.toLowerCase().includes(search.toLowerCase()))
  )

  const selectedAccount = selectedAccountId ? accountsMap.get(selectedAccountId) : null
  const isDemo = modeData?.mode === 'demo' || accounts.some((a) => a.accountId.includes('123456789012') || a.accountId === 'demo')

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Cloud Accounts"
        subtitle="Partitioned cloud accounts derived deterministically from discovered resources and cross-account IAM roles."
        badge={
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              padding: '2px 8px',
              fontSize: '11px',
              fontWeight: 600,
              borderRadius: 'var(--radius-sm)',
              border: isDemo ? '1px solid var(--border-warning)' : '1px solid var(--border-success)',
              background: isDemo ? 'var(--status-warning-bg)' : 'var(--status-success-bg)',
              color: isDemo ? 'var(--text-warning)' : 'var(--text-success)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}
          >
            <Radio size={12} />
            {isDemo ? 'ISOLATED SANDBOX ENVIRONMENT' : 'ACTIVE AWS CLOUD'}
          </span>
        }
        actions={
          <button
            type="button"
            onClick={() => {
              resetForm()
              setIsConnectModalOpen(true)
            }}
            style={{
              background: 'linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%)',
              color: '#ffffff',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: 'pointer',
              boxShadow: '0 2px 8px rgba(14, 165, 233, 0.3)',
            }}
          >
            <Plus size={16} />
            Connect AWS Account
          </button>
        }
      />

      {/* Toolbar */}
      <Toolbar
        searchPlaceholder="Filter by account ID or service..."
        searchValue={search}
        onSearchChange={setSearch}
        countSummary={`${accounts.length} ${accounts.length === 1 ? 'account' : 'accounts'}`}
      />

      {/* Content */}
      {isLoading ? (
        <LoadingSkeleton variant="card" count={3} height="160px" />
      ) : error ? (
        <Card variant="critical">
          <CardBody>
            <div style={{ color: 'var(--text-critical)', fontSize: '13px' }}>
              Failed to load cloud accounts: {(error as Error).message}
            </div>
          </CardBody>
        </Card>
      ) : accounts.length === 0 ? (
        <EmptyState
          icon={Globe}
          title="No Cloud Accounts Discovered"
          description="Run a cloud scan to discover resources and partition target accounts."
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 'var(--space-4)' }}>
          {accounts.map((acc) => (
            <Card
              key={acc.accountId}
              variant="elevated"
              onClick={() => setSelectedAccountId(acc.accountId)}
              style={{
                cursor: 'pointer',
                transition: 'border-color 0.15s ease, transform 0.15s ease',
              }}
            >
              <CardHeader
                title={
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <div
                      style={{
                        width: '36px',
                        height: '36px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--status-info-bg)',
                        border: '1px solid var(--border-accent)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      <Server size={18} />
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                          {acc.accountName || 'AWS Account'}
                        </span>
                        {acc.isCrossAccount && (
                          <span
                            style={{
                              fontSize: '9px',
                              padding: '1px 5px',
                              borderRadius: '4px',
                              background: 'rgba(16, 185, 129, 0.15)',
                              color: '#10b981',
                              border: '1px solid rgba(16, 185, 129, 0.3)',
                              fontWeight: 600,
                            }}
                          >
                            ASSUME ROLE
                          </span>
                        )}
                      </div>
                      <div className="font-mono" style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-high)' }}>
                        {acc.accountId}
                      </div>
                    </div>
                  </div>
                }
                action={
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', color: 'var(--text-muted)', fontSize: '12px' }}>
                    <span>Explore</span>
                    <ChevronRight size={14} />
                  </div>
                }
              />

              <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {/* Metrics Grid */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(4, 1fr)',
                    gap: 'var(--space-2)',
                    padding: 'var(--space-2) var(--space-3)',
                    background: 'var(--surface-overlay)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resources</div>
                    <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)' }}>
                      {acc.resources.length}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Services</div>
                    <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)' }}>
                      {acc.services.length}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>At Risk</div>
                    <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: acc.atRiskCount > 0 ? 'var(--text-critical)' : 'var(--text-success)' }}>
                      {acc.atRiskCount}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Findings</div>
                    <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: acc.totalFindings > 0 ? 'var(--text-high)' : 'var(--text-muted)' }}>
                      {acc.totalFindings}
                    </div>
                  </div>
                </div>

                {/* Severity Pill Breakdown */}
                <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', minHeight: '22px', alignItems: 'center' }}>
                  {acc.criticalCount > 0 && <SeverityBadge severity="CRITICAL" count={acc.criticalCount} />}
                  {acc.highCount > 0 && <SeverityBadge severity="HIGH" count={acc.highCount} />}
                  {acc.mediumCount > 0 && <SeverityBadge severity="MEDIUM" count={acc.mediumCount} />}
                  {acc.lowCount > 0 && <SeverityBadge severity="LOW" count={acc.lowCount} />}
                  {acc.totalFindings === 0 && (
                    <span style={{ fontSize: '12px', color: 'var(--text-success)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <ShieldCheck size={14} /> 0 Open Security Findings
                    </span>
                  )}
                </div>
              </CardBody>

              <CardFooter style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                  {acc.services.slice(0, 4).map((s) => (
                    <span
                      key={s}
                      className="font-mono"
                      style={{
                        padding: '2px 6px',
                        background: 'var(--surface-base)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '10px',
                        textTransform: 'uppercase',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {s}
                    </span>
                  ))}
                  {acc.services.length > 4 && (
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', alignSelf: 'center' }}>
                      +{acc.services.length - 4} more
                    </span>
                  )}
                </div>
                <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {acc.regions.join(', ') || 'us-east-1'}
                </div>
              </CardFooter>
            </Card>
          ))}
        </div>
      )}

      {/* Account Resources Drawer */}
      <Drawer
        isOpen={Boolean(selectedAccount)}
        onClose={() => setSelectedAccountId(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Account Details</span>
            <span className="font-mono" style={{ fontSize: '13px', color: 'var(--accent-primary)' }}>
              {selectedAccount?.accountId}
            </span>
          </div>
        }
        width="680px"
      >
        {selectedAccount && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: 'var(--space-3)',
                padding: 'var(--space-3)',
                background: 'var(--surface-overlay)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Account ID</div>
                <div className="font-mono" style={{ fontSize: '13px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedAccount.accountId}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Mode</div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: isDemo ? 'var(--text-warning)' : 'var(--text-success)', marginTop: '2px' }}>
                  {isDemo ? 'Sandbox Enclave' : 'Live AWS'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Resources</div>
                <div className="font-mono" style={{ fontSize: '13px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedAccount.resources.length}
                </div>
              </div>
            </div>

            <div>
              <h3 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 var(--space-3) 0' }}>
                Discovered Resources ({selectedAccount.resources.length})
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {selectedAccount.resources.map((res) => (
                  <div
                    key={res.resource_id}
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--surface-overlay)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 'var(--space-2)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>
                        {res.resource_name || res.resource_id}
                      </span>
                      <StatusBadge status={res.posture || res.security_posture || 'SECURE'} />
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-2)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span className="font-mono uppercase">{res.service}</span>
                      <span>•</span>
                      <span className="font-mono">{res.resource_type}</span>
                      <span>•</span>
                      <span className="font-mono">{res.region || 'global'}</span>
                    </div>
                    {res.resource_arn && (
                      <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {res.resource_arn}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Drawer>
      {/* Connect AWS Account Wizard Drawer */}
      <Drawer
        isOpen={isConnectModalOpen}
        onClose={() => {
          setIsConnectModalOpen(false)
          resetForm()
        }}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Key size={18} style={{ color: '#0ea5e9' }} />
            <span>Connect External AWS Account</span>
          </div>
        }
        width="650px"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {/* Stepper Header */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '12px 16px',
              background: 'var(--surface-overlay)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {[
              { num: 1, title: 'Account Details' },
              { num: 2, title: 'Deploy IAM Role' },
              { num: 3, title: 'Verify & Link' },
            ].map((s) => (
              <div
                key={s.num}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  opacity: connectStep === s.num ? 1 : 0.6,
                }}
              >
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background:
                      connectStep > s.num
                        ? 'var(--status-success-bg)'
                        : connectStep === s.num
                        ? '#0ea5e9'
                        : 'var(--surface-base)',
                    color: connectStep > s.num ? '#10b981' : '#ffffff',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  {connectStep > s.num ? <Check size={12} /> : s.num}
                </div>
                <span
                  style={{
                    fontSize: '12px',
                    fontWeight: connectStep === s.num ? 600 : 400,
                    color: connectStep === s.num ? 'var(--text-high)' : 'var(--text-muted)',
                  }}
                >
                  {s.title}
                </span>
              </div>
            ))}
          </div>

          {/* Error / Success Alerts */}
          {connectError && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#f87171',
                fontSize: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <AlertTriangle size={16} />
              <span>{connectError}</span>
            </div>
          )}

          {connectSuccess && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: '#34d399',
                fontSize: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <CheckCircle2 size={16} />
              <span>{connectSuccess}</span>
            </div>
          )}

          {/* STEP 1: Account Information */}
          {connectStep === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Target AWS Account ID (12 digits) *
                </label>
                <input
                  type="text"
                  placeholder="e.g. 123456789012"
                  value={newAccountId}
                  onChange={(e) => setNewAccountId(e.target.value.replace(/\D/g, '').slice(0, 12))}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-high)',
                    fontSize: '13px',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '4px',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Account Friendly Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. Production US-East Workload"
                  value={newAccountName}
                  onChange={(e) => setNewAccountName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-high)',
                    fontSize: '13px',
                    marginTop: '4px',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Default AWS Region
                </label>
                <select
                  value={newRegion}
                  onChange={(e) => setNewRegion(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-high)',
                    fontSize: '13px',
                    marginTop: '4px',
                  }}
                >
                  <option value="us-east-1">US East (N. Virginia) us-east-1</option>
                  <option value="us-east-2">US East (Ohio) us-east-2</option>
                  <option value="us-west-2">US West (Oregon) us-west-2</option>
                  <option value="eu-west-1">EU (Ireland) eu-west-1</option>
                  <option value="ap-south-1">Asia Pacific (Mumbai) ap-south-1</option>
                </select>
              </div>

              <div
                style={{
                  background: 'var(--surface-overlay)',
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '12px',
                  color: 'var(--text-muted)',
                  lineHeight: '1.5',
                }}
              >
                🔒 <strong>Cryptographic Isolation:</strong> CloudGuard uses AWS STS AssumeRole with a unique, cryptographically generated <code>ExternalId</code> for every tenant. This guarantees absolute isolation and mitigates the Confused Deputy vulnerability.
              </div>

              <button
                type="button"
                disabled={newAccountId.length !== 12 || generateExternalIdMutation.isPending}
                onClick={() => generateExternalIdMutation.mutate(newAccountId)}
                style={{
                  marginTop: 'var(--space-2)',
                  padding: '10px 16px',
                  background: newAccountId.length === 12 ? '#0ea5e9' : 'var(--surface-overlay)',
                  color: newAccountId.length === 12 ? '#ffffff' : 'var(--text-muted)',
                  border: 'none',
                  borderRadius: 'var(--radius-md)',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: newAccountId.length === 12 ? 'pointer' : 'not-allowed',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                }}
              >
                {generateExternalIdMutation.isPending ? <RefreshCw size={14} className="animate-spin" /> : <ChevronRight size={16} />}
                Generate External ID & Template
              </button>
            </div>
          )}

          {/* STEP 2: Deploy IAM Role */}
          {connectStep === 2 && externalIdData && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div
                style={{
                  background: 'rgba(14, 165, 233, 0.08)',
                  border: '1px solid rgba(14, 165, 233, 0.25)',
                  padding: '12px 14px',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ fontSize: '11px', color: '#38bdf8', textTransform: 'uppercase', fontWeight: 600 }}>
                  Assigned External ID (Cryptographic Token)
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
                  <code style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                    {externalIdData.external_id}
                  </code>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(externalIdData.external_id, 'extId')}
                    style={{
                      background: 'transparent',
                      border: '1px solid rgba(255, 255, 255, 0.15)',
                      color: copiedKey === 'extId' ? '#10b981' : 'var(--text-muted)',
                      borderRadius: '4px',
                      padding: '4px 8px',
                      fontSize: '11px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    {copiedKey === 'extId' ? <Check size={12} /> : <Copy size={12} />}
                    {copiedKey === 'extId' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Option A: 1-Click CloudFormation */}
              <div
                style={{
                  padding: '14px',
                  background: 'var(--surface-overlay)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Layers size={16} style={{ color: '#0ea5e9' }} />
                  Option A: 1-Click CloudFormation Stack
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '6px 0 12px 0' }}>
                  Deploy the read-only audit role automatically in your AWS console with pre-configured trust policies.
                </p>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <a
                    href={externalIdData.quick_launch_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      padding: '8px 14px',
                      background: '#0ea5e9',
                      color: '#ffffff',
                      textDecoration: 'none',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    Launch CloudFormation Stack
                    <ExternalLink size={13} />
                  </a>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(externalIdData.cloudformation_template, 'cfn')}
                    style={{
                      padding: '8px 14px',
                      background: 'var(--surface-base)',
                      color: copiedKey === 'cfn' ? '#10b981' : 'var(--text-high)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    {copiedKey === 'cfn' ? <Check size={13} /> : <Copy size={13} />}
                    {copiedKey === 'cfn' ? 'Template Copied' : 'Copy Template YAML'}
                  </button>
                </div>
              </div>

              {/* Option B: Manual IAM Role */}
              <div
                style={{
                  padding: '14px',
                  background: 'var(--surface-overlay)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={16} style={{ color: '#10b981' }} />
                  Option B: Manual IAM Role Creation
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '6px 0 10px 0' }}>
                  Create role <code>CloudGuardSecurityAuditRole</code> with this Trust Relationship:
                </p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(JSON.stringify(externalIdData.trust_policy, null, 2), 'trust')}
                    style={{
                      padding: '6px 12px',
                      background: 'var(--surface-base)',
                      border: '1px solid var(--border-subtle)',
                      color: copiedKey === 'trust' ? '#10b981' : 'var(--text-secondary)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '11px',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    {copiedKey === 'trust' ? <Check size={12} /> : <Copy size={12} />}
                    Copy Trust Policy JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(JSON.stringify(externalIdData.permissions_policy, null, 2), 'perm')}
                    style={{
                      padding: '6px 12px',
                      background: 'var(--surface-base)',
                      border: '1px solid var(--border-subtle)',
                      color: copiedKey === 'perm' ? '#10b981' : 'var(--text-secondary)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '11px',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    {copiedKey === 'perm' ? <Check size={12} /> : <Copy size={12} />}
                    Copy SecurityAudit Policy JSON
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 'var(--space-2)' }}>
                <button
                  type="button"
                  onClick={() => setConnectStep(1)}
                  style={{
                    padding: '8px 14px',
                    background: 'transparent',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-muted)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '12px',
                    cursor: 'pointer',
                  }}
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (!newRoleArn) {
                      setNewRoleArn(`arn:aws:iam::${newAccountId}:role/CloudGuardSecurityAuditRole`)
                    }
                    setConnectStep(3)
                  }}
                  style={{
                    padding: '8px 18px',
                    background: '#0ea5e9',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  Next: Enter Role ARN
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}

          {/* STEP 3: Verify & Link */}
          {connectStep === 3 && externalIdData && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Target Role ARN *
                </label>
                <input
                  type="text"
                  placeholder={`arn:aws:iam::${newAccountId}:role/CloudGuardSecurityAuditRole`}
                  value={newRoleArn}
                  onChange={(e) => setNewRoleArn(e.target.value.trim())}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-high)',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '4px',
                  }}
                />
              </div>

              <div
                style={{
                  background: 'var(--surface-overlay)',
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '12px',
                  color: 'var(--text-muted)',
                }}
              >
                <div><strong>Verifying Connection:</strong></div>
                CloudGuard will execute an <code>sts:AssumeRole</code> call using your target Role ARN and External ID to verify permissions before finalizing registration.
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 'var(--space-2)' }}>
                <button
                  type="button"
                  onClick={() => setConnectStep(2)}
                  style={{
                    padding: '8px 14px',
                    background: 'transparent',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-muted)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '12px',
                    cursor: 'pointer',
                  }}
                >
                  Back
                </button>
                <button
                  type="button"
                  disabled={!newRoleArn.startsWith('arn:aws:iam::') || connectAccountMutation.isPending}
                  onClick={() =>
                    connectAccountMutation.mutate({
                      account_id: newAccountId,
                      account_name: newAccountName || `AWS Account ${newAccountId}`,
                      role_arn: newRoleArn,
                      external_id: externalIdData.external_id,
                      default_region: newRegion,
                    })
                  }
                  style={{
                    padding: '10px 18px',
                    background: newRoleArn.startsWith('arn:aws:iam::') ? '#10b981' : 'var(--surface-overlay)',
                    color: newRoleArn.startsWith('arn:aws:iam::') ? '#ffffff' : 'var(--text-muted)',
                    border: 'none',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: newRoleArn.startsWith('arn:aws:iam::') ? 'pointer' : 'not-allowed',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  {connectAccountMutation.isPending ? <RefreshCw size={14} className="animate-spin" /> : <ShieldCheck size={16} />}
                  Test & Link AWS Account
                </button>
              </div>
            </div>
          )}
        </div>
      </Drawer>
    </div>
  )
}
