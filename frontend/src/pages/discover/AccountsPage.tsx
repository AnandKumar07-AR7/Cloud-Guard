import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Server,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react'
import { resourcesApi } from '../../api/resourcesApi'
import { systemApi } from '../../api/systemApi'
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

  const { data: modeData } = useQuery({
    queryKey: ['system', 'mode'],
    queryFn: () => systemApi.getMode(),
  })

  const { data: resData, isLoading, error } = useQuery({
    queryKey: ['resources', 'list'],
    queryFn: () => resourcesApi.listResources({ limit: 100 }),
  })

  const resources = resData?.resources || []

  // Aggregate accounts honestly from real resource inventory
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

  const accounts = Array.from(accountsMap.values()).filter((a) =>
    a.accountId.toLowerCase().includes(search.toLowerCase()) ||
    a.services.some((s) => s.toLowerCase().includes(search.toLowerCase()))
  )

  const selectedAccount = selectedAccountId ? accountsMap.get(selectedAccountId) : null
  const isDemo = modeData?.mode === 'demo' || accounts.some((a) => a.accountId.includes('123456789012') || a.accountId === 'demo')

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Cloud Accounts"
        subtitle="Partitioned cloud accounts derived deterministically from discovered resources."
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
                      <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                        AWS Account
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
    </div>
  )
}
