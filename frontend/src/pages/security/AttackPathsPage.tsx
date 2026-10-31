import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Info, ShieldAlert, Network } from 'lucide-react'
import { resourcesApi } from '../../api/resourcesApi'
import { findingsApi } from '../../api/findingsApi'
import { EmptyState } from '../../components/EmptyState'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'

export const AttackPathsPage: React.FC = () => {
  const { data: resData, isLoading } = useQuery({
    queryKey: ['resources', 'topology'],
    queryFn: () => resourcesApi.listResources({ limit: 50 }),
  })

  const { data: findingsData } = useQuery({
    queryKey: ['findings', 'exposed'],
    queryFn: () => findingsApi.listFindings({ internet_exposed: true }),
  })

  const exposedFindings = findingsData?.findings || []

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Attack Paths & Lateral Movement"
        subtitle="Visualizing potential exploitation paths from internet-exposed ingress points to high-privilege targets."
      />

      {/* Truthful Backend Capability Notice */}
      <div
        style={{
          padding: 'var(--space-3) var(--space-4)',
          background: 'var(--status-info-bg)',
          border: '1px solid var(--border-accent)',
          borderRadius: 'var(--radius-md)',
          display: 'flex',
          gap: 'var(--space-3)',
          alignItems: 'flex-start',
        }}
      >
        <Info size={17} style={{ color: 'var(--accent-primary)', marginTop: '2px', flexShrink: 0 }} />
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--text-high)' }}>Deterministic Architectural Boundary: </strong>
          Graph-based lateral movement traversal is not exposed by an independent backend API.
          AegisByte enforces zero-fabrication: below are the truthful ingress exposure points derived from verified
          internet-facing findings.
        </div>
      </div>

      {/* Ingress Exposure Points */}
      <Card variant="elevated">
        <CardHeader
          title={`Identified Ingress Points (${exposedFindings.length})`}
        />

        <CardBody style={{ padding: 'var(--space-4)' }}>
          {isLoading ? (
            <LoadingSkeleton variant="card" count={3} height="60px" />
          ) : exposedFindings.length === 0 ? (
            <EmptyState
              icon={Network}
              title="No Ingress Vulnerabilities Detected"
              description="No internet-exposed resources currently have open security findings."
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {exposedFindings.map((f) => (
                <div
                  key={f.finding_id}
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 'var(--space-3)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <div
                      style={{
                        padding: '6px',
                        background: 'var(--status-critical-bg)',
                        border: '1px solid var(--border-critical)',
                        borderRadius: 'var(--radius-sm)',
                        color: 'var(--text-critical)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <ShieldAlert size={15} />
                    </div>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>
                        {f.title}
                      </div>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        <span className="font-mono text-cyan">{f.rule_id}</span>
                        <span>•</span>
                        <span className="font-mono">{f.resource_name || f.resource_id}</span>
                        <span>•</span>
                        <span className="font-mono uppercase">{f.service}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 600,
                        padding: '2px 8px',
                        background: 'rgba(245, 158, 11, 0.15)',
                        color: 'var(--text-warning)',
                        borderRadius: 'var(--radius-sm)',
                      }}
                    >
                      Internet Ingress Point
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
