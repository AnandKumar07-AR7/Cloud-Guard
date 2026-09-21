import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Fingerprint,
  RotateCw,
} from 'lucide-react'
import { automationApi } from '../../api/automationApi'
import { mcpApi } from '../../api/mcpApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const AuditLogPage: React.FC = () => {
  const [tab, setTab] = useState<'automation' | 'mcp'>('automation')

  const { data: autoEvents, isLoading: loadingAuto, refetch: refetchAuto, isFetching: fetchingAuto } = useQuery({
    queryKey: ['audit', 'automation'],
    queryFn: () => automationApi.listAuditEvents(),
    enabled: tab === 'automation',
  })

  const { data: mcpEvents, isLoading: loadingMcp, refetch: refetchMcp, isFetching: fetchingMcp } = useQuery({
    queryKey: ['audit', 'mcp'],
    queryFn: () => mcpApi.getAuditLogs(),
    enabled: tab === 'mcp',
  })

  const isFetching = fetchingAuto || fetchingMcp

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Immutable Audit Log Ledger"
        subtitle="Cryptographically chained record of remediation progression, policy evaluations, and MCP tool dispatches."
        badge={
          <span
            style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--status-success-bg)',
              border: '1px solid var(--border-success)',
              color: 'var(--text-success)',
              textTransform: 'uppercase',
            }}
          >
            Tamper-Evident SHA-256 Chain
          </span>
        }
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (tab === 'automation') refetchAuto()
              else refetchMcp()
            }}
            disabled={isFetching}
          >
            <RotateCw size={14} className={isFetching ? 'spin' : ''} />
            Refresh
          </Button>
        }
      />

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <Button
          variant={tab === 'automation' ? 'primary' : 'outline'}
          size="sm"
          onClick={() => setTab('automation')}
        >
          Automation Decisions ({autoEvents?.length || 0})
        </Button>

        <Button
          variant={tab === 'mcp' ? 'primary' : 'outline'}
          size="sm"
          onClick={() => setTab('mcp')}
        >
          MCP Invocations ({mcpEvents?.length || 0})
        </Button>
      </div>

      {/* Log Events List */}
      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-4)' }}>
          {tab === 'automation' ? (
            loadingAuto ? (
              <LoadingSkeleton variant="card" count={4} height="70px" />
            ) : !autoEvents || autoEvents.length === 0 ? (
              <EmptyState
                icon={Fingerprint}
                title="No Automation Audit Events"
                description="Policy decisions and auto-remediations will append immutable ledger records here."
              />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {autoEvents.map((evt) => (
                  <div
                    key={evt.event_id || evt.created_at || evt.timestamp || Math.random().toString()}
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--surface-overlay)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {evt.action}
                        </span>
                        <span style={{ color: 'var(--text-muted)' }}>•</span>
                        <span style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                          Actor: <code className="font-mono">{evt.actor || evt.actor_id || 'System'}</code>
                        </span>
                      </div>
                      {evt.details && (
                        <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                          {JSON.stringify(evt.details)}
                        </div>
                      )}
                      {evt.event_hash && (
                        <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          Hash: {evt.event_hash}
                        </div>
                      )}
                    </div>

                    <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {evt.created_at || evt.timestamp ? new Date(evt.created_at || evt.timestamp!).toLocaleString() : 'N/A'}
                    </div>
                  </div>
                ))}
              </div>
            )
          ) : (
            loadingMcp ? (
              <LoadingSkeleton variant="card" count={4} height="70px" />
            ) : !mcpEvents || mcpEvents.length === 0 ? (
              <EmptyState
                icon={Fingerprint}
                title="No MCP Invocations Logged"
                description="MCP tool dispatches will be recorded with execution parameters and hashes."
              />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {mcpEvents.map((evt) => (
                  <div
                    key={evt.event_id || evt.request_id}
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--surface-overlay)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {evt.tool_name}
                        </span>
                        <span style={{ color: 'var(--text-muted)' }}>•</span>
                        <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                          {evt.server_id}
                        </span>
                      </div>
                      <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        Actor: {evt.user_id || 'System'} • Duration: {evt.latency_ms}ms • Status: {evt.status}
                      </div>
                    </div>

                    <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {evt.event_hash?.slice(0, 12)}
                    </div>
                  </div>
                ))}
              </div>
            )
          )}
        </CardBody>
      </Card>
    </div>
  )
}
