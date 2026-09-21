import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { RotateCw, Radio, Layers, Bot, AlertTriangle, Clock } from 'lucide-react'
import { scansApi } from '../../api/scansApi'
import { aiApi } from '../../api/aiApi'
import { findingsApi } from '../../api/findingsApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { Badge, StatusBadge, SeverityBadge } from '../../components/Badge'
import { Card, CardHeader, CardBody, PageHeader, Button } from '../../components/ui'

export const LiveActivityPage: React.FC = () => {
  // Controlled polling every 5 seconds (5000ms)
  const { data: scansData, isLoading: loadingScans, isFetching: fetchingScans, refetch: refetchScans } = useQuery({
    queryKey: ['live', 'scans'],
    queryFn: () => scansApi.listScans(10, 0),
    refetchInterval: 5000,
  })

  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['live', 'runs'],
    queryFn: () => aiApi.listRuns({ limit: 10 }),
    refetchInterval: 5000,
  })

  const { data: findingsData, isLoading: loadingFindings } = useQuery({
    queryKey: ['live', 'findings'],
    queryFn: () => findingsApi.listFindings({ limit: 10 }),
    refetchInterval: 5000,
  })

  const scans = scansData?.scans || []
  const findings = findingsData?.findings || []

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Live Operations Activity"
        subtitle="Continuous live event telemetry from PostgreSQL scan lifecycle and AI orchestration logs."
        badge={
          <Badge variant="success">
            <Radio size={12} className="pulse" style={{ marginRight: 6 }} />
            POLLING (5s INTERVAL)
          </Badge>
        }
        actions={
          <Button
            variant="outline"
            size="md"
            icon={<RotateCw size={13} className={fetchingScans ? 'spin' : ''} />}
            disabled={fetchingScans}
            onClick={() => refetchScans()}
          >
            Refresh Now
          </Button>
        }
      />

      {/* Grid: Live Scans & AI Runs */}
      <div className="cg-grid-2">
        {/* Live Scans Column */}
        <Card variant="default">
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Layers size={16} style={{ color: 'var(--accent-cyan)' }} />
                <span>Recent Cloud Scans</span>
              </div>
            }
            action={<Badge variant="cyan" size="sm">{scans.length} Scans</Badge>}
          />
          <CardBody>
            {loadingScans ? (
              <LoadingSkeleton variant="text" count={4} height={48} />
            ) : scans.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)', padding: '16px 0' }}>
                No scans recorded
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {scans.map((s) => (
                  <div
                    key={s.scan_id}
                    style={{
                      padding: '12px 14px',
                      background: 'var(--surface-elevated)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                        {s.scan_id.slice(0, 16)}...
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8 }}>
                        <span>Account: {s.account_id}</span>
                        <span>•</span>
                        <span>{s.resource_count} resources</span>
                        <span>•</span>
                        <span>{s.finding_count} threats</span>
                      </div>
                    </div>
                    <StatusBadge status={s.status} size="sm" />
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        {/* AI Agent Execution Runs Column */}
        <Card variant="default">
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Bot size={16} style={{ color: 'var(--accent)' }} />
                <span>AI Orchestration Runs</span>
              </div>
            }
            action={<Badge variant="info" size="sm">{runs?.length || 0} Runs</Badge>}
          />
          <CardBody>
            {loadingRuns ? (
              <LoadingSkeleton variant="text" count={4} height={48} />
            ) : !runs || runs.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)', padding: '16px 0' }}>
                No active agent runs
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {runs.map((r) => (
                  <div
                    key={r.run_id}
                    style={{
                      padding: '12px 14px',
                      background: 'var(--surface-elevated)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                        {r.run_id.slice(0, 16)}...
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8 }}>
                        <span>Agent: {r.agent_name}</span>
                        <span>•</span>
                        <span>Finding: {r.finding_id?.slice(0, 10)}...</span>
                      </div>
                    </div>
                    <StatusBadge status={r.status} size="sm" />
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      {/* Discovered Threat Stream */}
      <Card variant="default">
        <CardHeader
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={16} style={{ color: 'var(--sev-critical)' }} />
              <span>Live Discovered Misconfigurations Stream</span>
            </div>
          }
          subtitle="Real-time threat detections emitted across cloud infrastructure."
        />
        <CardBody>
          {loadingFindings ? (
            <LoadingSkeleton variant="table" count={3} />
          ) : findings.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)', padding: '16px 0' }}>
              Zero misconfigurations discovered in this monitoring window.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {findings.map((f) => (
                <div
                  key={f.finding_id}
                  style={{
                    padding: '10px 14px',
                    background: 'var(--surface-elevated)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 12,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0 }}>
                    <SeverityBadge severity={f.severity} size="sm" />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {f.title}
                      </div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                        Resource: {f.resource_id} • Service: {f.service}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <Clock size={12} />
                      {f.detected_at ? new Date(f.detected_at).toLocaleTimeString() : 'Recent'}
                    </span>
                    <StatusBadge status={f.status} size="sm" />
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
