import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, Cpu, RotateCw } from 'lucide-react'
import { aiApi } from '../../api/aiApi'
import { automationApi } from '../../api/automationApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const AgentActivityPage: React.FC = () => {
  const { data: runs, isLoading: loadingRuns, refetch, isFetching } = useQuery({
    queryKey: ['ai', 'runs', 'activity'],
    queryFn: () => aiApi.listRuns({ limit: 30 }),
  })

  const { data: decisions } = useQuery({
    queryKey: ['automation', 'decisions', 'activity'],
    queryFn: () => automationApi.listDecisions(),
  })

  const activities = (runs || []).map((r) => ({
    id: r.run_id,
    type: 'ANALYSIS',
    title: `AI Security Analysis completed for finding ${r.finding_id}`,
    agent: r.agent_name || 'AI Security Analyst',
    status: r.status,
    timestamp: r.started_at,
    duration: r.duration_ms,
  }))

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Live Agent Activity Stream"
        subtitle="Live event ledger recording autonomous security evaluations, policy assessments, and tool dispatches."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RotateCw size={14} className={isFetching ? 'spin' : ''} />
            Refresh
          </Button>
        }
      />

      {/* Activity Timeline */}
      <Card variant="elevated">
        <CardHeader
          title="Autonomous Event Stream"
          action={
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              {activities.length} Events Logged
            </span>
          }
        />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          {loadingRuns ? (
            <LoadingSkeleton variant="card" count={4} height="60px" />
          ) : activities.length === 0 ? (
            <EmptyState
              icon={Activity}
              title="No Agent Activity Recorded"
              description="Agent evaluations will appear in this ledger as investigations and automated progressions occur."
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {activities.map((act) => (
                <div
                  key={act.id}
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
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <div
                      style={{
                        padding: '6px',
                        background: 'var(--status-info-bg)',
                        border: '1px solid var(--border-accent)',
                        borderRadius: 'var(--radius-sm)',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      <Cpu size={16} />
                    </div>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-high)' }}>
                        {act.title}
                      </div>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        <span className="font-mono text-cyan">{act.id.slice(0, 12)}...</span>
                        <span>•</span>
                        <span className="font-mono">{act.agent}</span>
                        {act.duration && (
                          <>
                            <span>•</span>
                            <span className="font-mono">{act.duration}ms</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 600,
                        padding: '2px 8px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--status-success-bg)',
                        color: 'var(--text-success)',
                      }}
                    >
                      {act.status}
                    </span>
                    <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {act.timestamp ? new Date(act.timestamp).toLocaleTimeString() : 'Recorded'}
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
