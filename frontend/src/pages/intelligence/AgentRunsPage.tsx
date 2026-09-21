import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Cpu, Search, RotateCw, Fingerprint, ChevronRight } from 'lucide-react'
import { aiApi } from '../../api/aiApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Drawer } from '../../components/Drawer'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import type { AIAgentRun } from '../../types/ai'

export const AgentRunsPage: React.FC = () => {
  const [search, setSearch] = useState('')
  const [selectedRun, setSelectedRun] = useState<AIAgentRun | null>(null)

  const { data: runs, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['ai', 'runs', 'all'],
    queryFn: () => aiApi.listRuns({ limit: 50 }),
  })

  const { data: auditEvents } = useQuery({
    queryKey: ['ai', 'audit', selectedRun?.run_id],
    queryFn: () => aiApi.getRunAudit(selectedRun!.run_id),
    enabled: Boolean(selectedRun?.run_id),
  })

  const filteredRuns = (runs || []).filter(
    (r) =>
      r.run_id.toLowerCase().includes(search.toLowerCase()) ||
      (r.finding_id && r.finding_id.toLowerCase().includes(search.toLowerCase())) ||
      (r.agent_name && r.agent_name.toLowerCase().includes(search.toLowerCase()))
  )

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Agent Execution Runs"
        subtitle="Historical autonomous AI Security Analyst executions with tool traces and duration metrics."
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

      {/* Filter Bar */}
      <Card variant="default">
        <CardBody style={{ padding: 'var(--space-3)' }}>
          <div style={{ position: 'relative', maxWidth: '380px' }}>
            <Search
              size={14}
              style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
            />
            <input
              type="text"
              placeholder="Filter runs by run ID, finding ID, or agent name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                width: '100%',
                padding: '7px 12px 7px 32px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                outline: 'none',
              }}
            />
          </div>
        </CardBody>
      </Card>

      {/* Runs Table */}
      <Card variant="elevated">
        <CardHeader
          title={
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Showing <strong className="font-mono text-cyan">{filteredRuns.length}</strong> recorded runs
            </span>
          }
        />

        <CardBody style={{ padding: 0 }}>
          {isLoading ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <LoadingSkeleton variant="table" count={5} height="48px" />
            </div>
          ) : filteredRuns.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={Cpu}
                title="No Agent Runs"
                description="No AI agent execution runs have been logged yet."
              />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '120px' }}>Status</th>
                    <th style={{ width: '160px' }}>Run ID</th>
                    <th>Agent & Target Finding</th>
                    <th style={{ width: '120px' }}>Duration</th>
                    <th style={{ width: '160px' }}>Timestamp</th>
                    <th style={{ textAlign: 'right', width: '90px' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRuns.map((r) => (
                    <tr
                      key={r.run_id}
                      onClick={() => setSelectedRun(r)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background:
                              r.status === 'COMPLETED'
                                ? 'var(--status-success-bg)'
                                : r.status === 'FAILED'
                                ? 'var(--status-critical-bg)'
                                : 'var(--status-warning-bg)',
                            color:
                              r.status === 'COMPLETED'
                                ? 'var(--text-success)'
                                : r.status === 'FAILED'
                                ? 'var(--text-critical)'
                                : 'var(--text-warning)',
                          }}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {r.run_id}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 500, color: 'var(--text-high)', marginBottom: '2px' }}>
                          {r.agent_name || 'AI Security Analyst'}
                        </div>
                        <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Target: {r.finding_id || 'Global Scan'}
                        </div>
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {r.duration_ms ? `${r.duration_ms} ms` : 'N/A'}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {r.started_at ? new Date(r.started_at).toLocaleString() : 'N/A'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '2px', color: 'var(--accent-primary)', fontSize: '12px' }}>
                          <span>Trace</span>
                          <ChevronRight size={13} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Run Details & Audit Drawer */}
      <Drawer
        isOpen={Boolean(selectedRun)}
        onClose={() => setSelectedRun(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Run Trace</span>
            <span className="font-mono text-cyan" style={{ fontSize: '12px' }}>
              {selectedRun?.run_id}
            </span>
          </div>
        }
        width="660px"
      >
        {selectedRun && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: 'var(--space-3)',
                padding: 'var(--space-3)',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Agent</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedRun.agent_name || 'AI Security Analyst'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Status</div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-success)', marginTop: '2px' }}>
                  {selectedRun.status}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Finding</div>
                <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                  {selectedRun.finding_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Duration</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedRun.duration_ms ? `${selectedRun.duration_ms} ms` : 'N/A'}
                </div>
              </div>
            </div>

            {selectedRun.summary && (
              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>
                  Analysis Summary
                </h3>
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.5,
                  }}
                >
                  {selectedRun.summary}
                </div>
              </div>
            )}

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                <Fingerprint size={15} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: 0 }}>
                  Tool Execution Audit Trace
                </h3>
              </div>

              {!auditEvents || auditEvents.length === 0 ? (
                <div style={{ padding: 'var(--space-3)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                  No tool execution events recorded for this run.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                  {auditEvents.map((evt, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: 'var(--space-3)',
                        background: 'var(--surface-overlay)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {evt.tool_name}
                        </span>
                        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}
                        </span>
                      </div>
                      {Boolean(evt.tool_input) && (
                        <pre
                          className="font-mono"
                          style={{
                            padding: 'var(--space-2)',
                            background: 'var(--surface-base)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: '10px',
                            color: 'var(--text-secondary)',
                            margin: 0,
                            overflowX: 'auto',
                          }}
                        >
                          {JSON.stringify(evt.tool_input, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}
