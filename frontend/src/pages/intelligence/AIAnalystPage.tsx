import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Cpu,
  Sparkles,
  Wrench,
  Fingerprint,
} from 'lucide-react'
import { aiApi } from '../../api/aiApi'
import { findingsApi } from '../../api/findingsApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const AIAnalystPage: React.FC = () => {
  const queryClient = useQueryClient()
  const [selectedFindingId, setSelectedFindingId] = useState<string>('')
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)

  // Fetch recent runs
  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['ai', 'runs'],
    queryFn: () => aiApi.listRuns({ limit: 20 }),
  })

  // Fetch findings for analysis selector
  const { data: findingsData } = useQuery({
    queryKey: ['findings', 'open'],
    queryFn: () => findingsApi.listFindings({ status: 'OPEN', limit: 30 }),
  })

  // Selected run details
  const activeRunId = selectedRunId || (runs && runs.length > 0 ? runs[0].run_id : null)

  const { data: currentRun, isLoading: loadingRun } = useQuery({
    queryKey: ['ai', 'run', activeRunId],
    queryFn: () => aiApi.getRun(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  const { data: recommendations } = useQuery({
    queryKey: ['ai', 'recommendations', activeRunId],
    queryFn: () => aiApi.getRunRecommendations(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  const { data: auditEvents } = useQuery({
    queryKey: ['ai', 'audit', activeRunId],
    queryFn: () => aiApi.getRunAudit(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  // Trigger analysis mutation
  const analyzeMutation = useMutation({
    mutationFn: (findingId: string) => aiApi.analyze(findingId),
    onSuccess: (newRun) => {
      queryClient.invalidateQueries({ queryKey: ['ai', 'runs'] })
      setSelectedRunId(newRun.run_id)
    },
  })

  // Create remediation plan mutation from recommendation
  const createPlanMutation = useMutation({
    mutationFn: (recId: string) => aiApi.createRemediationPlanFromRecommendation(recId),
    onSuccess: () => {
      alert('Remediation plan created successfully! Head to Remediation Center.')
    },
  })

  const findings = findingsData?.findings || []

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="AI Security Analyst"
        subtitle="Autonomous agent analysis generating structured risk context, attack surface assessments, and remediation handoffs."
        badge={
          <span
            style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--status-info-bg)',
              border: '1px solid var(--border-accent)',
              color: 'var(--accent-primary)',
              textTransform: 'uppercase',
            }}
          >
            Structured Advisory Workspace
          </span>
        }
        actions={
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <select
              value={selectedFindingId}
              onChange={(e) => setSelectedFindingId(e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                maxWidth: '320px',
                outline: 'none',
              }}
            >
              <option value="">Select an open finding to analyze...</option>
              {findings.map((f) => (
                <option key={f.finding_id} value={f.finding_id}>
                  [{f.severity}] {f.title.slice(0, 40)}...
                </option>
              ))}
            </select>

            <Button
              variant="primary"
              size="sm"
              disabled={!selectedFindingId || analyzeMutation.isPending}
              onClick={() => selectedFindingId && analyzeMutation.mutate(selectedFindingId)}
            >
              <Cpu size={14} className={analyzeMutation.isPending ? 'spin' : ''} />
              {analyzeMutation.isPending ? 'Analyzing...' : 'Execute Analysis'}
            </Button>
          </div>
        }
      />

      {/* Main 2-Column Analyst Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 'var(--space-4)', alignItems: 'start' }}>
        {/* Left Column: Historical Agent Runs */}
        <Card variant="elevated">
          <CardHeader
            title="Analyst Runs"
            action={<span className="font-mono text-cyan">{runs?.length || 0}</span>}
          />
          <CardBody style={{ padding: 0 }}>
            {loadingRuns ? (
              <div style={{ padding: 'var(--space-3)' }}>
                <LoadingSkeleton variant="card" count={4} height="56px" />
              </div>
            ) : !runs || runs.length === 0 ? (
              <div style={{ padding: 'var(--space-5)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                No analyst runs recorded. Select a finding above to trigger an autonomous analysis.
              </div>
            ) : (
              <div style={{ maxHeight: '680px', overflowY: 'auto' }}>
                {runs.map((r) => {
                  const isSelected = r.run_id === activeRunId
                  return (
                    <div
                      key={r.run_id}
                      onClick={() => setSelectedRunId(r.run_id)}
                      style={{
                        padding: 'var(--space-3)',
                        borderBottom: '1px solid var(--border-subtle)',
                        background: isSelected ? 'var(--status-info-bg)' : 'transparent',
                        borderLeft: isSelected ? '3px solid var(--accent-primary)' : '3px solid transparent',
                        cursor: 'pointer',
                        transition: 'background 0.1s ease',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="font-mono text-cyan" style={{ fontSize: '11px', fontWeight: 600 }}>
                          {r.run_id.slice(0, 8)}...
                        </span>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 600,
                            padding: '1px 6px',
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
                      </div>

                      <div style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '4px' }}>
                        Finding: <span className="font-mono">{r.finding_id ? r.finding_id.slice(0, 10) : 'N/A'}...</span>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        <span className="font-mono">{r.agent_name || 'Security Analyst'}</span>
                        <span className="font-mono">{r.duration_ms ? `${r.duration_ms}ms` : 'Recorded'}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Right Column: Structured Analysis Inspector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {loadingRun ? (
            <LoadingSkeleton variant="card" count={3} height="180px" />
          ) : !currentRun ? (
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-6)' }}>
                <EmptyState
                  icon={Cpu}
                  title="No Run Selected"
                  description="Select a completed run on the left or trigger an analysis on an open finding."
                />
              </CardBody>
            </Card>
          ) : (
            <>
              {/* Top Details Card */}
              <Card variant="elevated">
                <CardHeader
                  title={
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span>Run Overview</span>
                      <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 'normal' }}>
                        {currentRun.run_id}
                      </span>
                    </div>
                  }
                  action={
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
                      {currentRun.status}
                    </span>
                  }
                />
                <CardBody style={{ padding: 'var(--space-4)' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(4, 1fr)',
                      gap: 'var(--space-3)',
                      padding: 'var(--space-3)',
                      background: 'var(--surface-overlay)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Finding</div>
                      <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                        {currentRun.finding_id}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Agent</div>
                      <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                        {currentRun.agent_name || 'AI Security Analyst'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Execution Latency</div>
                      <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                        {currentRun.duration_ms ? `${currentRun.duration_ms} ms` : 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Triggered At</div>
                      <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {currentRun.started_at ? new Date(currentRun.started_at).toLocaleTimeString() : 'N/A'}
                      </div>
                    </div>
                  </div>
                </CardBody>
              </Card>

              {/* Investigation Summary */}
              <Card variant="elevated">
                <CardHeader title="Investigation Summary" />
                <CardBody style={{ padding: 'var(--space-4)' }}>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    {currentRun.summary || currentRun.executive_summary || 'Autonomous risk evaluation concluded successfully.'}
                  </div>
                </CardBody>
              </Card>

              {/* Observed Facts vs Inferences */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 'var(--space-4)' }}>
                <Card variant="elevated">
                  <CardHeader
                    title={
                      <span style={{ color: 'var(--accent-primary)', fontSize: '13px' }}>
                        Observed Facts (Deterministic)
                      </span>
                    }
                  />
                  <CardBody style={{ padding: 'var(--space-4)' }}>
                    {currentRun.observed_facts && currentRun.observed_facts.length > 0 ? (
                      <ul style={{ paddingLeft: '18px', margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                        {currentRun.observed_facts.map((fact, i) => (
                          <li key={i} style={{ marginBottom: '4px' }}>{fact}</li>
                        ))}
                      </ul>
                    ) : (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Finding metadata, resource tags, and evaluated configuration fields.
                      </div>
                    )}
                  </CardBody>
                </Card>

                <Card variant="elevated">
                  <CardHeader
                    title={
                      <span style={{ color: 'var(--accent-primary)', fontSize: '13px' }}>
                        AI Inferences (Advisory)
                      </span>
                    }
                  />
                  <CardBody style={{ padding: 'var(--space-4)' }}>
                    {currentRun.ai_inferences && currentRun.ai_inferences.length > 0 ? (
                      <ul style={{ paddingLeft: '18px', margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                        {currentRun.ai_inferences.map((inf, i) => (
                          <li key={i} style={{ marginBottom: '4px' }}>{inf}</li>
                        ))}
                      </ul>
                    ) : (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Attack surface amplification, privilege escalation paths, and lateral movement vulnerability.
                      </div>
                    )}
                  </CardBody>
                </Card>
              </div>

              {/* Actionable Recommendations */}
              <Card variant="elevated">
                <CardHeader
                  title={`Actionable Recommendations (${recommendations?.length || 0})`}
                  action={
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Phase 8 AI → Phase 7 Remediation Bridge
                    </span>
                  }
                />
                <CardBody style={{ padding: 'var(--space-4)' }}>
                  {!recommendations || recommendations.length === 0 ? (
                    <div style={{ padding: 'var(--space-3)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                      No separate recommendations generated for this run.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                      {recommendations.map((rec) => (
                        <div
                          key={rec.recommendation_id}
                          style={{
                            padding: 'var(--space-3)',
                            background: 'var(--surface-overlay)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            gap: 'var(--space-4)',
                          }}
                        >
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: '4px' }}>
                              <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                                Strategy: {rec.strategy_name || 'Targeted Mitigation'}
                              </span>
                              <span
                                style={{
                                  fontSize: '10px',
                                  padding: '1px 6px',
                                  borderRadius: 'var(--radius-sm)',
                                  background: 'var(--status-success-bg)',
                                  color: 'var(--text-success)',
                                  fontWeight: 600,
                                }}
                              >
                                {rec.safety_class || 'REQUIRES_APPROVAL'}
                              </span>
                            </div>
                            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0 }}>
                              {rec.description || rec.action_summary}
                            </p>
                          </div>

                          <Button
                            variant="primary"
                            size="sm"
                            onClick={() => createPlanMutation.mutate(rec.recommendation_id)}
                            disabled={createPlanMutation.isPending}
                          >
                            <Wrench size={13} />
                            Generate Plan
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </CardBody>
              </Card>

              {/* Audit Provenance */}
              {auditEvents && auditEvents.length > 0 && (
                <Card variant="elevated">
                  <CardHeader
                    title={
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                        <Fingerprint size={15} style={{ color: 'var(--accent-primary)' }} />
                        <span>Tamper-Evident Tool Execution Trace ({auditEvents.length} Events)</span>
                      </div>
                    }
                  />
                  <CardBody style={{ padding: 'var(--space-3) var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                    {auditEvents.map((evt, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '6px 10px',
                          background: 'var(--surface-overlay)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          fontSize: '11px',
                        }}
                      >
                        <span className="font-mono text-cyan">{evt.tool_name}</span>
                        <span className="font-mono" style={{ color: 'var(--text-muted)' }}>
                          {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}
                        </span>
                      </div>
                    ))}
                  </CardBody>
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
