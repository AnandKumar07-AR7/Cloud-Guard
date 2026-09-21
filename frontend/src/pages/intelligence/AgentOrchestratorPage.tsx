import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Workflow,
  Cpu,
} from 'lucide-react'
import { aiApi } from '../../api/aiApi'
import { scansApi } from '../../api/scansApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'

interface PipelineStep {
  step: number
  title: string
  responsibility: string
  subsystem: string
  status: 'ACTIVE' | 'READY' | 'IDLE'
  agentOrService: string
}

const PIPELINE_STEPS: PipelineStep[] = [
  { step: 1, title: 'DETECTION', responsibility: 'Deterministic rule evaluation against cloud resources', subsystem: 'Phase 1-3 Detection Engine', status: 'ACTIVE', agentOrService: 'RuleScanner' },
  { step: 2, title: 'AI ANALYSIS', responsibility: 'Autonomous contextual evaluation of finding & attack surface', subsystem: 'Phase 8 AI Orchestrator', status: 'ACTIVE', agentOrService: 'AIAgentRunner' },
  { step: 3, title: 'RISK ASSESSMENT', responsibility: 'Multi-factor mathematical risk scoring & exposure amplification', subsystem: 'Phase 4 Risk Engine', status: 'READY', agentOrService: 'DeterministicRiskCalculator' },
  { step: 4, title: 'PLAN GENERATION', responsibility: 'Deterministic remediation action synthesis & blast radius scoping', subsystem: 'Phase 7 Remediation Engine', status: 'READY', agentOrService: 'RemediationPlanner' },
  { step: 5, title: 'POLICY EVALUATION', responsibility: 'Automation policy match, safety gate, & kill switch inspection', subsystem: 'Phase 9 Automation Engine', status: 'READY', agentOrService: 'PolicyGovernor' },
  { step: 6, title: 'APPROVAL', responsibility: 'Separation-of-duties review with creator rejection enforcement', subsystem: 'Phase 6 RBAC / Phase 7', status: 'READY', agentOrService: 'HumanApprovalGate' },
  { step: 7, title: 'EXECUTION', responsibility: 'State-machine locked action dispatch to cloud provider', subsystem: 'Phase 7 Provider Gateway', status: 'READY', agentOrService: 'ProviderExecutor' },
  { step: 8, title: 'VERIFICATION', responsibility: 'Independent post-execution state query to confirm vulnerability elimination', subsystem: 'Phase 7 Verifier', status: 'READY', agentOrService: 'StateVerifier' },
  { step: 9, title: 'RE-SCAN', responsibility: 'Full scan pass confirming finding closure in primary database', subsystem: 'Phase 2 Scan Lifecycle', status: 'READY', agentOrService: 'ContinuousScanner' },
]

export const AgentOrchestratorPage: React.FC = () => {
  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['ai', 'runs', 'orchestrator'],
    queryFn: () => aiApi.listRuns({ limit: 10 }),
  })

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Agent Orchestrator Control Plane"
        subtitle="End-to-end autonomous security remediation pipeline with strict policy gates and separation of duties."
      />

      {/* 9-Step Pipeline Stepper */}
      <Card variant="elevated">
        <CardHeader
          title="Deterministic Orchestration Pipeline"
          action={
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Phase 1 → Phase 9 Lifecycle
            </span>
          }
        />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-3)' }}>
            {PIPELINE_STEPS.map((step) => (
              <div
                key={step.step}
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
                  <span className="font-mono text-cyan" style={{ fontSize: '11px', fontWeight: 600 }}>
                    STEP 0{step.step}
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 600,
                      padding: '1px 6px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'var(--status-success-bg)',
                      color: 'var(--text-success)',
                    }}
                  >
                    {step.status}
                  </span>
                </div>

                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>
                  {step.title}
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {step.responsibility}
                </div>

                <div
                  style={{
                    marginTop: 'auto',
                    paddingTop: 'var(--space-2)',
                    borderTop: '1px solid var(--border-subtle)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '10px',
                    color: 'var(--text-muted)',
                  }}
                >
                  <span className="font-mono">{step.subsystem}</span>
                  <span className="font-mono text-cyan">{step.agentOrService}</span>
                </div>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Real Active Telemetry: Recent Orchestration Runs */}
      <Card variant="elevated">
        <CardHeader
          title="Recent Orchestration Telemetry"
          action={
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Real Backend Runs ({runs?.length || 0})
            </span>
          }
        />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          {loadingRuns ? (
            <LoadingSkeleton variant="card" count={3} height="60px" />
          ) : !runs || runs.length === 0 ? (
            <EmptyState
              icon={Workflow}
              title="No Orchestration Runs Recorded"
              description="Trigger an AI Security Analyst investigation from a finding to populate orchestration traces."
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {runs.map((r) => (
                <div
                  key={r.run_id}
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
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--status-info-bg)',
                        border: '1px solid var(--border-accent)',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      <Cpu size={16} />
                    </div>
                    <div>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {r.run_id}
                        </span>
                        <span style={{ color: 'var(--text-muted)' }}>•</span>
                        <span style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                          {r.agent_name || 'AI Security Analyst'}
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        Target: <span className="font-mono">{r.finding_id}</span> • Started: {r.started_at ? new Date(r.started_at).toLocaleString() : 'N/A'}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {r.duration_ms ? `${r.duration_ms} ms` : 'N/A'}
                    </span>
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
                      {r.status}
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
