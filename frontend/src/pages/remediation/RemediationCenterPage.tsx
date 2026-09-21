import React, { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Wrench,
  CheckCircle,
  AlertCircle,
  ShieldCheck,
  Play,
  XCircle,
  Fingerprint,
  FileCheck,
} from 'lucide-react'
import { remediationApi } from '../../api/remediationApi'
import { DiffViewer } from '../../components/DiffViewer'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

const LIFECYCLE_STEPS = [
  'DRAFT',
  'VALIDATED',
  'PENDING_APPROVAL',
  'APPROVED',
  'EXECUTING',
  'EXECUTED',
  'VERIFYING',
  'VERIFIED_FIXED',
]

export const RemediationCenterPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const findingIdParam = searchParams.get('finding_id') || ''
  const planIdParam = searchParams.get('plan_id') || ''

  const [activePlanId, setActivePlanId] = useState<string>(planIdParam)
  const [inputFindingId, setInputFindingId] = useState<string>(findingIdParam)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Fetch plan by ID
  const { data: plan, isLoading: loadingPlan, refetch: refetchPlan } = useQuery({
    queryKey: ['remediations', 'plan', activePlanId],
    queryFn: () => remediationApi.getPlan(activePlanId),
    enabled: Boolean(activePlanId),
  })

  // Fetch audit events
  const { data: auditEvents } = useQuery({
    queryKey: ['remediations', 'audit', activePlanId],
    queryFn: () => remediationApi.getAuditEvents(activePlanId),
    enabled: Boolean(activePlanId),
  })

  // Fetch audit chain verification
  const { data: chainVerification } = useQuery({
    queryKey: ['remediations', 'chain', activePlanId],
    queryFn: () => remediationApi.verifyAuditChain(activePlanId),
    enabled: Boolean(activePlanId),
  })

  // Create Plan Mutation
  const createPlanMutation = useMutation({
    mutationFn: (fId: string) => remediationApi.createPlan(fId),
    onSuccess: (newPlan) => {
      setActivePlanId(newPlan.remediation_id)
      setSearchParams({ plan_id: newPlan.remediation_id })
      setErrorMessage(null)
    },
    onError: (err: Error) => {
      setErrorMessage(err.message)
    },
  })

  // Auto-create plan if finding_id is provided in URL and no plan_id is set
  useEffect(() => {
    if (findingIdParam && !planIdParam && !activePlanId && !createPlanMutation.isPending) {
      createPlanMutation.mutate(findingIdParam)
    }
  }, [findingIdParam])

  // Lifecycle action mutations
  const validateMutation = useMutation({
    mutationFn: () => remediationApi.validatePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const approveMutation = useMutation({
    mutationFn: () => remediationApi.approvePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const rejectMutation = useMutation({
    mutationFn: () => remediationApi.rejectPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const executeMutation = useMutation({
    mutationFn: () => remediationApi.executePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const verifyMutation = useMutation({
    mutationFn: () => remediationApi.verifyPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const cancelMutation = useMutation({
    mutationFn: () => remediationApi.cancelPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      setErrorMessage(null)
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  // Determine current lifecycle step index
  const currentState = plan?.state || 'DRAFT'
  const currentStepIdx = LIFECYCLE_STEPS.indexOf(currentState)

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Safe Remediation Center"
        subtitle="Deterministic state-machine governed cloud configuration remediations with cryptographic audit trail."
        actions={
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Load Plan ID or enter Finding ID..."
              value={inputFindingId}
              onChange={(e) => setInputFindingId(e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                width: '260px',
                outline: 'none',
              }}
            />

            <Button
              variant="primary"
              size="sm"
              disabled={!inputFindingId || createPlanMutation.isPending}
              onClick={() => {
                if (inputFindingId.startsWith('rem-') || inputFindingId.includes('-')) {
                  setActivePlanId(inputFindingId)
                  setSearchParams({ plan_id: inputFindingId })
                } else {
                  createPlanMutation.mutate(inputFindingId)
                }
              }}
            >
              <Wrench size={14} />
              {createPlanMutation.isPending ? 'Creating Plan...' : 'Load / Create Plan'}
            </Button>
          </div>
        }
      />

      {/* Error Alert */}
      {errorMessage && (
        <Card variant="critical">
          <CardBody style={{ padding: 'var(--space-3) var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <AlertCircle size={18} style={{ color: 'var(--text-critical)', flexShrink: 0 }} />
            <div style={{ color: 'var(--text-critical)', fontSize: '13px' }}>
              <strong>Operation Blocked: </strong>
              {errorMessage}
            </div>
          </CardBody>
        </Card>
      )}

      {loadingPlan ? (
        <LoadingSkeleton variant="card" count={3} height="150px" />
      ) : !plan ? (
        <Card variant="elevated">
          <CardBody style={{ padding: 'var(--space-6)' }}>
            <EmptyState
              icon={Wrench}
              title="No Remediation Plan Selected"
              description="Enter a finding ID or remediation plan ID above to inspect the lifecycle, diff, and audit chain."
            />
          </CardBody>
        </Card>
      ) : (
        <>
          {/* Lifecycle State Machine Stepper */}
          <Card variant="elevated">
            <CardHeader
              title={
                <div>
                  <span style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                    State Machine Lifecycle
                  </span>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)', marginTop: '2px' }}>
                    Current State: <span className="font-mono text-cyan">{plan.state}</span>
                  </div>
                </div>
              }
              action={
                <span
                  style={{
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '11px',
                    fontWeight: 600,
                    background: 'var(--status-success-bg)',
                    color: 'var(--text-success)',
                    border: '1px solid var(--border-success)',
                  }}
                >
                  {plan.safety}
                </span>
              }
            />
            <CardBody style={{ padding: 'var(--space-4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'relative' }}>
                {LIFECYCLE_STEPS.map((step, idx) => {
                  const isPassed = currentStepIdx > idx
                  const isCurrent = currentStepIdx === idx
                  const isFinalFixed = plan.state === 'VERIFIED_FIXED' && step === 'VERIFIED_FIXED'

                  return (
                    <div
                      key={step}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        position: 'relative',
                        zIndex: 2,
                        flex: 1,
                      }}
                    >
                      <div
                        style={{
                          width: '28px',
                          height: '28px',
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: isFinalFixed
                            ? 'var(--text-success)'
                            : isCurrent
                            ? 'var(--accent-primary)'
                            : isPassed
                            ? 'var(--status-info-bg)'
                            : 'var(--surface-overlay)',
                          color: isCurrent || isFinalFixed ? 'var(--surface-base)' : 'var(--text-secondary)',
                          border: isCurrent
                            ? '2px solid var(--accent-primary)'
                            : '1px solid var(--border-subtle)',
                        }}
                      >
                        {isPassed || isFinalFixed ? <CheckCircle size={14} /> : idx + 1}
                      </div>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '9px',
                          color: isCurrent ? 'var(--accent-primary)' : 'var(--text-muted)',
                          marginTop: '6px',
                          textAlign: 'center',
                          textTransform: 'uppercase',
                          fontWeight: isCurrent ? 600 : 400,
                        }}
                      >
                        {step.replace('_', ' ')}
                      </span>
                    </div>
                  )
                })}
              </div>
            </CardBody>
          </Card>

          {/* Action Control Panel */}
          <Card variant="elevated">
            <CardBody
              style={{
                padding: 'var(--space-4)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>
                  Governed Actions for State: <code className="font-mono text-cyan">{plan.state}</code>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Backend enforces authorization, separation of duties, and state machine validation.
                </div>
              </div>

              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                {plan.state === 'DRAFT' && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => validateMutation.mutate()}
                    disabled={validateMutation.isPending}
                  >
                    <FileCheck size={14} />
                    Validate Plan
                  </Button>
                )}

                {plan.state === 'PENDING_APPROVAL' && (
                  <>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => approveMutation.mutate()}
                      disabled={approveMutation.isPending}
                    >
                      <ShieldCheck size={14} />
                      Approve Plan
                    </Button>

                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => rejectMutation.mutate()}
                      disabled={rejectMutation.isPending}
                    >
                      <XCircle size={14} />
                      Reject Plan
                    </Button>
                  </>
                )}

                {plan.state === 'APPROVED' && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => executeMutation.mutate()}
                    disabled={executeMutation.isPending}
                  >
                    <Play size={14} />
                    Execute Remediation
                  </Button>
                )}

                {plan.state === 'EXECUTED' && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => verifyMutation.mutate()}
                    disabled={verifyMutation.isPending}
                  >
                    <ShieldCheck size={14} />
                    Trigger Independent Verification
                  </Button>
                )}

                {plan.state !== 'VERIFIED_FIXED' && plan.state !== 'CANCELLED' && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => cancelMutation.mutate()}
                    disabled={cancelMutation.isPending}
                  >
                    Cancel Plan
                  </Button>
                )}
              </div>
            </CardBody>
          </Card>

          {/* Plan Specifications Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-3)' }}>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Remediation Plan ID</div>
                <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                  {plan.remediation_id}
                </div>
              </CardBody>
            </Card>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Finding ID</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {plan.finding_id}
                </div>
              </CardBody>
            </Card>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Strategy</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {plan.strategy_name || 'Targeted Fix'}
                </div>
              </CardBody>
            </Card>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Resource</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {plan.resource_id}
                </div>
              </CardBody>
            </Card>
          </div>

          {/* MANDATORY BEFORE / AFTER CONFIGURATION DIFF (Section 21) */}
          <Card variant="elevated">
            <CardHeader
              title="Configuration Comparison (Current vs Proposed State)"
              action={
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Deterministic State Diff
                </span>
              }
            />
            <CardBody style={{ padding: 'var(--space-4)' }}>
              <DiffViewer
                before={plan.actions?.[0]?.parameters?.before_state || { status: 'Vulnerable configuration active', target: plan.resource_id }}
                after={plan.actions?.[0]?.parameters?.after_state || { status: 'Remediated configuration applied', target: plan.resource_id }}
                beforeTitle="Current State (Vulnerable)"
                afterTitle="Proposed State (Remediated)"
              />
            </CardBody>
          </Card>

          {/* Cryptographic SHA-256 Audit Chain Ledger (Section 25) */}
          <Card variant="elevated">
            <CardHeader
              title={
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <Fingerprint size={16} style={{ color: 'var(--accent-primary)' }} />
                  <span>Tamper-Evident Audit Chain Ledger</span>
                </div>
              }
              action={
                chainVerification && (
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '11px',
                      fontWeight: 600,
                      background: chainVerification.verified ? 'var(--status-success-bg)' : 'var(--status-critical-bg)',
                      color: chainVerification.verified ? 'var(--text-success)' : 'var(--text-critical)',
                    }}
                  >
                    <CheckCircle size={12} />
                    {chainVerification.verified ? 'SHA-256 Hash Chain Verified' : 'Integrity Check Failed'}
                  </span>
                )
              }
            />
            <CardBody style={{ padding: 'var(--space-4)' }}>
              {!auditEvents || auditEvents.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 'var(--space-4)', color: 'var(--text-muted)', fontSize: '12px' }}>
                  No audit events recorded yet for this plan.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                  {auditEvents.map((evt) => (
                    <div
                      key={evt.event_id}
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
                            Actor: <code className="font-mono">{evt.actor}</code>
                          </span>
                        </div>
                        <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                          Hash: {evt.event_hash} | Prev: {evt.previous_event_hash || 'GENESIS'}
                        </div>
                      </div>

                      <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {new Date(evt.timestamp).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>
        </>
      )}
    </div>
  )
}
