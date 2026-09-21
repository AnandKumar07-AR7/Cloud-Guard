import React, { useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  ShieldCheck,
  CheckCircle,
  Info,
} from 'lucide-react'
import { remediationApi } from '../../api/remediationApi'
import { findingsApi } from '../../api/findingsApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const VerificationPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const planIdParam = searchParams.get('plan_id') || ''
  const [planIdInput, setPlanIdInput] = useState(planIdParam)
  const [activePlanId, setActivePlanId] = useState(planIdParam)

  const { data: plan, isLoading: loadingPlan, refetch } = useQuery({
    queryKey: ['remediations', 'verify', activePlanId],
    queryFn: () => remediationApi.getPlan(activePlanId),
    enabled: Boolean(activePlanId),
  })

  const { data: finding } = useQuery({
    queryKey: ['findings', 'plan-finding', plan?.finding_id],
    queryFn: () => findingsApi.getFinding(plan!.finding_id),
    enabled: Boolean(plan?.finding_id),
  })

  const verifyMutation = useMutation({
    mutationFn: () => remediationApi.verifyPlan(activePlanId),
    onSuccess: () => refetch(),
  })

  const isVerifiedFixed = plan?.state === 'VERIFIED_FIXED'
  const isFailed = plan?.state === 'VERIFICATION_FAILED' || plan?.state === 'STILL_VULNERABLE'
  const isExecuted = plan?.state === 'EXECUTED'

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Independent Post-Remediation Verification"
        subtitle="Execution success does not equal security fixed. Independent re-scan telemetry proves vulnerability elimination."
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
            Zero-Trust Verification
          </span>
        }
        actions={
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Enter plan UUID..."
              value={planIdInput}
              onChange={(e) => setPlanIdInput(e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                width: '300px',
                outline: 'none',
              }}
            />
            <Button
              variant="primary"
              size="sm"
              disabled={!planIdInput}
              onClick={() => {
                setActivePlanId(planIdInput)
                setSearchParams({ plan_id: planIdInput })
              }}
            >
              Load Plan
            </Button>
          </div>
        }
      />

      {/* Zero Trust Principle Banner */}
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
          <strong style={{ color: 'var(--text-high)' }}>Critical Security Rule: </strong>
          Remediation execution dispatches the API mutation, but only independent verification via live resource
          inspection can transition the state machine to <code className="font-mono text-cyan">VERIFIED_FIXED</code>.
        </div>
      </div>

      {loadingPlan ? (
        <LoadingSkeleton variant="card" count={3} height="120px" />
      ) : !plan ? (
        <Card variant="elevated">
          <CardBody style={{ padding: 'var(--space-6)' }}>
            <EmptyState
              icon={ShieldCheck}
              title="No Plan Loaded"
              description="Enter a remediation plan ID above to inspect the verification lifecycle and final security state."
            />
          </CardBody>
        </Card>
      ) : (
        <>
          {/* Flagship Stepper: BEFORE → ACTION → AFTER → VERIFICATION → RE-SCAN → FINAL SECURITY STATE */}
          <Card variant="elevated">
            <CardHeader
              title="6-Stage Independent Verification Pipeline"
              action={
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  State: <strong className="font-mono text-cyan">{plan.state}</strong>
                </span>
              }
            />
            <CardBody style={{ padding: 'var(--space-4)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 'var(--space-2)' }}>
                {/* Stage 1: BEFORE */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 01</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>BEFORE</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Vulnerable baseline recorded</div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-critical)', fontWeight: 600 }}>● OPEN FINDING</span>
                  </div>
                </div>

                {/* Stage 2: ACTION */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 02</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>ACTION</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{plan.strategy_name || 'Targeted fix'}</div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Approved & Dispatched</span>
                  </div>
                </div>

                {/* Stage 3: AFTER */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 03</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>AFTER</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Mutation applied to provider</div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-warning)' }}>● EXECUTED</span>
                  </div>
                </div>

                {/* Stage 4: VERIFICATION */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 04</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>VERIFICATION</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target rule re-tested independently</div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: isVerifiedFixed ? 'var(--text-success)' : 'var(--text-muted)' }}>
                      {isVerifiedFixed ? '✓ Rule Passed' : 'Pending Test'}
                    </span>
                  </div>
                </div>

                {/* Stage 5: RE-SCAN */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 05</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)' }}>RE-SCAN</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Full catalog scan confirms state</div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: isVerifiedFixed ? 'var(--text-success)' : 'var(--text-muted)' }}>
                      {isVerifiedFixed ? '✓ Scan Validated' : 'Awaiting Cycle'}
                    </span>
                  </div>
                </div>

                {/* Stage 6: FINAL SECURITY STATE */}
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: isVerifiedFixed ? 'var(--status-success-bg)' : 'var(--surface-overlay)',
                    border: isVerifiedFixed ? '1px solid var(--border-success)' : '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '10px' }}>STAGE 06</span>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: isVerifiedFixed ? 'var(--text-success)' : 'var(--text-high)' }}>
                    FINAL STATE
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {isVerifiedFixed ? 'Finding Closed' : 'Incomplete'}
                  </div>
                  <div style={{ marginTop: 'auto', paddingTop: '6px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        color: isVerifiedFixed ? 'var(--text-success)' : isFailed ? 'var(--text-critical)' : 'var(--text-warning)',
                      }}
                    >
                      {plan.state}
                    </span>
                  </div>
                </div>
              </div>
            </CardBody>
          </Card>

          {/* Action Trigger Card */}
          {isExecuted && (
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
                  <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)', margin: 0 }}>
                    Ready for Independent Verification
                  </h3>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px', margin: 0 }}>
                    Execute rule scanner pass against target resource to mathematically prove risk closure.
                  </p>
                </div>

                <Button
                  variant="primary"
                  onClick={() => verifyMutation.mutate()}
                  disabled={verifyMutation.isPending}
                >
                  <ShieldCheck size={15} />
                  {verifyMutation.isPending ? 'Verifying...' : 'Run Verification Pass'}
                </Button>
              </CardBody>
            </Card>
          )}

          {/* Details Box */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-3)' }}>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Finding</div>
                <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                  {plan.finding_id}
                </div>
              </CardBody>
            </Card>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resource Target</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {plan.resource_id}
                </div>
              </CardBody>
            </Card>
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-3)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Created By</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {plan.created_by || 'Security Operator'}
                </div>
              </CardBody>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
