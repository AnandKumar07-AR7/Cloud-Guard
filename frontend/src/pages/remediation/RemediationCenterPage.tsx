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
  ArrowRight,
  ArrowLeft,
  Zap,
  Sparkles,
  Layers,
  RefreshCw,
  X,
} from 'lucide-react'
import { remediationApi } from '../../api/remediationApi'
import { findingsApi } from '../../api/findingsApi'
import { DiffViewer } from '../../components/DiffViewer'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { SeverityBadge } from '../../components/Badge'
import type { RemediationPlan } from '../../types/remediation'

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
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const [viewTab, setViewTab] = useState<'plans' | 'findings'>('plans')

  // Fetch all plans
  const {
    data: allPlans,
    isLoading: loadingAllPlans,
    refetch: refetchAllPlans,
  } = useQuery({
    queryKey: ['remediations', 'plans'],
    queryFn: () => remediationApi.listPlans({ limit: 50 }),
  })

  // Fetch open findings for on-demand plan generation
  const { data: openFindingsData, isLoading: loadingOpenFindings } = useQuery({
    queryKey: ['findings', 'open-remediation'],
    queryFn: () => findingsApi.listFindings({ status: 'OPEN', limit: 20 }),
  })

  // Fetch active plan by ID
  const {
    data: plan,
    isLoading: loadingPlan,
    refetch: refetchPlan,
  } = useQuery({
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

  // Helper to invalidate cross-system security query caches
  const invalidateAllSecurityCaches = () => {
    queryClient.invalidateQueries({ queryKey: ['remediations'] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['posture'] })
    queryClient.invalidateQueries({ queryKey: ['scans'] })
  }

  // Create Plan Mutation
  const createPlanMutation = useMutation({
    mutationFn: (fId: string) => remediationApi.createPlan(fId),
    onSuccess: (newPlan) => {
      setActivePlanId(newPlan.remediation_id)
      setSearchParams({ plan_id: newPlan.remediation_id })
      setErrorMessage(null)
      setSuccessMessage(`Remediation plan generated successfully for finding ${newPlan.finding_id}.`)
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => {
      // If an active plan already exists for this finding, automatically load it
      const match = err.message.match(/id=([a-zA-Z0-9_-]+)/)
      if (match && match[1]) {
        setErrorMessage(null)
        setSuccessMessage(`Loaded existing active remediation plan (${match[1].slice(0, 8)}...).`)
        handleSelectPlan(match[1])
        refetchAllPlans()
        return
      }
      setErrorMessage(err.message)
    },
  })

  // Lifecycle action mutations
  const validateMutation = useMutation({
    mutationFn: () => remediationApi.validatePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Plan validation passed! Guardrails and IAM constraints verified. Ready for approval.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const approveMutation = useMutation({
    mutationFn: () => remediationApi.approvePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Plan approved by authorized security principal. Governed execution unlocked.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const rejectMutation = useMutation({
    mutationFn: () => remediationApi.rejectPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Plan rejected. Status updated to DRAFT.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const executeMutation = useMutation({
    mutationFn: () => remediationApi.executePlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Remediation plan executed successfully! Cloud resource modified. Verification scan is now pending.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const verifyMutation = useMutation({
    mutationFn: () => remediationApi.verifyPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Remediation verified! Cloud target is hardened and finding is now officially RESOLVED.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  const cancelMutation = useMutation({
    mutationFn: () => remediationApi.cancelPlan(activePlanId),
    onSuccess: () => {
      refetchPlan()
      refetchAllPlans()
      setErrorMessage(null)
      setSuccessMessage('Plan cancelled.')
      invalidateAllSecurityCaches()
    },
    onError: (err: Error) => setErrorMessage(err.message),
  })

  // Determine current lifecycle step index
  const currentState = plan?.state || 'DRAFT'
  const currentStepIdx = LIFECYCLE_STEPS.indexOf(currentState)

  const openFindings = openFindingsData?.findings || []
  const plansList = allPlans || []

  // Count states
  const pendingApprovalsCount = plansList.filter((p) => p.state === 'PENDING_APPROVAL').length
  const draftPlansCount = plansList.filter((p) => p.state === 'DRAFT').length
  const fixedCount = plansList.filter((p) => p.state === 'VERIFIED_FIXED' || p.state === 'EXECUTED').length

  const handleSelectPlan = (planId: string) => {
    setActivePlanId(planId)
    setSearchParams({ plan_id: planId })
  }

  const handleBackToList = () => {
    setActivePlanId('')
    setSearchParams({})
  }

  // Automatically load existing plan if finding_id is passed in URL
  useEffect(() => {
    if (!activePlanId && findingIdParam && plansList.length > 0) {
      const match = plansList.find((p) => p.finding_id === findingIdParam)
      if (match) {
        setActivePlanId(match.remediation_id)
        setSearchParams({ plan_id: match.remediation_id })
      }
    }
  }, [findingIdParam, activePlanId, plansList, setSearchParams])

  const handleLoadOrCreate = (rawTarget?: string) => {
    const target = (rawTarget || inputFindingId || 'f-aws-s3-1').trim()
    if (!target) return

    setErrorMessage(null)

    // 1. Check if target is an existing plan or finding in the loaded plans list
    const existing = plansList.find(
      (p) => p.remediation_id === target || p.finding_id === target
    )
    if (existing) {
      handleSelectPlan(existing.remediation_id)
      return
    }

    // 2. If target starts with 'rem-' (legacy mock format)
    if (target.startsWith('rem-')) {
      handleSelectPlan(target)
      return
    }

    // 3. Otherwise, create a new plan
    createPlanMutation.mutate(target)
  }

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Safe Remediation Center"
        subtitle="Review, approve, and execute deterministic automated fixes for cloud security misconfigurations."
        badge={
          <span
            style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '3px 10px',
              borderRadius: 999,
              background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(6, 182, 212, 0.2) 100%)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              color: '#34d399',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <ShieldCheck size={12} />
            SAFE AUTO-REMEDIATION READY
          </span>
        }
        actions={
          activePlanId ? (
            <Button variant="outline" size="sm" onClick={handleBackToList}>
              <ArrowLeft size={14} />
              Back to Plans List
            </Button>
          ) : (
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Enter Finding ID or Plan ID..."
                value={inputFindingId}
                onChange={(e) => setInputFindingId(e.target.value)}
                style={{
                  padding: '7px 12px',
                  background: 'rgba(18, 25, 43, 0.8)',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  borderRadius: 8,
                  color: '#ffffff',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                  width: '260px',
                  outline: 'none',
                }}
              />
              <Button
                variant="primary"
                size="sm"
                disabled={createPlanMutation.isPending}
                onClick={() => handleLoadOrCreate(inputFindingId || 'f-aws-s3-1')}
              >
                <Wrench size={14} />
                {createPlanMutation.isPending ? 'Loading Plan...' : 'Load / Create Plan'}
              </Button>
            </div>
          )
        }
      />

      {/* Error Alert */}
      {errorMessage && (
        <Card variant="critical">
          <CardBody
            style={{
              padding: 'var(--space-3) var(--space-4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <AlertCircle size={18} style={{ color: 'var(--text-critical)', flexShrink: 0 }} />
              <div style={{ color: 'var(--text-critical)', fontSize: '13px' }}>
                <strong>Operation Notice: </strong>
                {errorMessage}
              </div>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: 4,
                display: 'flex',
                alignItems: 'center',
              }}
              title="Dismiss notice"
            >
              <X size={16} />
            </button>
          </CardBody>
        </Card>
      )}

      {/* Success Alert */}
      {successMessage && (
        <Card variant="default" style={{ border: '1px solid rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.08)' }}>
          <CardBody
            style={{
              padding: 'var(--space-3) var(--space-4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 'var(--space-3)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <CheckCircle size={18} style={{ color: '#34d399', flexShrink: 0 }} />
              <div style={{ color: '#34d399', fontSize: '13px', fontWeight: 500 }}>
                <strong>Success: </strong>
                {successMessage}
              </div>
            </div>
            <button
              onClick={() => setSuccessMessage(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: 4,
                display: 'flex',
                alignItems: 'center',
              }}
              title="Dismiss notification"
            >
              <X size={16} />
            </button>
          </CardBody>
        </Card>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* VIEW 1: PLANS LIBRARY & QUEUE (Shown when no plan is currently open) */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {!activePlanId ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Top Quick Stats */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 12,
            }}
          >
            <Card variant="default">
              <CardBody style={{ padding: '16px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  TOTAL REMEDIATION PLANS
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color: '#38bdf8', marginTop: 4 }}>
                  {plansList.length}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Generated across all scans
                </div>
              </CardBody>
            </Card>

            <Card variant="default">
              <CardBody style={{ padding: '16px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  PENDING APPROVAL
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color: '#fbbf24', marginTop: 4 }}>
                  {pendingApprovalsCount}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Requires human sign-off
                </div>
              </CardBody>
            </Card>

            <Card variant="default">
              <CardBody style={{ padding: '16px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  DRAFT PLANS
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color: '#818cf8', marginTop: 4 }}>
                  {draftPlansCount}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Ready to validate
                </div>
              </CardBody>
            </Card>

            <Card variant="default">
              <CardBody style={{ padding: '16px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  COMPLETED FIXES
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color: '#34d399', marginTop: 4 }}>
                  {fixedCount}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Verified cloud hardening
                </div>
              </CardBody>
            </Card>
          </div>

          {/* Section Switcher Tabs */}
          <div
            style={{
              display: 'flex',
              gap: 8,
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              paddingBottom: 8,
            }}
          >
            <button
              type="button"
              onClick={() => setViewTab('plans')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 16px',
                borderRadius: 8,
                border: 'none',
                background: viewTab === 'plans' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: viewTab === 'plans' ? '#38bdf8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 700,
                borderBottom: viewTab === 'plans' ? '2px solid #06b6d4' : 'none',
              }}
            >
              <Wrench size={15} />
              Active Remediation Plans ({plansList.length})
            </button>
            <button
              type="button"
              onClick={() => setViewTab('findings')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 16px',
                borderRadius: 8,
                border: 'none',
                background: viewTab === 'findings' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: viewTab === 'findings' ? '#38bdf8' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 700,
                borderBottom: viewTab === 'findings' ? '2px solid #06b6d4' : 'none',
              }}
            >
              <Zap size={15} />
              Open Issues Ready to Fix ({openFindings.length})
            </button>
          </div>

          {/* Sub-View: Active Remediation Plans Table */}
          {viewTab === 'plans' && (
            <Card variant="elevated">
              <CardHeader
                title="Active Remediation Plans"
                subtitle="Select any plan to inspect the policy diff, state machine progress, and execute the fix."
                action={
                  <Button variant="outline" size="sm" onClick={() => refetchAllPlans()}>
                    <RefreshCw size={13} className={loadingAllPlans ? 'spin' : ''} />
                    Refresh Plans
                  </Button>
                }
              />
              <CardBody style={{ padding: 0 }}>
                {loadingAllPlans ? (
                  <div style={{ padding: 18 }}>
                    <LoadingSkeleton variant="table" count={5} />
                  </div>
                ) : plansList.length === 0 ? (
                  <div style={{ padding: 32, textAlign: 'center' }}>
                    <EmptyState
                      icon={Wrench}
                      title="No Remediation Plans Created Yet"
                      description="Switch to the 'Open Issues Ready to Fix' tab to generate a plan with a single click."
                    />
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                      <thead>
                        <tr
                          style={{
                            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                            color: 'var(--text-muted)',
                            fontSize: 11,
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          <th style={{ padding: '12px 16px' }}>PLAN ID</th>
                          <th style={{ padding: '12px 16px' }}>TITLE & GOAL</th>
                          <th style={{ padding: '12px 16px' }}>RESOURCE TARGET</th>
                          <th style={{ padding: '12px 16px' }}>SAFETY</th>
                          <th style={{ padding: '12px 16px' }}>STATUS</th>
                          <th style={{ padding: '12px 16px', textAlign: 'right' }}>ACTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {plansList.map((p) => (
                          <tr
                            key={p.remediation_id}
                            style={{
                              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                              transition: 'background 0.12s ease',
                              cursor: 'pointer',
                            }}
                            onClick={() => handleSelectPlan(p.remediation_id)}
                            onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)')}
                            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                          >
                            <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                              {p.remediation_id.slice(0, 8)}...
                            </td>
                            <td style={{ padding: '14px 16px', fontWeight: 600, color: '#ffffff' }}>
                              {p.title || p.strategy_name || p.plan_spec?.description || 'Remediation Plan'}
                            </td>
                            <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                              {p.resource_id ? p.resource_id.split('/').pop() || p.resource_id : 'AWS Target'}
                            </td>
                            <td style={{ padding: '14px 16px' }}>
                              <span
                                style={{
                                  padding: '2px 8px',
                                  borderRadius: 4,
                                  fontSize: 10,
                                  fontWeight: 700,
                                  fontFamily: 'var(--font-mono)',
                                  background:
                                    p.safety === 'SAFE_REVERSIBLE'
                                      ? 'rgba(16, 185, 129, 0.15)'
                                      : 'rgba(245, 158, 11, 0.15)',
                                  color: p.safety === 'SAFE_REVERSIBLE' ? '#34d399' : '#fbbf24',
                                }}
                              >
                                {p.safety || 'MEDIUM_RISK'}
                              </span>
                            </td>
                            <td style={{ padding: '14px 16px' }}>
                              <span
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 5,
                                  padding: '3px 10px',
                                  borderRadius: 4,
                                  fontSize: 11,
                                  fontWeight: 700,
                                  fontFamily: 'var(--font-mono)',
                                  background:
                                    p.state === 'VERIFIED_FIXED'
                                      ? 'rgba(16, 185, 129, 0.2)'
                                      : p.state === 'EXECUTED'
                                      ? 'rgba(245, 158, 11, 0.2)'
                                      : p.state === 'APPROVED'
                                      ? 'rgba(6, 182, 212, 0.2)'
                                      : p.state === 'PENDING_APPROVAL'
                                      ? 'rgba(251, 191, 36, 0.2)'
                                      : 'rgba(99, 102, 241, 0.2)',
                                  color:
                                    p.state === 'VERIFIED_FIXED'
                                      ? '#34d399'
                                      : p.state === 'EXECUTED'
                                      ? '#fbbf24'
                                      : p.state === 'APPROVED'
                                      ? '#38bdf8'
                                      : p.state === 'PENDING_APPROVAL'
                                      ? '#fcd34d'
                                      : '#818cf8',
                                  border:
                                    p.state === 'VERIFIED_FIXED'
                                      ? '1px solid rgba(16, 185, 129, 0.4)'
                                      : '1px solid transparent',
                                }}
                              >
                                {p.state === 'VERIFIED_FIXED' && <CheckCircle size={12} />}
                                {p.state === 'VERIFIED_FIXED'
                                  ? '✓ RESOLVED'
                                  : p.state === 'EXECUTED'
                                  ? '⚡ PENDING VERIFY'
                                  : p.state === 'APPROVED'
                                  ? 'READY TO EXECUTE'
                                  : p.state === 'PENDING_APPROVAL'
                                  ? 'AWAITING APPROVAL'
                                  : p.state}
                              </span>
                            </td>
                            <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                              <Button
                                variant="primary"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleSelectPlan(p.remediation_id)
                                }}
                              >
                                Inspect & Remediate
                                <ArrowRight size={13} />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardBody>
            </Card>
          )}

          {/* Sub-View: Open Issues to Generate New Plans */}
          {viewTab === 'findings' && (
            <Card variant="elevated">
              <CardHeader
                title="Discovered Cloud Issues Ready to Remediate"
                subtitle="Click 'Generate Plan' on any issue to automatically build a deterministic fix plan."
              />
              <CardBody style={{ padding: 0 }}>
                {loadingOpenFindings ? (
                  <div style={{ padding: 18 }}>
                    <LoadingSkeleton variant="table" count={5} />
                  </div>
                ) : openFindings.length === 0 ? (
                  <div style={{ padding: 32, textAlign: 'center' }}>
                    <EmptyState
                      icon={CheckCircle}
                      title="All Issues Remediated!"
                      description="No open cloud findings currently require remediation."
                    />
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
                      <thead>
                        <tr
                          style={{
                            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                            color: 'var(--text-muted)',
                            fontSize: 11,
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          <th style={{ padding: '12px 16px' }}>SEVERITY</th>
                          <th style={{ padding: '12px 16px' }}>ISSUE TITLE</th>
                          <th style={{ padding: '12px 16px' }}>RESOURCE</th>
                          <th style={{ padding: '12px 16px' }}>RULE ID</th>
                          <th style={{ padding: '12px 16px', textAlign: 'right' }}>AUTOMATED ACTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {openFindings.map((f) => (
                          <tr
                            key={f.finding_id}
                            style={{
                              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                              transition: 'background 0.12s ease',
                            }}
                          >
                            <td style={{ padding: '14px 16px' }}>
                              <SeverityBadge severity={f.severity} size="sm" />
                            </td>
                            <td style={{ padding: '14px 16px', fontWeight: 600, color: '#ffffff' }}>
                              {f.title}
                            </td>
                            <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                              {f.resource_id ? f.resource_id.split('/').pop() || f.resource_id : 'Target'}
                            </td>
                            <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: '#38bdf8' }}>
                              {f.rule_id}
                            </td>
                            <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                              <Button
                                variant="primary"
                                size="sm"
                                disabled={createPlanMutation.isPending}
                                onClick={() => handleLoadOrCreate(f.finding_id)}
                              >
                                <Zap size={13} />
                                {createPlanMutation.isPending ? 'Loading...' : 'Generate Plan'}
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardBody>
            </Card>
          )}
        </div>
      ) : (
        /* ────────────────────────────────────────────────────────────────────────── */
        /* VIEW 2: ACTIVE PLAN INSPECTOR & DIFF EXECUTION */
        /* ────────────────────────────────────────────────────────────────────────── */
        <>
          {loadingPlan ? (
            <LoadingSkeleton variant="card" count={3} height="150px" />
          ) : !plan ? (
            <Card variant="elevated">
              <CardBody style={{ padding: 'var(--space-6)' }}>
                <EmptyState
                  icon={Wrench}
                  title="Plan Not Found"
                  description="The requested plan could not be located."
                  action={
                    <Button variant="primary" size="sm" onClick={handleBackToList}>
                      Back to Plans List
                    </Button>
                  }
                />
              </CardBody>
            </Card>
          ) : (
            <>
              {/* If plan is verified fixed, render prominent success resolution banner */}
              {plan.state === 'VERIFIED_FIXED' && (
                <Card
                  variant="default"
                  style={{
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(6, 78, 59, 0.25))',
                  }}
                >
                  <CardBody
                    style={{
                      padding: '16px 20px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 16,
                      flexWrap: 'wrap',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <div
                        style={{
                          width: 42,
                          height: 42,
                          borderRadius: '50%',
                          background: 'rgba(16, 185, 129, 0.2)',
                          border: '1px solid rgba(16, 185, 129, 0.4)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#34d399',
                          flexShrink: 0,
                        }}
                      >
                        <CheckCircle size={22} />
                      </div>
                      <div>
                        <div style={{ fontSize: 15, fontWeight: 700, color: '#ecfdf5', display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span>Remediation Complete & Target Hardened</span>
                          <span
                            style={{
                              fontSize: 10,
                              background: 'rgba(16, 185, 129, 0.3)',
                              color: '#34d399',
                              padding: '2px 8px',
                              borderRadius: 4,
                              fontWeight: 700,
                              letterSpacing: '0.05em',
                            }}
                          >
                            RESOLVED
                          </span>
                        </div>
                        <div style={{ fontSize: 13, color: '#a7f3d0', marginTop: 3 }}>
                          Cloud configuration was successfully applied and cryptographically verified against the active cloud target. Finding{' '}
                          <code className="font-mono text-cyan" style={{ fontSize: 12 }}>{plan.finding_id}</code> is officially marked as <strong>RESOLVED</strong>.
                        </div>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <Button variant="outline" size="sm" onClick={() => navigate(`/findings/${plan.finding_id}`)}>
                        View Finding
                      </Button>
                      <Button variant="primary" size="sm" onClick={handleBackToList}>
                        Back to Plans
                      </Button>
                    </div>
                  </CardBody>
                </Card>
              )}

              {/* Lifecycle State Machine Stepper */}
              <Card variant="elevated">
                <CardHeader
                  title={
                    <div>
                      <span
                        style={{
                          fontSize: '10px',
                          textTransform: 'uppercase',
                          color: 'var(--text-muted)',
                          letterSpacing: '0.05em',
                        }}
                      >
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
                      {plan.safety || 'DETERMINISTIC_GUARDRAIL'}
                    </span>
                  }
                />
                <CardBody style={{ padding: 'var(--space-4)' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      position: 'relative',
                    }}
                  >
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
                      Deterministic authorization verification and rollback safeguards enforced.
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
                        Verify Fix
                      </Button>
                    )}

                    {plan.state === 'VERIFIED_FIXED' && (
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          padding: '6px 14px',
                          borderRadius: 6,
                          background: 'rgba(16, 185, 129, 0.15)',
                          border: '1px solid rgba(16, 185, 129, 0.35)',
                          color: '#34d399',
                          fontSize: 12,
                          fontWeight: 700,
                        }}
                      >
                        <CheckCircle size={15} />
                        VERIFIED FIXED & RESOLVED
                      </div>
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
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 'var(--space-3)' }}>
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-3)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Remediation Plan ID
                    </div>
                    <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                      {plan.remediation_id}
                    </div>
                  </CardBody>
                </Card>
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-3)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Target Finding ID
                    </div>
                    <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                      {plan.finding_id}
                    </div>
                  </CardBody>
                </Card>
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-3)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Strategy
                    </div>
                    <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                      {plan.strategy_name || 'Targeted Fix'}
                    </div>
                  </CardBody>
                </Card>
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-3)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Target Resource
                    </div>
                    <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                      {plan.resource_id}
                    </div>
                  </CardBody>
                </Card>
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-3)' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Resolution Status
                    </div>
                    <div
                      className="font-mono"
                      style={{
                        fontSize: '12px',
                        marginTop: '2px',
                        fontWeight: 700,
                        color:
                          plan.state === 'VERIFIED_FIXED'
                            ? '#34d399'
                            : plan.state === 'EXECUTED'
                            ? '#fbbf24'
                            : '#38bdf8',
                      }}
                    >
                      {plan.state === 'VERIFIED_FIXED'
                        ? '✓ RESOLVED'
                        : plan.state === 'EXECUTED'
                        ? '⚡ PENDING VERIFY'
                        : 'OPEN'}
                    </div>
                  </CardBody>
                </Card>
              </div>

              {/* BEFORE / AFTER CONFIGURATION DIFF */}
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
                    before={
                      plan.actions?.[0]?.parameters?.before_state || {
                        status: 'Vulnerable configuration active',
                        target: plan.resource_id,
                      }
                    }
                    after={
                      plan.actions?.[0]?.parameters?.after_state || {
                        status: 'Remediated configuration applied',
                        target: plan.resource_id,
                      }
                    }
                    beforeTitle="Current State (Vulnerable)"
                    afterTitle="Proposed State (Remediated)"
                  />
                </CardBody>
              </Card>

              {/* Cryptographic SHA-256 Audit Chain Ledger */}
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
                          background: chainVerification.verified
                            ? 'var(--status-success-bg)'
                            : 'var(--status-critical-bg)',
                          color: chainVerification.verified
                            ? 'var(--text-success)'
                            : 'var(--text-critical)',
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
        </>
      )}
    </div>
  )
}
export default RemediationCenterPage
