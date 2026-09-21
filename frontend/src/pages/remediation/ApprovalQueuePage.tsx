import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import {
  ShieldCheck,
  XCircle,
  UserCheck,
  AlertCircle,
  Wrench,
} from 'lucide-react'
import { remediationApi } from '../../api/remediationApi'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { useAuth } from '../../auth/AuthContext'

export const ApprovalQueuePage: React.FC = () => {
  const { user } = useAuth()
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const [planIdInput, setPlanIdInput] = useState('')

  const approveMutation = useMutation({
    mutationFn: (planId: string) => remediationApi.approvePlan(planId),
    onSuccess: () => {
      setSuccessMessage('Remediation plan approved successfully.')
      setErrorMessage(null)
    },
    onError: (err: Error) => {
      setErrorMessage(err.message)
      setSuccessMessage(null)
    },
  })

  const rejectMutation = useMutation({
    mutationFn: (planId: string) => remediationApi.rejectPlan(planId),
    onSuccess: () => {
      setSuccessMessage('Remediation plan rejected.')
      setErrorMessage(null)
    },
    onError: (err: Error) => {
      setErrorMessage(err.message)
      setSuccessMessage(null)
    },
  })

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Remediation Approval Queue"
        subtitle="Strict separation of duties gate: changes to cloud infrastructure require review by an authorized operator."
      />

      {/* Separation of Duties Notice */}
      <div
        style={{
          padding: 'var(--space-3) var(--space-4)',
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid var(--border-warning)',
          borderRadius: 'var(--radius-md)',
          display: 'flex',
          gap: 'var(--space-3)',
          alignItems: 'flex-start',
        }}
      >
        <UserCheck size={18} style={{ color: 'var(--text-warning)', marginTop: '2px', flexShrink: 0 }} />
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--text-high)' }}>Separation of Duties Rule: </strong>
          The engineer or agent who authored a remediation plan CANNOT approve it.
          Self-approval attempts are rejected deterministically by the Phase 7 backend with HTTP 403 Forbidden.
        </div>
      </div>

      {/* Notifications */}
      {errorMessage && (
        <Card variant="critical">
          <CardBody style={{ padding: 'var(--space-3) var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <AlertCircle size={18} style={{ color: 'var(--text-critical)', flexShrink: 0 }} />
            <div style={{ color: 'var(--text-critical)', fontSize: '13px' }}>
              <strong>Authorization Block: </strong>
              {errorMessage}
            </div>
          </CardBody>
        </Card>
      )}

      {successMessage && (
        <div
          style={{
            padding: 'var(--space-3) var(--space-4)',
            background: 'var(--status-success-bg)',
            border: '1px solid var(--border-success)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--text-success)',
            fontSize: '13px',
          }}
        >
          {successMessage}
        </div>
      )}

      {/* Action Input Card */}
      <Card variant="elevated">
        <CardHeader title="Authorize or Review Pending Plan" />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Enter Remediation Plan ID to review..."
              value={planIdInput}
              onChange={(e) => setPlanIdInput(e.target.value)}
              style={{
                flex: 1,
                padding: '8px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
              }}
            />
            <Button
              variant="primary"
              size="sm"
              disabled={!planIdInput || approveMutation.isPending}
              onClick={() => planIdInput && approveMutation.mutate(planIdInput)}
            >
              <ShieldCheck size={14} />
              Approve Plan
            </Button>
            <Button
              variant="danger"
              size="sm"
              disabled={!planIdInput || rejectMutation.isPending}
              onClick={() => planIdInput && rejectMutation.mutate(planIdInput)}
            >
              <XCircle size={14} />
              Reject Plan
            </Button>
          </div>
        </CardBody>
      </Card>

      {/* Queue State */}
      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-6)' }}>
          <EmptyState
            icon={Wrench}
            title="Approval Queue Clean"
            description="No plans currently require separation-of-duties review. You can inspect pending plans in the Remediation Center."
            action={
              <Link to="/remediation" style={{ textDecoration: 'none' }}>
                <Button variant="outline" size="sm">
                  <Wrench size={14} />
                  Go to Remediation Center
                </Button>
              </Link>
            }
          />
        </CardBody>
      </Card>
    </div>
  )
}
