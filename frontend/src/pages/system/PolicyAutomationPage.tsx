import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Power,
  RotateCw,
  Trash2,
} from 'lucide-react'
import { automationApi } from '../../api/automationApi'
import { Modal } from '../../components/Modal'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { useAuth } from '../../auth/AuthContext'
import type { AutomationPolicy } from '../../types/automation'

export const PolicyAutomationPage: React.FC = () => {
  const { hasPermission } = useAuth()
  const queryClient = useQueryClient()
  const canManage = hasPermission('automation.manage')
  const canKillSwitch = hasPermission('automation.killswitch')

  const [isKillSwitchModalOpen, setIsKillSwitchModalOpen] = useState(false)
  const [killSwitchReason, setKillSwitchReason] = useState('')
  const [killSwitchAction, setKillSwitchAction] = useState<'enable' | 'disable'>('enable')

  // Fetch Policies
  const { data: policies, isLoading: loadingPolicies, refetch, isFetching } = useQuery({
    queryKey: ['automation', 'policies'],
    queryFn: () => automationApi.listPolicies(),
  })

  // Fetch Kill Switch status
  const { data: killSwitch } = useQuery({
    queryKey: ['automation', 'kill-switch'],
    queryFn: () => automationApi.getKillSwitchStatus(),
  })

  // Kill Switch Mutation
  const killSwitchMutation = useMutation({
    mutationFn: ({ enable, reason }: { enable: boolean; reason: string }) =>
      enable
        ? automationApi.enableKillSwitch(reason)
        : automationApi.disableKillSwitch(reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automation', 'kill-switch'] })
      setIsKillSwitchModalOpen(false)
      setKillSwitchReason('')
    },
  })

  // Delete policy mutation
  const deletePolicyMutation = useMutation({
    mutationFn: (policyId: string) => automationApi.deletePolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automation', 'policies'] })
    },
  })

  const isHalted = killSwitch?.enabled || false

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Policy-Governed Automation & Emergency Controls"
        subtitle="Deterministic rule gates for automated remediation progression and global emergency kill switch."
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

      {/* Emergency Kill Switch Banner (Section 39) */}
      <Card
        variant={isHalted ? 'critical' : 'elevated'}
        style={{
          border: isHalted ? '2px solid var(--border-critical)' : '1px solid var(--border-subtle)',
        }}
      >
        <CardBody
          style={{
            padding: 'var(--space-4) var(--space-5)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: 'var(--radius-sm)',
                background: isHalted ? 'var(--status-critical-bg)' : 'var(--status-success-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: isHalted ? 'var(--text-critical)' : 'var(--text-success)',
              }}
            >
              <Power size={22} />
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 600, color: isHalted ? 'var(--text-critical)' : 'var(--text-high)', margin: 0 }}>
                  Global Automation Kill Switch
                </h2>
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: isHalted ? 'var(--text-critical)' : 'var(--status-success-bg)',
                    color: isHalted ? '#fff' : 'var(--text-success)',
                  }}
                >
                  {isHalted ? 'EMERGENCY HALTED' : 'NORMAL OPERATION'}
                </span>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                {isHalted
                  ? `Active halt engaged: "${killSwitch?.reason || 'Security Emergency'}". All automated progressions blocked.`
                  : 'Automated remediation progression is permitted according to configured policy boundaries.'}
              </p>
            </div>
          </div>

          {canKillSwitch && (
            <div>
              <Button
                variant={isHalted ? 'primary' : 'danger'}
                onClick={() => {
                  setKillSwitchAction(isHalted ? 'disable' : 'enable')
                  setIsKillSwitchModalOpen(true)
                }}
              >
                <Power size={14} />
                {isHalted ? 'Resume Automation' : 'Halt All Automation'}
              </Button>
            </div>
          )}
        </CardBody>
      </Card>

      {/* SECTION 2: AUTOMATION POLICIES */}
      <div>
        <h2 style={{ fontSize: '13px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-3)' }}>
          Active Automation Policies ({policies?.length || 0})
        </h2>

        {loadingPolicies ? (
          <LoadingSkeleton variant="card" count={3} height="120px" />
        ) : !policies || policies.length === 0 ? (
          <Card variant="elevated">
            <CardBody style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={Power}
                title="No Automation Policies Configured"
                description="Create deterministic governance policies to allow automated progressions for specific safety classes."
              />
            </CardBody>
          </Card>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {policies.map((p) => (
              <Card key={p.policy_id} variant="elevated">
                <CardBody style={{ padding: 'var(--space-4)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                      <span className="font-mono text-cyan" style={{ fontSize: '11px', fontWeight: 600 }}>
                        PRIORITY {p.priority}
                      </span>
                      <span style={{ color: 'var(--text-muted)' }}>•</span>
                      <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-high)' }}>
                        {p.name}
                      </span>
                    </div>

                    <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 8px 0' }}>
                      {p.description}
                    </p>

                    <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 600,
                          padding: '2px 8px',
                          borderRadius: 'var(--radius-sm)',
                          background: p.require_human_approval ? 'rgba(245, 158, 11, 0.15)' : 'var(--status-success-bg)',
                          color: p.require_human_approval ? 'var(--text-warning)' : 'var(--text-success)',
                        }}
                      >
                        {p.require_human_approval ? 'Approval Required' : 'Autonomous'}
                      </span>

                      {p.allowed_safety_levels?.map((s) => (
                        <span
                          key={s}
                          style={{
                            fontSize: '10px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background: 'var(--status-info-bg)',
                            color: 'var(--accent-primary)',
                          }}
                        >
                          {s}
                        </span>
                      ))}

                      {p.allowed_rule_ids?.map((rid) => (
                        <span
                          key={rid}
                          className="font-mono"
                          style={{
                            fontSize: '10px',
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background: 'var(--surface-overlay)',
                            border: '1px solid var(--border-subtle)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {rid}
                        </span>
                      ))}
                    </div>
                  </div>

                  {canManage && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deletePolicyMutation.mutate(p.policy_id)}
                      disabled={deletePolicyMutation.isPending}
                    >
                      <Trash2 size={13} />
                      Delete
                    </Button>
                  )}
                </CardBody>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Kill Switch Rationale Modal */}
      <Modal
        isOpen={isKillSwitchModalOpen}
        onClose={() => setIsKillSwitchModalOpen(false)}
        title={killSwitchAction === 'enable' ? 'Emergency Kill Switch Confirmation' : 'Resume Global Automation Confirmation'}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
            {killSwitchAction === 'enable'
              ? 'Engaging the emergency kill switch instantly halts all automated remediation pipelines across all accounts. A mandatory audit rationale is required.'
              : 'Resuming automation permits configured policies to progress automated fixes once more.'}
          </p>

          <div>
            <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
              Audit Rationale / Incident Ticket (Mandatory)
            </label>
            <input
              type="text"
              placeholder="e.g. Production freeze window active..."
              value={killSwitchReason}
              onChange={(e) => setKillSwitchReason(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '13px',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsKillSwitchModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant={killSwitchAction === 'enable' ? 'danger' : 'primary'}
              size="sm"
              disabled={!killSwitchReason.trim() || killSwitchMutation.isPending}
              onClick={() =>
                killSwitchMutation.mutate({
                  enable: killSwitchAction === 'enable',
                  reason: killSwitchReason,
                })
              }
            >
              {killSwitchMutation.isPending ? 'Submitting...' : 'Confirm Status Change'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
