import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { User, CheckCircle } from 'lucide-react'
import { useAuth } from '../../auth/AuthContext'
import { systemApi } from '../../api/systemApi'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'

export const SettingsPage: React.FC = () => {
  const { user } = useAuth()

  const { data: health, isLoading: loadingHealth } = useQuery({
    queryKey: ['system', 'health'],
    queryFn: () => systemApi.getHealth(),
  })

  const { data: mode, isLoading: loadingMode } = useQuery({
    queryKey: ['system', 'mode'],
    queryFn: () => systemApi.getMode(),
  })

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="System Configuration & Identity"
        subtitle="Current operator session, role-based access control grants, and backend runtime status."
      />

      {/* Operator Profile */}
      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>
            <div
              style={{
                width: '46px',
                height: '46px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--status-info-bg)',
                border: '1px solid var(--border-accent)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-primary)',
              }}
            >
              <User size={22} />
            </div>

            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)' }}>
                {user?.email || 'Authenticated Operator'}
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginTop: '3px' }}>
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--status-info-bg)',
                    color: 'var(--accent-primary)',
                    textTransform: 'uppercase',
                  }}
                >
                  {user?.role}
                </span>
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  User ID: {user?.user_id}
                </span>
              </div>
            </div>
          </div>

          {/* Granted Permissions List */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
              Granted RBAC Permissions ({user?.permissions?.length || 0})
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
              {user?.permissions?.map((p) => (
                <span
                  key={p}
                  className="font-mono"
                  style={{
                    padding: '3px 8px',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {p}
                </span>
              ))}
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Runtime Environment Health */}
      <Card variant="elevated">
        <CardHeader title="Backend Runtime Telemetry" />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          {loadingHealth || loadingMode ? (
            <LoadingSkeleton variant="card" count={2} height="60px" />
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-3)' }}>
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>API Status</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
                  <CheckCircle size={15} style={{ color: 'var(--text-success)' }} />
                  <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-success)' }}>
                    {health?.status || 'HEALTHY'}
                  </span>
                </div>
              </div>

              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Database Persistence</div>
                <div className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-high)', marginTop: '4px' }}>
                  PostgreSQL 15 (Docker)
                </div>
              </div>

              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Provider Mode</div>
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    marginTop: '4px',
                    color: mode?.mode === 'demo' ? 'var(--text-warning)' : 'var(--text-success)',
                    textTransform: 'uppercase',
                  }}
                >
                  {mode?.mode === 'demo' ? 'Synthetic Enclave Environment' : 'Live AWS Provider'}
                </div>
              </div>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
