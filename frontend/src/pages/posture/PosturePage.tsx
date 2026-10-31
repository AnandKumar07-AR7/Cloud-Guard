import React, { useEffect, useState } from 'react'
import { RefreshCw, Server, ShieldCheck, AlertTriangle } from 'lucide-react'
import { postureApi } from '../../api/postureApi'
import { ScoreGauge } from '../../components/ScoreGauge'
import { Badge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { Card, CardHeader, CardBody, PageHeader, StatTile, Button } from '../../components/ui'
import type { PostureResponse } from '../../types/posture'

export const PosturePage: React.FC = () => {
  const [posture, setPosture] = useState<PostureResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const loadPosture = async () => {
    setIsLoading(true)
    try {
      const res = await postureApi.getPosture()
      setPosture(res)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadPosture()
  }, [])

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="SECURITY POSTURE INTELLIGENCE"
        subtitle="Deterministic posture scoring across cloud services, accounts, and attack surface boundaries."
        badge={<Badge variant="cyan">CIS BENCHMARK v3.0</Badge>}
        actions={
          <Button
            variant="outline"
            size="md"
            icon={<RefreshCw size={13} className={isLoading ? 'spin' : ''} />}
            onClick={loadPosture}
          >
            REFRESH POSTURE
          </Button>
        }
      />

      {/* Top Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 340px) 1fr', gap: 'var(--space-4)' }}>
        {/* Main Posture Score Card */}
        <Card variant="default">
          <CardHeader
            title={
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                GLOBAL COMPOSITE SCORE
              </span>
            }
          />
          <CardBody style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px 16px' }}>
            {isLoading ? (
              <LoadingSkeleton width={140} height={140} borderRadius="50%" />
            ) : (
              <ScoreGauge
                score={posture?.posture_score ?? 82}
                size={160}
                strokeWidth={12}
                label="GLOBAL POSTURE SCORE"
                subtitle={`ENVIRONMENT RISK: ${posture?.risk_level || 'LOW'}`}
              />
            )}

            <div
              style={{
                width: '100%',
                marginTop: 'var(--space-4)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                fontSize: 'var(--font-size-xs)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">RISK LEVEL:</span>
                <strong className="text-cyan">{posture?.risk_level || 'NONE'}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">ACTIVE SCAN:</span>
                <span className="text-primary">{posture?.scan_id ? posture.scan_id.slice(0, 12) + '...' : 'LATEST'}</span>
              </div>
            </div>
          </CardBody>
        </Card>

        {/* Resource Posture Breakdown */}
        <Card variant="default">
          <CardHeader
            title="RESOURCE HEALTH DISTRIBUTION"
            subtitle="Real-time status of inspected cloud infrastructure resources."
          />
          <CardBody style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 'var(--space-4)' }}>
            {isLoading ? (
              <LoadingSkeleton variant="stat" count={4} />
            ) : (
              <div className="cg-grid-4">
                <StatTile
                  label="SECURE"
                  value={posture?.resource_posture_summary?.SECURE ?? 0}
                  context="Clean Baseline"
                  severity="success"
                  icon={<ShieldCheck size={16} />}
                />
                <StatTile
                  label="AT RISK"
                  value={posture?.resource_posture_summary?.AT_RISK ?? 0}
                  context="Low/Med Concerns"
                  severity="low"
                />
                <StatTile
                  label="HIGH RISK"
                  value={posture?.resource_posture_summary?.HIGH_RISK ?? 0}
                  context="Elevated Vulnerabilities"
                  severity="high"
                  icon={<AlertTriangle size={16} />}
                />
                <StatTile
                  label="CRITICAL"
                  value={posture?.resource_posture_summary?.CRITICAL ?? 0}
                  context="Immediate Exposure"
                  severity="critical"
                  icon={<AlertTriangle size={16} />}
                />
              </div>
            )}

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 16px',
                background: 'var(--bg-surface-subtle)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-subtle)',
                fontSize: 'var(--font-size-xs)',
                color: 'var(--text-muted)',
              }}
            >
              <span>Total Assessed Resources: <strong className="text-primary">{posture?.total_resources ?? 0}</strong></span>
              <span>Total Active Misconfigurations: <strong className="text-critical">{posture?.total_findings ?? 0}</strong></span>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Service Posture Breakdown Grid */}
      <Card variant="default">
        <CardHeader
          title="SERVICE POSTURE BREAKDOWN"
          subtitle="Precision risk scoring partitioned by discovered AWS service domain."
        />
        <CardBody>
          {isLoading ? (
            <LoadingSkeleton variant="card" count={4} />
          ) : !posture?.service_posture || Object.keys(posture.service_posture).length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)', padding: '16px 0' }}>
              No service telemetry records discovered for this environment.
            </div>
          ) : (
            <div className="cg-stat-grid">
              {Object.entries(posture.service_posture).map(([serviceKey, sData]) => {
                const isCrit = (sData.critical_findings || 0) > 0
                const isHigh = (sData.high_findings || 0) > 0

                return (
                  <div
                    key={serviceKey}
                    style={{
                      background: 'var(--surface-elevated)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-md)',
                      padding: '16px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 12,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Server size={14} style={{ color: 'var(--accent-cyan)' }} />
                        <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                          {serviceKey}
                        </span>
                      </div>
                      <Badge variant={isCrit ? 'critical' : isHigh ? 'high' : 'success'} size="sm">
                        {sData.risk_level || 'HEALTHY'}
                      </Badge>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                      <div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>POSTURE SCORE</div>
                        <div style={{ fontSize: 'var(--font-size-xl)', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                          {sData.posture_score?.toFixed(0) ?? 100}%
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>THREATS</div>
                        <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 700, color: sData.total_findings > 0 ? 'var(--sev-critical)' : 'var(--state-success)', fontFamily: 'var(--font-mono)' }}>
                          {sData.total_findings}
                        </div>
                      </div>
                    </div>

                    <div
                      style={{
                        display: 'flex',
                        gap: 6,
                        paddingTop: 8,
                        borderTop: '1px solid var(--border-subtle)',
                        fontSize: '10px',
                        color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      <span>Resources: {sData.total_resources}</span>
                      <span>•</span>
                      <span>Critical: {sData.critical_findings || 0}</span>
                      <span>•</span>
                      <span>High: {sData.high_findings || 0}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
