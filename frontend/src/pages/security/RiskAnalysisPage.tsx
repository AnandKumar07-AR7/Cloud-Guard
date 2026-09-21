import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Globe,
  Key,
  Database,
  ShieldCheck,
} from 'lucide-react'
import { postureApi } from '../../api/postureApi'
import { findingsApi } from '../../api/findingsApi'
import { SeverityBadge } from '../../components/Badge'
import { ScoreGauge } from '../../components/ScoreGauge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Link } from 'react-router-dom'

export const RiskAnalysisPage: React.FC = () => {
  const { data: posture, isLoading: loadingPosture } = useQuery({
    queryKey: ['posture', 'risk'],
    queryFn: () => postureApi.getPosture(),
  })

  const { data: findingsData, isLoading: loadingFindings } = useQuery({
    queryKey: ['findings', 'top-risks'],
    queryFn: () => findingsApi.listFindings({ limit: 50 }),
  })

  const findings = findingsData?.findings || []

  // Top risks sorted by risk score descending
  const topRisks = [...findings]
    .filter((f) => f.risk_score !== undefined)
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 10)

  // Calculate deterministic multipliers distribution
  const internetExposedCount = findings.filter((f) => f.is_internet_exposed).length
  const privEscCount = findings.filter((f) => f.privilege_escalation_risk).length
  const dataExpCount = findings.filter((f) => f.data_exposure_risk).length

  if (loadingPosture || loadingFindings) {
    return (
      <div className="cg-page-container">
        <LoadingSkeleton variant="card" count={1} height="120px" />
        <div className="cg-grid-3">
          <LoadingSkeleton variant="card" count={1} height="200px" />
          <LoadingSkeleton variant="card" count={1} height="200px" />
          <LoadingSkeleton variant="card" count={1} height="200px" />
        </div>
      </div>
    )
  }

  const postureScore = posture?.posture_score ?? 100
  const riskLevel = posture?.risk_level ?? 'LOW'

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Deterministic Risk Analysis"
        subtitle="Mathematical risk calculation based on base severity, asset exposure, privilege amplification, and data sensitivity."
      />

      {/* Top Banner: Score & Multipliers */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '300px 1fr',
          gap: 'var(--space-4)',
          alignItems: 'stretch',
        }}
      >
        {/* Posture Scorecard */}
        <Card
          variant="elevated"
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--space-5)',
            textAlign: 'center',
          }}
        >
          <ScoreGauge score={postureScore} size={140} strokeWidth={11} />
          <div style={{ marginTop: 'var(--space-3)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Environment Risk Level
            </div>
            <div
              style={{
                fontSize: '15px',
                fontWeight: 700,
                color:
                  riskLevel === 'CRITICAL'
                    ? 'var(--text-critical)'
                    : riskLevel === 'HIGH'
                    ? 'var(--text-high)'
                    : 'var(--accent-primary)',
                marginTop: '2px',
              }}
            >
              {riskLevel} RISK
            </div>
          </div>
        </Card>

        {/* Multipliers Grid */}
        <Card variant="elevated" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <CardHeader
            title="Deterministic Risk Formula"
            action={
              <span className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                Formula Engine v1.2
              </span>
            }
          />
          <CardBody style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div
              style={{
                padding: 'var(--space-3)',
                background: 'var(--surface-overlay)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
                fontSize: '12px',
              }}
            >
              <code className="font-mono text-cyan">
                Final Score = Base Score + Internet Exposure (+20) + Privilege Escalation (+15) + Sensitive Data (+15)
              </code>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-3)' }}>
              {/* Multiplier 1 */}
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--text-warning)', marginBottom: 'var(--space-1)' }}>
                  <Globe size={15} />
                  <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Internet Exposed</span>
                </div>
                <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-high)' }}>
                  {internetExposedCount}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  +20 Multiplier Applied
                </div>
              </div>

              {/* Multiplier 2 */}
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: '#ec4899', marginBottom: 'var(--space-1)' }}>
                  <Key size={15} />
                  <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Privilege Risk</span>
                </div>
                <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-high)' }}>
                  {privEscCount}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  +15 Multiplier Applied
                </div>
              </div>

              {/* Multiplier 3 */}
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--accent-primary)', marginBottom: 'var(--space-1)' }}>
                  <Database size={15} />
                  <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase' }}>Data Exposure</span>
                </div>
                <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-high)' }}>
                  {dataExpCount}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  +15 Multiplier Applied
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Top 10 High Risk Items */}
      <Card variant="elevated">
        <CardHeader
          title="Ranked High-Risk Findings"
          action={
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Ordered strictly by deterministic risk score
            </span>
          }
        />

        <CardBody style={{ padding: 0 }}>
          {topRisks.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={ShieldCheck}
                title="No High Risk Findings"
                description="Environment is currently operating within secure parameters."
              />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '90px' }}>Risk Score</th>
                    <th style={{ width: '110px' }}>Severity</th>
                    <th>Finding & Rule</th>
                    <th>Target Resource</th>
                    <th style={{ width: '150px' }}>Multipliers</th>
                    <th style={{ textAlign: 'right', width: '110px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisks.map((finding) => (
                    <tr key={finding.finding_id}>
                      <td>
                        <span
                          className="font-mono"
                          style={{
                            padding: '3px 7px',
                            borderRadius: 'var(--radius-sm)',
                            fontWeight: 700,
                            fontSize: '12px',
                            background:
                              (finding.risk_score || 0) >= 80
                                ? 'var(--status-critical-bg)'
                                : 'rgba(249, 115, 22, 0.15)',
                            color:
                              (finding.risk_score || 0) >= 80
                                ? 'var(--text-critical)'
                                : 'var(--text-high)',
                          }}
                        >
                          {finding.risk_score?.toFixed(1)}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <div style={{ fontWeight: 500, color: 'var(--text-high)', marginBottom: '2px' }}>
                          {finding.title}
                        </div>
                        <div className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                          {finding.rule_id}
                        </div>
                      </td>
                      <td>
                        <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                          {finding.resource_name || finding.resource_id}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          {finding.service} • {finding.resource_type}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {finding.is_internet_exposed && (
                            <span
                              style={{
                                fontSize: '10px',
                                padding: '2px 6px',
                                borderRadius: 'var(--radius-sm)',
                                background: 'rgba(245, 158, 11, 0.15)',
                                color: 'var(--text-warning)',
                                fontWeight: 600,
                              }}
                            >
                              EXPOSED (+20)
                            </span>
                          )}
                          {finding.privilege_escalation_risk && (
                            <span
                              style={{
                                fontSize: '10px',
                                padding: '2px 6px',
                                borderRadius: 'var(--radius-sm)',
                                background: 'rgba(236, 72, 153, 0.15)',
                                color: '#ec4899',
                                fontWeight: 600,
                              }}
                            >
                              PRIV (+15)
                            </span>
                          )}
                          {!finding.is_internet_exposed && !finding.privilege_escalation_risk && (
                            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Base Only</span>
                          )}
                        </div>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <Link
                          to={`/findings/${finding.finding_id}/investigate`}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            padding: '3px 8px',
                            background: 'var(--surface-overlay)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-sm)',
                            color: 'var(--accent-primary)',
                            fontSize: '11px',
                            textDecoration: 'none',
                          }}
                        >
                          Investigate
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
