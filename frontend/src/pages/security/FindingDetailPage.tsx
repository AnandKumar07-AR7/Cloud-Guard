import React from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert,
  ArrowLeft,
  Cpu,
  Wrench,
  Globe,
  History,
} from 'lucide-react'
import { findingsApi } from '../../api/findingsApi'
import { SeverityBadge, StatusBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ['findings', 'detail', id],
    queryFn: () => findingsApi.getFinding(id!),
    enabled: Boolean(id),
  })

  const { data: historyData } = useQuery({
    queryKey: ['findings', 'history', finding?.canonical_id],
    queryFn: () => findingsApi.getFindingHistory(finding!.canonical_id),
    enabled: Boolean(finding?.canonical_id),
  })

  if (isLoading) {
    return (
      <div className="cg-page-container">
        <LoadingSkeleton variant="card" count={1} height="80px" />
        <LoadingSkeleton variant="card" count={2} height="180px" />
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="cg-page-container">
        <Link
          to="/findings"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            color: 'var(--text-secondary)',
            fontSize: '13px',
            textDecoration: 'none',
          }}
        >
          <ArrowLeft size={14} /> Back to Findings
        </Link>
        <EmptyState
          icon={ShieldAlert}
          title="Finding Not Found"
          description={`Finding '${id}' could not be loaded.`}
        />
      </div>
    )
  }

  return (
    <div className="cg-page-container">
      {/* Top Bar Navigation & Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Link
            to="/findings"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              padding: '6px 12px',
              background: 'var(--surface-overlay)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-secondary)',
              fontSize: '12px',
              textDecoration: 'none',
            }}
          >
            <ArrowLeft size={14} />
            Findings
          </Link>
          <span style={{ color: 'var(--text-muted)' }}>/</span>
          <span className="font-mono text-cyan" style={{ fontSize: '13px' }}>
            {finding.finding_id}
          </span>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
          <Link
            to={`/findings/${finding.finding_id}/investigate`}
            style={{ textDecoration: 'none' }}
          >
            <Button variant="outline" size="sm">
              <Cpu size={14} />
              AI Investigation
            </Button>
          </Link>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate(`/remediation?finding_id=${finding.finding_id}`)}
          >
            <Wrench size={14} />
            Remediate
          </Button>
        </div>
      </div>

      {/* Overview Card */}
      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-5)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-cyan" style={{ fontSize: '13px', fontWeight: 600 }}>
              {finding.rule_id}
            </span>
            <StatusBadge status={finding.status} />
            {finding.is_internet_exposed && (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--status-critical-bg)',
                  border: '1px solid var(--border-critical)',
                  color: 'var(--text-critical)',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                <Globe size={11} /> INTERNET EXPOSED
              </span>
            )}
          </div>

          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-high)', margin: 0 }}>
            {finding.title}
          </h1>

          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
            {finding.description}
          </p>

          {/* Technical Specs Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 'var(--space-3)',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--surface-overlay)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resource</div>
              <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                {finding.resource_name || finding.resource_id}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Service / Type</div>
              <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                {finding.service.toUpperCase()} • {finding.resource_type}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Account & Region</div>
              <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                {finding.account_id} • {finding.region || 'global'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
              <div
                className="font-mono"
                style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: finding.risk_score >= 80 ? 'var(--text-critical)' : 'var(--accent-primary)',
                  marginTop: '2px',
                }}
              >
                {finding.risk_score !== undefined ? finding.risk_score.toFixed(1) : 'N/A'}
              </div>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Evidence Section */}
      <Card variant="elevated">
        <CardHeader title="Deterministic Evidence" />
        <CardBody style={{ padding: 'var(--space-4)' }}>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-3)' }}>
            {finding.evidence?.summary}
          </div>
          <pre
            className="font-mono"
            style={{
              padding: 'var(--space-3)',
              background: 'var(--surface-overlay)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              color: 'var(--text-high)',
              overflowX: 'auto',
              margin: 0,
            }}
          >
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </CardBody>
      </Card>

      {/* History Section */}
      {historyData?.history && Array.isArray(historyData.history) && (
        <Card variant="elevated">
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <History size={15} style={{ color: 'var(--accent-primary)' }} />
                <span>Finding History</span>
                <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 'normal' }}>
                  (Canonical ID: {finding.canonical_id})
                </span>
              </div>
            }
          />
          <CardBody style={{ padding: 'var(--space-3) var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {historyData.history.map((h, idx) => (
              <div
                key={h.finding_id + idx}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 12px',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '12px',
                }}
              >
                <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
                  <span className="font-mono text-cyan">Scan: {h.scan_id}</span>
                  <StatusBadge status={h.status} />
                </div>
                <div className="font-mono" style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                  {h.last_detected_at || 'Detected'}
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      )}
    </div>
  )
}
