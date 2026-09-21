import React, { useState, useMemo } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert,
  Search,
  Globe,
  RotateCw,
  Cpu,
  Wrench,
} from 'lucide-react'
import { findingsApi } from '../../api/findingsApi'
import { scansApi } from '../../api/scansApi'
import { SeverityBadge, StatusBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Drawer } from '../../components/Drawer'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import type { Finding } from '../../types/findings'

export const FindingsPage: React.FC = () => {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const scanId = searchParams.get('scan_id') || undefined
  const severityFilter = searchParams.get('severity') || 'ALL'
  const serviceFilter = searchParams.get('service') || 'ALL'
  const statusFilter = searchParams.get('status') || 'ALL'
  const internetExposedFilter = searchParams.get('exposed') === 'true'
  const searchQuery = searchParams.get('q') || ''
  const page = parseInt(searchParams.get('page') || '1', 10)
  const limit = 25

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  // Fetch scans list for scan dropdown
  const { data: scansData } = useQuery({
    queryKey: ['scans', 'list'],
    queryFn: () => scansApi.listScans(20, 0),
  })

  // Fetch findings
  const { data: findingsData, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['findings', 'list', scanId, severityFilter, serviceFilter, statusFilter, internetExposedFilter, page],
    queryFn: () =>
      findingsApi.listFindings({
        scan_id: scanId,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        service: serviceFilter !== 'ALL' ? serviceFilter : undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        internet_exposed: internetExposedFilter ? true : undefined,
        limit,
        offset: (page - 1) * limit,
      }),
  })

  const findings = findingsData?.findings || findingsData?.items || []
  const totalFindings = findingsData?.total !== undefined ? findingsData.total : findings.length
  const totalPages = Math.max(1, Math.ceil(totalFindings / limit))

  // Local text search filter
  const filteredFindings = useMemo(() => {
    if (!searchQuery) return findings
    const q = searchQuery.toLowerCase()
    return findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q) ||
        f.resource_id.toLowerCase().includes(q) ||
        (f.resource_name && f.resource_name.toLowerCase().includes(q))
    )
  }, [findings, searchQuery])

  // Update URL params helper
  const updateFilter = (key: string, value: string | null) => {
    const newParams = new URLSearchParams(searchParams)
    if (!value || value === 'ALL') {
      newParams.delete(key)
    } else {
      newParams.set(key, value)
    }
    newParams.set('page', '1')
    setSearchParams(newParams)
  }

  // Count metrics
  const criticalCount = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL').length
  const highCount = findings.filter((f) => f.severity.toUpperCase() === 'HIGH').length
  const exposedCount = findings.filter((f) => f.is_internet_exposed).length

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Security Findings"
        subtitle="Comprehensive detection registry with deterministic evidence, risk scoring, and AI investigation."
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

      {/* Filter Bar */}
      <Card variant="default">
        <CardBody style={{ padding: 'var(--space-3)' }}>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 'var(--space-3)',
              alignItems: 'center',
            }}
          >
            {/* Search */}
            <div style={{ position: 'relative', flex: '1 1 240px', minWidth: '200px' }}>
              <Search
                size={14}
                style={{
                  position: 'absolute',
                  left: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                }}
              />
              <input
                type="text"
                placeholder="Search title, rule ID, resource..."
                value={searchQuery}
                onChange={(e) => updateFilter('q', e.target.value)}
                style={{
                  width: '100%',
                  padding: '7px 12px 7px 32px',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-high)',
                  fontSize: '12px',
                  outline: 'none',
                }}
              />
            </div>

            {/* Scan Filter */}
            <select
              value={scanId || ''}
              onChange={(e) => updateFilter('scan_id', e.target.value || null)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
              }}
            >
              <option value="">All Scans (Latest)</option>
              {(scansData?.scans || scansData?.items || []).map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.scan_id.slice(0, 8)}... ({s.status})
                </option>
              ))}
            </select>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => updateFilter('severity', e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>

            {/* Service Filter */}
            <select
              value={serviceFilter}
              onChange={(e) => updateFilter('service', e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Services</option>
              <option value="s3">S3</option>
              <option value="iam">IAM</option>
              <option value="ec2">EC2</option>
              <option value="rds">RDS</option>
              <option value="lambda">Lambda</option>
              <option value="vpc">VPC</option>
              <option value="cloudtrail">CloudTrail</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => updateFilter('status', e.target.value)}
              style={{
                padding: '7px 12px',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="RESOLVED">Resolved</option>
              <option value="SUPPRESSED">Suppressed</option>
            </select>

            {/* Internet Exposed Toggle */}
            <button
              onClick={() => updateFilter('exposed', internetExposedFilter ? null : 'true')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '7px 12px',
                borderRadius: 'var(--radius-sm)',
                border: internetExposedFilter
                  ? '1px solid var(--border-critical)'
                  : '1px solid var(--border-subtle)',
                background: internetExposedFilter ? 'var(--status-critical-bg)' : 'var(--surface-overlay)',
                color: internetExposedFilter ? 'var(--text-critical)' : 'var(--text-secondary)',
                fontSize: '12px',
                fontWeight: internetExposedFilter ? 600 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Globe size={13} />
              Internet Exposed
            </button>
          </div>
        </CardBody>
      </Card>

      {/* Findings Table Card */}
      <Card variant="elevated">
        <CardHeader
          title={
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', gap: 'var(--space-2)' }}>
              <span>
                Showing <strong className="font-mono text-cyan">{filteredFindings.length}</strong> of{' '}
                <strong className="font-mono">{totalFindings}</strong> findings
              </span>
            </div>
          }
          action={
            <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', fontSize: '11px' }}>
              {criticalCount > 0 && <span style={{ color: 'var(--text-critical)' }}>● {criticalCount} Critical</span>}
              {highCount > 0 && <span style={{ color: 'var(--text-high)' }}>● {highCount} High</span>}
              {exposedCount > 0 && <span style={{ color: 'var(--text-warning)' }}>● {exposedCount} Exposed</span>}
            </div>
          }
        />

        <CardBody style={{ padding: 0 }}>
          {isLoading ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <LoadingSkeleton variant="table" count={6} height="48px" />
            </div>
          ) : filteredFindings.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={ShieldAlert}
                title="No Findings Found"
                description={
                  searchQuery || severityFilter !== 'ALL' || serviceFilter !== 'ALL'
                    ? 'No findings match your current filter criteria. Try resetting filters.'
                    : 'No security misconfigurations detected in the selected scan.'
                }
              />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '120px' }}>Severity</th>
                    <th>Finding & Rule ID</th>
                    <th>Resource</th>
                    <th style={{ width: '90px' }}>Risk</th>
                    <th style={{ width: '100px' }}>Status</th>
                    <th style={{ textAlign: 'right', width: '130px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.finding_id}
                      onClick={() => setSelectedFinding(finding)}
                      style={{ cursor: 'pointer' }}
                    >
                      {/* Severity */}
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>

                      {/* Finding Title & Rule */}
                      <td>
                        <div style={{ fontWeight: 500, color: 'var(--text-high)', marginBottom: '3px' }}>
                          {finding.title}
                        </div>
                        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', fontSize: '11px' }}>
                          <span className="font-mono text-cyan">{finding.rule_id}</span>
                          <span style={{ color: 'var(--text-muted)' }}>•</span>
                          <span style={{ color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                            {finding.category}
                          </span>
                          {finding.is_internet_exposed && (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '3px',
                                padding: '1px 5px',
                                borderRadius: 'var(--radius-sm)',
                                background: 'var(--status-critical-bg)',
                                border: '1px solid var(--border-critical)',
                                color: 'var(--text-critical)',
                                fontSize: '10px',
                                fontWeight: 600,
                              }}
                            >
                              <Globe size={10} />
                              EXPOSED
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Target Resource */}
                      <td>
                        <div className="font-mono" style={{ color: 'var(--text-high)', fontSize: '12px' }}>
                          {finding.resource_name || finding.resource_id}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          {finding.service} • {finding.resource_type}
                        </div>
                      </td>

                      {/* Risk Score */}
                      <td>
                        {finding.risk_score !== undefined ? (
                          <span
                            className="font-mono"
                            style={{
                              padding: '2px 6px',
                              borderRadius: 'var(--radius-sm)',
                              background:
                                finding.risk_score >= 80
                                  ? 'var(--status-critical-bg)'
                                  : finding.risk_score >= 60
                                  ? 'rgba(249, 115, 22, 0.12)'
                                  : 'var(--status-info-bg)',
                              color:
                                finding.risk_score >= 80
                                  ? 'var(--text-critical)'
                                  : finding.risk_score >= 60
                                  ? 'var(--text-high)'
                                  : 'var(--accent-primary)',
                              fontWeight: 600,
                              fontSize: '11px',
                            }}
                          >
                            {finding.risk_score.toFixed(1)}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>N/A</span>
                        )}
                      </td>

                      {/* Status */}
                      <td>
                        <StatusBadge status={finding.status} />
                      </td>

                      {/* Actions */}
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                          <Link
                            to={`/findings/${finding.finding_id}/investigate`}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              padding: '4px 8px',
                              background: 'var(--status-info-bg)',
                              border: '1px solid var(--border-accent)',
                              borderRadius: 'var(--radius-sm)',
                              color: 'var(--accent-primary)',
                              fontSize: '11px',
                              textDecoration: 'none',
                              fontWeight: 500,
                            }}
                          >
                            <Cpu size={12} />
                            Investigate
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div
            style={{
              padding: 'var(--space-3) var(--space-4)',
              borderTop: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              fontSize: '12px',
              color: 'var(--text-secondary)',
            }}
          >
            <div>
              Page <span className="font-mono">{page}</span> of <span className="font-mono">{totalPages}</span>
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => updateFilter('page', String(page - 1))}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => updateFilter('page', String(page + 1))}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Finding Detail Quick Drawer */}
      <Drawer
        isOpen={Boolean(selectedFinding)}
        onClose={() => setSelectedFinding(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Finding Details</span>
            {selectedFinding && <SeverityBadge severity={selectedFinding.severity} />}
          </div>
        }
        width="660px"
      >
        {selectedFinding && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {/* Title & Description */}
            <div>
              <h2 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)', margin: '0 0 var(--space-2) 0' }}>
                {selectedFinding.title}
              </h2>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                {selectedFinding.description}
              </p>
            </div>

            {/* Quick Metadata Box */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: 'var(--space-3)',
                padding: 'var(--space-3)',
                background: 'var(--surface-overlay)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Finding ID</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedFinding.finding_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Canonical ID</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedFinding.canonical_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Rule ID</div>
                <div className="font-mono text-cyan" style={{ fontSize: '12px', marginTop: '2px' }}>
                  {selectedFinding.rule_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resource ID</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedFinding.resource_id}
                </div>
              </div>
            </div>

            {/* Evidence View */}
            {selectedFinding.evidence && (
              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>
                  Deterministic Evidence
                </h3>
                <div
                  style={{
                    padding: 'var(--space-3)',
                    background: 'var(--surface-overlay)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.5,
                  }}
                >
                  <div>{selectedFinding.evidence.summary}</div>
                  {selectedFinding.evidence.details && Object.keys(selectedFinding.evidence.details).length > 0 && (
                    <pre
                      className="font-mono"
                      style={{
                        marginTop: 'var(--space-2)',
                        padding: 'var(--space-2)',
                        background: 'var(--surface-base)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '11px',
                        color: 'var(--accent-primary)',
                        overflowX: 'auto',
                      }}
                    >
                      {JSON.stringify(selectedFinding.evidence.details, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            )}

            {/* Action buttons */}
            <div style={{ display: 'flex', gap: 'var(--space-3)', marginTop: 'var(--space-2)' }}>
              <Button
                variant="primary"
                style={{ flex: 1 }}
                onClick={() => {
                  navigate(`/findings/${selectedFinding.finding_id}/investigate`)
                  setSelectedFinding(null)
                }}
              >
                <Cpu size={14} />
                Open AI Investigation
              </Button>

              <Button
                variant="outline"
                onClick={() => {
                  navigate(`/remediation?finding_id=${selectedFinding.finding_id}`)
                  setSelectedFinding(null)
                }}
              >
                <Wrench size={14} />
                Remediate
              </Button>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}
