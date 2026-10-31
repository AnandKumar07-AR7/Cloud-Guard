import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Layers,
  Play,
  RotateCw,
  ChevronRight,
  Loader2,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react'
import { scansApi } from '../../api/scansApi'
import { SeverityBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Modal } from '../../components/Modal'
import { Drawer } from '../../components/Drawer'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import type { ScanSummary } from '../../types/scans'
import { Link } from 'react-router-dom'

export const ScansPage: React.FC = () => {
  const queryClient = useQueryClient()
  const [isRunModalOpen, setIsRunModalOpen] = useState(false)
  const [selectedScan, setSelectedScan] = useState<ScanSummary | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)

  // Form state for Run Scan modal
  const [scenario, setScenario] = useState('full')
  const [aiEnrichment, setAiEnrichment] = useState(true)

  const { data: scansData, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['scans', 'list'],
    queryFn: () => scansApi.listScans(50, 0),
  })

  const runScanMutation = useMutation({
    mutationFn: () =>
      scansApi.createScan({
        scenario,
        enrich_with_ai: aiEnrichment,  // matches backend ScanRequest field name
      }),
    onSuccess: (data) => {
      setScanError(null)
      setActiveScanId(data.scan_id)
      setIsRunModalOpen(false)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['posture'] })
      // Auto-refresh list after 4s for AWS async scans
      setTimeout(() => {
        refetch()
        setActiveScanId(null)
      }, 4000)
    },
    onError: (err: unknown) => {
      const message =
        err instanceof Error ? err.message : 'Failed to start scan. Please try again.'
      setScanError(message)
    },
  })

  const scans = scansData?.scans || []

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Security Scans"
        subtitle="Multi-service asset discovery and deterministic misconfiguration evaluation runs."
        actions={
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              <RotateCw size={14} className={isFetching ? 'spin' : ''} />
              Refresh
            </Button>

            <Button
              variant="primary"
              size="sm"
              onClick={() => setIsRunModalOpen(true)}
            >
              <Play size={14} />
              Run Security Scan
            </Button>
          </div>
        }
      />

      {/* Scan in-progress banner */}
      {activeScanId && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: '10px 16px',
          background: 'rgba(6,182,212,0.08)',
          border: '1px solid rgba(6,182,212,0.3)',
          borderRadius: 'var(--radius-sm)',
          marginBottom: 'var(--space-3)',
        }}>
          <Loader2 size={16} className="spin" style={{ color: 'var(--accent-primary)', flexShrink: 0 }} />
          <span style={{ fontSize: '13px', color: 'var(--text-high)' }}>
            Scan <span className="font-mono text-cyan" style={{ fontSize: '12px' }}>{activeScanId}</span> has been queued and is running in the background.
          </span>
        </div>
      )}

      {/* Error banner */}
      {scanError && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: '10px 16px',
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 'var(--radius-sm)',
          marginBottom: 'var(--space-3)',
        }}>
          <AlertCircle size={16} style={{ color: 'var(--text-critical)', flexShrink: 0 }} />
          <span style={{ fontSize: '13px', color: 'var(--text-critical)', flex: 1 }}>{scanError}</span>
          <button
            onClick={() => setScanError(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: '16px', lineHeight: 1 }}
          >×</button>
        </div>
      )}

      {/* Scans Table Card */}
      <Card variant="elevated">
        <CardHeader
          title={
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Showing <strong className="font-mono text-cyan">{scans.length}</strong> recorded scans
            </span>
          }
        />

        <CardBody style={{ padding: 0 }}>
          {isLoading ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <LoadingSkeleton variant="table" count={5} height="48px" />
            </div>
          ) : scans.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={Layers}
                title="No Scans Executed"
                description="Run your first cloud security scan to evaluate asset configurations against detection rules."
              />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '120px' }}>Status</th>
                    <th style={{ width: '180px' }}>Scan ID</th>
                    <th style={{ width: '130px' }}>Scenario</th>
                    <th>Resources & Findings</th>
                    <th style={{ width: '140px' }}>Posture Score</th>
                    <th style={{ width: '160px' }}>Timestamp</th>
                    <th style={{ textAlign: 'right', width: '90px' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr
                      key={scan.scan_id}
                      onClick={() => setSelectedScan(scan)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background:
                              scan.status === 'COMPLETED'
                                ? 'var(--status-success-bg)'
                                : scan.status === 'FAILED'
                                ? 'var(--status-critical-bg)'
                                : 'var(--status-warning-bg)',
                            color:
                              scan.status === 'COMPLETED'
                                ? 'var(--text-success)'
                                : scan.status === 'FAILED'
                                ? 'var(--text-critical)'
                                : 'var(--text-warning)',
                          }}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {scan.scan_id}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono uppercase" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                          {scan.scenario || 'full'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                          <span style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                            {scan.resources_scanned || scan.resource_count || 0} resources
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>•</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-critical)', fontWeight: 600 }}>
                            {scan.findings_count || scan.finding_count || 0} findings
                          </span>
                        </div>
                      </td>
                      <td>
                        {scan.risk_summary?.posture_score !== undefined ? (
                          <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent-primary)' }}>
                            {scan.risk_summary.posture_score.toFixed(1)} / 100
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Recorded</span>
                        )}
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '2px', color: 'var(--accent-primary)', fontSize: '12px' }}>
                          <span>Inspect</span>
                          <ChevronRight size={13} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Run Scan Modal */}
      <Modal
        isOpen={isRunModalOpen}
        onClose={() => setIsRunModalOpen(false)}
        title="Launch Security Scan"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
              Scan Scenario
            </label>
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
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
            >
              <option value="full">Full Cloud Environment (All Services)</option>
              <option value="s3_critical">S3 Public Exposure & Bucket Policies</option>
              <option value="iam_privilege">IAM Roles, Keys & Privilege Escalation</option>
              <option value="network_ingress">Security Groups & Ingress Exposure</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <input
              type="checkbox"
              id="ai-enrich"
              checked={aiEnrichment}
              onChange={(e) => setAiEnrichment(e.target.checked)}
              style={{ accentColor: 'var(--accent-primary)' }}
            />
            <label htmlFor="ai-enrich" style={{ fontSize: '13px', color: 'var(--text-high)', cursor: 'pointer' }}>
              Trigger autonomous AI investigation for critical detections
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsRunModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => runScanMutation.mutate()}
              disabled={runScanMutation.isPending}
            >
              {runScanMutation.isPending ? 'Starting Scan...' : 'Start Scan'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Scan Detail Drawer */}
      <Drawer
        isOpen={Boolean(selectedScan)}
        onClose={() => setSelectedScan(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Scan Details:</span>
            <span className="font-mono text-cyan" style={{ fontSize: '12px' }}>
              {selectedScan?.scan_id}
            </span>
          </div>
        }
        width="660px"
      >
        {selectedScan && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
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
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Status</div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-success)', marginTop: '2px' }}>
                  {selectedScan.status}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Scenario</div>
                <div className="font-mono uppercase" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedScan.scenario || 'full'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resources Evaluated</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedScan.resources_scanned || selectedScan.resource_count || 0}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Findings Identified</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-critical)', fontWeight: 600, marginTop: '2px' }}>
                  {selectedScan.findings_count || selectedScan.finding_count || 0}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <Link
                to={`/findings?scan_id=${selectedScan.scan_id}`}
                style={{ textDecoration: 'none', flex: 1 }}
              >
                <Button variant="primary" style={{ width: '100%' }}>
                  View All Findings from this Scan
                </Button>
              </Link>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}
