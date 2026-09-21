import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RefreshCw, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react'
import { resourcesApi } from '../../api/resourcesApi'
import { StatusBadge, Badge } from '../../components/Badge'
import { Drawer } from '../../components/Drawer'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader, Table, Button, Toolbar, Card } from '../../components/ui'
import type { Resource, ResourceDetail } from '../../types/resources'

export const AssetsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const [resources, setResources] = useState<Resource[]>([])
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(true)

  // Filters
  const [serviceFilter, setServiceFilter] = useState(searchParams.get('service') || '')
  const [postureFilter, setPostureFilter] = useState(searchParams.get('posture') || '')
  const [searchQuery, setSearchQuery] = useState('')

  // Detail Drawer
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(searchParams.get('resource_id'))
  const [resourceDetail, setResourceDetail] = useState<ResourceDetail | null>(null)
  const [isLoadingDetail, setIsLoadingDetail] = useState(false)

  const loadResources = async () => {
    setIsLoading(true)
    try {
      const res = await resourcesApi.listResources({
        service: serviceFilter || undefined,
        security_posture: postureFilter || undefined,
        limit: 50,
      })
      setResources(res.items || [])
      setTotal(res.total || 0)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadResources()
  }, [serviceFilter, postureFilter])

  useEffect(() => {
    if (selectedResourceId) {
      setIsLoadingDetail(true)
      resourcesApi
        .getResource(selectedResourceId)
        .then((detail) => setResourceDetail(detail))
        .catch(() => setResourceDetail(null))
        .finally(() => setIsLoadingDetail(false))
    } else {
      setResourceDetail(null)
    }
  }, [selectedResourceId])

  const filtered = resources.filter((r) => {
    if (!searchQuery.trim()) return true
    const q = searchQuery.toLowerCase()
    return (
      r.resource_id.toLowerCase().includes(q) ||
      (r.name && r.name.toLowerCase().includes(q)) ||
      r.service.toLowerCase().includes(q)
    )
  })

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="ASSETS EXPLORER"
        subtitle="Discovered cloud assets across regions, services, and accounts with live security posture status."
        badge={<Badge variant="cyan">{total} Resources</Badge>}
        actions={
          <Button
            variant="outline"
            size="md"
            icon={<RefreshCw size={13} className={isLoading ? 'spin' : ''} />}
            onClick={loadResources}
          >
            REFRESH INVENTORY
          </Button>
        }
      />

      {/* Filter Toolbar */}
      <Toolbar
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Filter by ID, ARN, or name..."
        filters={
          <>
            <select
              value={serviceFilter}
              onChange={(e) => {
                setServiceFilter(e.target.value)
                setSearchParams((prev) => {
                  if (e.target.value) prev.set('service', e.target.value)
                  else prev.delete('service')
                  return prev
                })
              }}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                fontSize: 'var(--font-size-xs)',
                cursor: 'pointer',
              }}
            >
              <option value="">All Services</option>
              <option value="s3">S3</option>
              <option value="iam">IAM</option>
              <option value="ec2">EC2</option>
              <option value="lambda">Lambda</option>
              <option value="rds">RDS</option>
              <option value="vpc">VPC</option>
            </select>

            <select
              value={postureFilter}
              onChange={(e) => {
                setPostureFilter(e.target.value)
                setSearchParams((prev) => {
                  if (e.target.value) prev.set('posture', e.target.value)
                  else prev.delete('posture')
                  return prev
                })
              }}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                fontSize: 'var(--font-size-xs)',
                cursor: 'pointer',
              }}
            >
              <option value="">All Postures</option>
              <option value="SECURE">Secure</option>
              <option value="AT_RISK">At Risk</option>
              <option value="HIGH_RISK">High Risk</option>
              <option value="CRITICAL">Critical</option>
            </select>

            {(serviceFilter || postureFilter || searchQuery) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setServiceFilter('')
                  setPostureFilter('')
                  setSearchQuery('')
                  setSearchParams({})
                }}
              >
                Clear Filters
              </Button>
            )}
          </>
        }
        countLabel={`Showing ${filtered.length} of ${total}`}
      />

      {/* Asset Table */}
      {isLoading ? (
        <LoadingSkeleton variant="table" count={6} />
      ) : filtered.length === 0 ? (
        <EmptyState
          title="No Cloud Assets Match Your Filters"
          description="Try broadening your service or security posture filters to view discovered resources."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <th>RESOURCE ID / ARN</th>
              <th>NAME</th>
              <th>SERVICE</th>
              <th>TYPE</th>
              <th>REGION</th>
              <th>SECURITY POSTURE</th>
              <th style={{ textAlign: 'right' }}>DETAILS</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr
                key={r.resource_id}
                onClick={() => setSelectedResourceId(r.resource_id)}
                style={{ cursor: 'pointer' }}
              >
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                      {r.resource_id}
                    </span>
                    {r.resource_arn && (
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {r.resource_arn.length > 50 ? r.resource_arn.slice(0, 50) + '...' : r.resource_arn}
                      </span>
                    )}
                  </div>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>{r.name || r.resource_name || '—'}</td>
                <td>
                  <Badge variant="cyan" size="sm">
                    {r.service}
                  </Badge>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {r.resource_type}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {r.region || 'global'}
                </td>
                <td>
                  <StatusBadge status={r.posture || r.security_posture || 'SECURE'} size="sm" />
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedResourceId(r.resource_id)
                    }}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--accent-cyan)',
                      fontSize: 'var(--font-size-xs)',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    INSPECT →
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {/* Resource Detail Drawer */}
      <Drawer
        isOpen={!!selectedResourceId}
        onClose={() => setSelectedResourceId(null)}
        title={resourceDetail?.resource?.name || resourceDetail?.resource?.resource_name || selectedResourceId || 'Resource Detail'}
        subtitle={resourceDetail?.resource?.resource_arn}
      >
        {isLoadingDetail ? (
          <LoadingSkeleton variant="text" count={6} />
        ) : resourceDetail ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Posture Banner */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 16px',
                background: 'var(--surface-elevated)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                CURRENT POSTURE:
              </span>
              <StatusBadge status={resourceDetail.security_posture || resourceDetail.resource?.security_posture || 'SECURE'} />
            </div>

            {/* Attributes Grid */}
            <div className="cg-grid-2">
              <div style={{ padding: '10px 14px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>SERVICE</div>
                <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2, textTransform: 'uppercase' }}>
                  {resourceDetail.resource?.service || 'UNKNOWN'}
                </div>
              </div>
              <div style={{ padding: '10px 14px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>REGION</div>
                <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                  {resourceDetail.resource?.region || 'global'}
                </div>
              </div>
            </div>

            {/* Findings attached to this resource */}
            <div>
              <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: '0.04em' }}>
                DETECTED MISCONFIGURATIONS ({resourceDetail.findings?.length || 0})
              </div>
              {!resourceDetail.findings || resourceDetail.findings.length === 0 ? (
                <div style={{ padding: '16px', background: 'var(--state-success-bg)', border: '1px solid var(--state-success-border)', borderRadius: 'var(--radius-sm)', color: 'var(--state-success)', fontSize: 'var(--font-size-xs)' }}>
                  ✓ No open findings associated with this resource.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {resourceDetail.findings.map((f) => (
                    <div
                      key={f.finding_id}
                      style={{
                        padding: '10px 14px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--surface-elevated)',
                        border: '1px solid var(--border-subtle)',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {f.title}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                          Rule: {f.rule_id}
                        </div>
                      </div>
                      <Badge variant={f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : 'medium'} size="sm">
                        {f.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Raw Configuration Dump */}
            {resourceDetail.safe_config && (
              <div>
                <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: '0.04em' }}>
                  PARSED CONFIGURATION SNAPSHOT
                </div>
                <pre
                  style={{
                    padding: 14,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--accent-cyan)',
                    maxHeight: 280,
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {JSON.stringify(resourceDetail.safe_config, null, 2)}
                </pre>
              </div>
            )}
          </div>
        ) : (
          <EmptyState title="Resource Not Found" description="The selected resource ID could not be loaded." />
        )}
      </Drawer>
    </div>
  )
}
