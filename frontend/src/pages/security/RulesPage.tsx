import React, { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  Search,
  BookOpen,
  ChevronRight,
  FileCode,
} from 'lucide-react'
import { rulesApi } from '../../api/rulesApi'
import { SeverityBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Drawer } from '../../components/Drawer'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import type { SecurityRule } from '../../types/rules'

export const RulesPage: React.FC = () => {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [serviceFilter, setServiceFilter] = useState('ALL')
  const [categoryFilter, setCategoryFilter] = useState('ALL')
  const [selectedRule, setSelectedRule] = useState<SecurityRule | null>(null)

  const { data: rulesData, isLoading, error } = useQuery({
    queryKey: ['rules', 'list', severityFilter, serviceFilter, categoryFilter],
    queryFn: () =>
      rulesApi.listRules({
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        service: serviceFilter !== 'ALL' ? serviceFilter : undefined,
        category: categoryFilter !== 'ALL' ? categoryFilter : undefined,
        limit: 100,
      }),
  })

  const rules = rulesData?.items || []
  const totalRules = rulesData?.total || 0

  const filteredRules = useMemo(() => {
    if (!search) return rules
    const q = search.toLowerCase()
    return rules.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.rule_id.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q)
    )
  }, [rules, search])

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Detection Rules Catalog"
        subtitle="Production-grade deterministic cloud security rules across S3, IAM, EC2, RDS, VPC, Lambda, and CloudTrail."
        badge={
          <span
            style={{
              padding: '3px 10px',
              background: 'var(--surface-overlay)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
            }}
          >
            <span style={{ color: 'var(--text-muted)' }}>Registered Rules: </span>
            <span className="font-mono text-cyan" style={{ fontWeight: 600 }}>
              {totalRules}
            </span>
          </span>
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
            <div style={{ position: 'relative', flex: '1 1 240px', minWidth: '200px' }}>
              <Search
                size={14}
                style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
              />
              <input
                type="text"
                placeholder="Search rules by name, ID, or description..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
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

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
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

            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
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

            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
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
              <option value="ALL">All Categories</option>
              <option value="access-control">Access Control</option>
              <option value="encryption">Encryption</option>
              <option value="logging">Logging & Auditing</option>
              <option value="network">Network Security</option>
              <option value="resilience">Resilience</option>
            </select>
          </div>
        </CardBody>
      </Card>

      {/* Rules Table */}
      <Card variant="elevated">
        <CardBody style={{ padding: 0 }}>
          {isLoading ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <LoadingSkeleton variant="table" count={6} height="48px" />
            </div>
          ) : filteredRules.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState
                icon={Shield}
                title="No Detection Rules Found"
                description={
                  search || severityFilter !== 'ALL' || serviceFilter !== 'ALL' || categoryFilter !== 'ALL'
                    ? 'No rules match your filter criteria.'
                    : 'No detection rules currently loaded.'
                }
              />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '120px' }}>Severity</th>
                    <th>Rule Name & Identifier</th>
                    <th>Service / Resource</th>
                    <th>Category</th>
                    <th style={{ width: '90px' }}>Status</th>
                    <th style={{ textAlign: 'right', width: '90px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map((rule) => (
                    <tr
                      key={rule.rule_id}
                      onClick={() => setSelectedRule(rule)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <SeverityBadge severity={rule.severity} />
                      </td>
                      <td>
                        <div style={{ fontWeight: 500, color: 'var(--text-high)', marginBottom: '3px' }}>
                          {rule.name}
                        </div>
                        <div className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                          {rule.rule_id}
                        </div>
                      </td>
                      <td>
                        <div className="font-mono uppercase" style={{ color: 'var(--text-high)', fontSize: '12px' }}>
                          {rule.service}
                        </div>
                        <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {rule.resource_type}
                        </div>
                      </td>
                      <td>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background: 'var(--surface-overlay)',
                            border: '1px solid var(--border-subtle)',
                            fontSize: '11px',
                            color: 'var(--text-secondary)',
                            textTransform: 'capitalize',
                          }}
                        >
                          {rule.category}
                        </span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            color: rule.enabled !== false ? 'var(--text-success)' : 'var(--text-muted)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          ● {rule.enabled !== false ? 'ACTIVE' : 'DISABLED'}
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

      {/* Rule Detail Drawer */}
      <Drawer
        isOpen={Boolean(selectedRule)}
        onClose={() => setSelectedRule(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Rule Details</span>
            {selectedRule && <SeverityBadge severity={selectedRule.severity} />}
          </div>
        }
        width="660px"
      >
        {selectedRule && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-high)', margin: '0 0 var(--space-2) 0' }}>
                {selectedRule.name}
              </h2>
              <div className="font-mono text-cyan" style={{ fontSize: '12px', marginBottom: 'var(--space-2)' }}>
                {selectedRule.rule_id}
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                {selectedRule.description}
              </p>
            </div>

            {/* Rule Specs */}
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
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Service</div>
                <div className="font-mono uppercase" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedRule.service}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Resource Type</div>
                <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedRule.resource_type}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Category</div>
                <div style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px', textTransform: 'capitalize' }}>
                  {selectedRule.category}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Provider</div>
                <div className="font-mono uppercase" style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '2px' }}>
                  {selectedRule.provider || 'aws'}
                </div>
              </div>
            </div>

            {/* Rationale */}
            {selectedRule.rationale && (
              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>
                  Security Rationale
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
                  {selectedRule.rationale}
                </div>
              </div>
            )}

            {/* Remediation Procedure */}
            {selectedRule.remediation && (
              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>
                  Remediation Procedure
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
                  {selectedRule.remediation}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  )
}
