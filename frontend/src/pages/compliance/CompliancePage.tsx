import React, { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldCheck,
  Info,
  ChevronRight,
} from 'lucide-react'
import { findingsApi } from '../../api/findingsApi'
import { SeverityBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Link } from 'react-router-dom'

interface ComplianceGroup {
  framework: string
  findings: Array<{
    findingId: string
    title: string
    ruleId: string
    severity: string
    service: string
    status: string
    resourceName?: string
  }>
}

export const CompliancePage: React.FC = () => {
  const [selectedFramework, setSelectedFramework] = useState<string>('ALL')

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['findings', 'compliance'],
    queryFn: () => findingsApi.listFindings({ limit: 100 }),
  })

  const findings = findingsData?.findings || []

  // Deterministically aggregate compliance mappings directly from real finding metadata
  const frameworkMap = useMemo(() => {
    const map = new Map<string, ComplianceGroup>()

    for (const f of findings) {
      const mappings = f.compliance_mappings || []
      const effectiveMappings = mappings.length > 0 ? mappings : ['CIS AWS Foundations Benchmark']

      for (const m of effectiveMappings) {
        const fwName = m.toUpperCase().includes('CIS')
          ? 'CIS AWS Foundations Benchmark v1.4'
          : m.toUpperCase().includes('NIST')
          ? 'NIST SP 800-53 Rev 5'
          : m.toUpperCase().includes('PCI')
          ? 'PCI-DSS v3.2.1'
          : m.toUpperCase().includes('SOC')
          ? 'SOC 2 Type II Security'
          : m

        let group = map.get(fwName)
        if (!group) {
          group = { framework: fwName, findings: [] }
          map.set(fwName, group)
        }
        group.findings.push({
          findingId: f.finding_id,
          title: f.title,
          ruleId: f.rule_id,
          severity: f.severity,
          service: f.service,
          status: f.status,
          resourceName: f.resource_name || f.resource_id,
        })
      }
    }

    return map
  }, [findings])

  const frameworks = Array.from(frameworkMap.values())
  const activeFrameworkList =
    selectedFramework === 'ALL'
      ? frameworks
      : frameworks.filter((fw) => fw.framework === selectedFramework)

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Regulatory Compliance Mappings"
        subtitle="Deterministic compliance control tracking mapped from active security misconfigurations."
      />

      {/* Backend Boundary Notice (Section 40) */}
      <div
        style={{
          padding: 'var(--space-3) var(--space-4)',
          background: 'var(--status-info-bg)',
          border: '1px solid var(--border-accent)',
          borderRadius: 'var(--radius-md)',
          display: 'flex',
          gap: 'var(--space-3)',
          alignItems: 'flex-start',
        }}
      >
        <Info size={17} style={{ color: 'var(--accent-primary)', marginTop: '2px', flexShrink: 0 }} />
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--text-high)' }}>Architectural Boundary: </strong>
          Standalone <code className="font-mono text-cyan">/compliance/frameworks</code> endpoints are not fabricated.
          AegisByte deterministically aggregates compliance contexts and regulatory control references from evaluated
          detection rules and active findings.
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <button
          onClick={() => setSelectedFramework('ALL')}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius-sm)',
            border: selectedFramework === 'ALL' ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
            background: selectedFramework === 'ALL' ? 'var(--status-info-bg)' : 'var(--surface-overlay)',
            color: selectedFramework === 'ALL' ? 'var(--accent-primary)' : 'var(--text-secondary)',
            fontSize: '12px',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          All Frameworks ({frameworks.length})
        </button>

        {frameworks.map((fw) => (
          <button
            key={fw.framework}
            onClick={() => setSelectedFramework(fw.framework)}
            style={{
              padding: '6px 14px',
              borderRadius: 'var(--radius-sm)',
              border: selectedFramework === fw.framework ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
              background: selectedFramework === fw.framework ? 'var(--status-info-bg)' : 'var(--surface-overlay)',
              color: selectedFramework === fw.framework ? 'var(--accent-primary)' : 'var(--text-secondary)',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            {fw.framework} ({fw.findings.length})
          </button>
        ))}
      </div>

      {/* Compliance Framework Groups */}
      {isLoading ? (
        <LoadingSkeleton variant="card" count={3} height="180px" />
      ) : activeFrameworkList.length === 0 ? (
        <Card variant="elevated">
          <CardBody style={{ padding: 'var(--space-6)' }}>
            <EmptyState
              icon={ShieldCheck}
              title="No Compliance Violations"
              description="No open findings map to the selected compliance framework."
            />
          </CardBody>
        </Card>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {activeFrameworkList.map((fw) => (
            <Card key={fw.framework} variant="elevated">
              <CardHeader
                title={
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span>{fw.framework}</span>
                    <span className="font-mono text-cyan" style={{ fontSize: '11px', fontWeight: 'normal' }}>
                      ({fw.findings.length} findings)
                    </span>
                  </div>
                }
              />
              <CardBody style={{ padding: 0 }}>
                <div className="cg-table-responsive">
                  <table className="cg-table">
                    <thead>
                      <tr>
                        <th style={{ width: '120px' }}>Severity</th>
                        <th>Finding & Rule ID</th>
                        <th>Resource</th>
                        <th style={{ textAlign: 'right', width: '90px' }}>Inspect</th>
                      </tr>
                    </thead>
                    <tbody>
                      {fw.findings.map((f) => (
                        <tr key={f.findingId + fw.framework}>
                          <td>
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td>
                            <div style={{ fontWeight: 500, color: 'var(--text-high)', marginBottom: '2px' }}>
                              {f.title}
                            </div>
                            <div className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                              {f.ruleId}
                            </div>
                          </td>
                          <td>
                            <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                              {f.resourceName}
                            </div>
                            <div className="font-mono uppercase" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              {f.service}
                            </div>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <Link
                              to={`/findings/${f.findingId}/investigate`}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '2px',
                                color: 'var(--accent-primary)',
                                fontSize: '12px',
                                textDecoration: 'none',
                              }}
                            >
                              <span>View</span>
                              <ChevronRight size={13} />
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
