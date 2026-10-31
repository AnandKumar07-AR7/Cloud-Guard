import React from 'react'
import { FileText, Info } from 'lucide-react'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody } from '../../components/ui/Card'

export const ReportsPage: React.FC = () => {
  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Executive & Audit Reports"
        subtitle="Compliance and executive vulnerability report generation."
      />

      {/* Backend Boundary Notice (Section 41) */}
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
          The AegisByte backend does not expose an asynchronous report rendering or export endpoint.
          Per Section 41 zero-compromise rules, mock PDF/CSV generation is strictly prohibited. Security posture,
          findings, and compliance registries are accessible live via their respective operational views.
        </div>
      </div>

      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-8)' }}>
          <EmptyState
            icon={FileText}
            title="Report Generation Not Exposed"
            description="A dedicated reports API is not present in the frozen backend. Live telemetry remains accessible across Findings, Posture, and Compliance views."
          />
        </CardBody>
      </Card>
    </div>
  )
}
