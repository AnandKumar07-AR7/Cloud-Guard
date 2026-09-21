import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Play, Wrench, Search } from 'lucide-react'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const ExecutionsPage: React.FC = () => {
  const [filterPlanId, setFilterPlanId] = useState('')

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="Remediation Executions"
        subtitle="Historical record of executed cloud mutations against AWS and Cloud infrastructure."
        actions={
          <Link to="/remediation" style={{ textDecoration: 'none' }}>
            <Button variant="primary" size="sm">
              <Wrench size={14} />
              Remediation Center
            </Button>
          </Link>
        }
      />

      {/* Execution Tracker */}
      <Card variant="elevated">
        <CardBody style={{ padding: 'var(--space-4)' }}>
          <div style={{ position: 'relative', maxWidth: '340px', marginBottom: 'var(--space-4)' }}>
            <Search
              size={14}
              style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
            />
            <input
              type="text"
              placeholder="Search execution by Plan ID or Resource..."
              value={filterPlanId}
              onChange={(e) => setFilterPlanId(e.target.value)}
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

          <EmptyState
            icon={Play}
            title="Execution Audit Log"
            description="Executed remediation plans will record their provider dispatch and verification status here."
          />
        </CardBody>
      </Card>
    </div>
  )
}
