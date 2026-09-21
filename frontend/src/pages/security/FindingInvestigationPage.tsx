import React, { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert,
  ArrowLeft,
  Cpu,
  Wrench,
  Sparkles,
  Database,
  ShieldCheck,
} from 'lucide-react'
import { findingsApi } from '../../api/findingsApi'
import { aiApi } from '../../api/aiApi'
import { SeverityBadge, StatusBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

export const FindingInvestigationPage: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: invData, isLoading, error } = useQuery({
    queryKey: ['findings', 'investigation', id],
    queryFn: () => findingsApi.getInvestigation(id!),
    enabled: Boolean(id),
  })

  const { data: historyData } = useQuery({
    queryKey: ['findings', 'history', invData?.finding.canonical_id],
    queryFn: () => findingsApi.getFindingHistory(invData!.finding.canonical_id),
    enabled: Boolean(invData?.finding.canonical_id),
  })

  // Mutation to trigger AI Security Analyst
  const aiMutation = useMutation({
    mutationFn: (findingId: string) => aiApi.analyze(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings', 'investigation', id] })
    },
  })

  if (isLoading) {
    return (
      <div className="cg-page-container">
        <LoadingSkeleton variant="card" count={1} height="80px" />
        <div className="cg-grid-3">
          <LoadingSkeleton variant="card" count={1} height="360px" />
          <LoadingSkeleton variant="card" count={1} height="360px" />
          <LoadingSkeleton variant="card" count={1} height="360px" />
        </div>
      </div>
    )
  }

  if (error || !invData) {
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
          description={`Finding ID '${id}' could not be loaded: ${(error as Error)?.message || 'Record does not exist'}`}
        />
      </div>
    )
  }

  const { finding, rule, resource, evidence } = invData
  const aiAnalysis = finding.ai_analysis || invData.ai_analysis

  return (
    <div className="cg-page-container">
      {/* Top Breadcrumb & Actions Bar */}
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

        <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
          <Button
            variant="outline"
            size="sm"
            onClick={() => aiMutation.mutate(finding.finding_id)}
            disabled={aiMutation.isPending}
          >
            <Cpu size={14} className={aiMutation.isPending ? 'spin' : ''} />
            {aiMutation.isPending ? 'Executing AI Analyst...' : 'Run AI Security Analysis'}
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate(`/remediation?finding_id=${finding.finding_id}`)}
          >
            <Wrench size={14} />
            Create Remediation Plan
          </Button>
        </div>
      </div>

      {/* Header Banner */}
      <Card variant="elevated">
        <CardBody
          style={{
            padding: 'var(--space-4) var(--space-5)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            gap: 'var(--space-4)',
          }}
        >
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-cyan" style={{ fontSize: '13px', fontWeight: 600 }}>
                {finding.rule_id}
              </span>
              <span style={{ color: 'var(--text-muted)' }}>•</span>
              <span className="font-mono uppercase" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                {finding.service}
              </span>
              <StatusBadge status={finding.status} />
            </div>

            <h1 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--text-high)', margin: '0 0 var(--space-2) 0' }}>
              {finding.title}
            </h1>

            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              {finding.description}
            </p>
          </div>

          {/* Risk & Posture Scorecard */}
          <div
            style={{
              display: 'flex',
              gap: 'var(--space-4)',
              background: 'var(--surface-overlay)',
              padding: 'var(--space-3) var(--space-4)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              alignItems: 'center',
            }}
          >
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Risk Score
              </div>
              <div
                className="font-mono"
                style={{
                  fontSize: '22px',
                  fontWeight: 700,
                  color:
                    finding.risk_score >= 80
                      ? 'var(--text-critical)'
                      : finding.risk_score >= 60
                      ? 'var(--text-high)'
                      : 'var(--accent-primary)',
                }}
              >
                {finding.risk_score !== undefined ? finding.risk_score.toFixed(1) : 'N/A'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Out of 100</div>
            </div>

            <div style={{ width: '1px', height: '36px', background: 'var(--border-subtle)' }} />

            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Exposure
              </div>
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  marginTop: '4px',
                  color: finding.is_internet_exposed ? 'var(--text-critical)' : 'var(--text-success)',
                }}
              >
                {finding.is_internet_exposed ? 'INTERNET EXPOSED' : 'INTERNAL ONLY'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {finding.category || 'Security Control'}
              </div>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Flagship Tri-Panel Investigation Layout */}
      <div className="cg-grid-3" style={{ alignItems: 'stretch' }}>
        {/* PANEL 1: OBSERVED FACTS (Deterministic Telemetry) */}
        <Card variant="elevated" style={{ display: 'flex', flexDirection: 'column' }}>
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Database size={15} style={{ color: 'var(--accent-primary)' }} />
                <span>Observed Facts</span>
              </div>
            }
            action={
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--status-info-bg)',
                  border: '1px solid var(--border-accent)',
                  color: 'var(--accent-primary)',
                  textTransform: 'uppercase',
                }}
              >
                Deterministic Telemetry
              </span>
            }
          />
          <CardBody style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {/* Resource Context */}
            <div>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                Target Resource Context
              </div>
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 'var(--space-2)',
                }}
              >
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Name / ID: </span>
                  <span className="font-mono text-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                    {finding.resource_name || finding.resource_id}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Service & Type: </span>
                  <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                    {finding.service.toUpperCase()} • {finding.resource_type}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Region & Account: </span>
                  <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                    {finding.region || 'global'} • {finding.account_id}
                  </span>
                </div>
                {finding.resource_arn && (
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ARN: </span>
                    <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {finding.resource_arn}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Evidence Details */}
            <div>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                Configuration Evidence
              </div>
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ fontSize: '12px', color: 'var(--text-high)', marginBottom: 'var(--space-2)', lineHeight: 1.4 }}>
                  {evidence?.summary || 'No summary evidence recorded.'}
                </div>

                {evidence?.field_path && (
                  <div style={{ marginBottom: '4px', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Field Evaluated: </span>
                    <code className="font-mono text-cyan">{evidence.field_path}</code>
                  </div>
                )}

                {evidence?.observed_value !== undefined && (
                  <div style={{ marginBottom: '4px', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Observed Value: </span>
                    <code className="font-mono" style={{ color: 'var(--text-critical)' }}>
                      {JSON.stringify(evidence.observed_value)}
                    </code>
                  </div>
                )}

                {evidence?.expected_value !== undefined && (
                  <div style={{ fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Expected Value: </span>
                    <code className="font-mono" style={{ color: 'var(--text-success)' }}>
                      {JSON.stringify(evidence.expected_value)}
                    </code>
                  </div>
                )}
              </div>
            </div>

            {/* Finding History Occurrences */}
            {historyData && historyData.occurrences > 1 && (
              <div>
                <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                  Historical Recurrence ({historyData.occurrences} Scans)
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                  {historyData.history.slice(0, 3).map((h, i) => (
                    <div
                      key={h.finding_id + i}
                      style={{
                        padding: '6px 10px',
                        background: 'var(--surface-overlay)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '11px',
                      }}
                    >
                      <span className="font-mono">Scan {h.scan_id.slice(0, 8)}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{h.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardBody>
        </Card>

        {/* PANEL 2: AI INFERENCES (Advisory Intelligence) */}
        <Card variant="elevated" style={{ display: 'flex', flexDirection: 'column' }}>
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Cpu size={15} style={{ color: 'var(--accent-primary)' }} />
                <span>AI Inferences</span>
              </div>
            }
            action={
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  color: 'var(--accent-primary)',
                  textTransform: 'uppercase',
                }}
              >
                Advisory Intelligence
              </span>
            }
          />
          <CardBody style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {/* AI Banner */}
            <div
              style={{
                padding: '8px 12px',
                background: 'var(--status-info-bg)',
                border: '1px solid var(--border-accent)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                lineHeight: 1.4,
              }}
            >
              <strong style={{ color: 'var(--accent-primary)' }}>Advisory Boundary:</strong> AI analysis provides contextual risk interpretation and blast radius evaluation. It is NOT authoritative telemetry.
            </div>

            {aiAnalysis ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {/* Executive Summary */}
                <div>
                  <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-1)' }}>
                    Executive Summary
                  </div>
                  <div
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--surface-overlay)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      color: 'var(--text-high)',
                      lineHeight: 1.5,
                    }}
                  >
                    {aiAnalysis.executive_summary || 'Analysis completed.'}
                  </div>
                </div>

                {/* Technical Risk Interpretation */}
                {aiAnalysis.technical_analysis && (
                  <div>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-1)' }}>
                      Attack Surface & Technical Risk
                    </div>
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
                      {aiAnalysis.technical_analysis}
                    </div>
                  </div>
                )}

                {/* Business Impact */}
                {aiAnalysis.business_impact && (
                  <div>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-1)' }}>
                      Business Impact
                    </div>
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
                      {aiAnalysis.business_impact}
                    </div>
                  </div>
                )}

                {/* Confidence & Source */}
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                    borderTop: '1px solid var(--border-subtle)',
                    paddingTop: 'var(--space-2)',
                  }}
                >
                  <span>Confidence: <strong style={{ color: 'var(--text-high)' }}>{aiAnalysis.confidence || 'HIGH'}</strong></span>
                  <span className="font-mono">Engine: {aiAnalysis.ai_source || 'Gemini Pro SecOps'}</span>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '30px 10px', color: 'var(--text-muted)' }}>
                <Sparkles size={28} style={{ marginBottom: 'var(--space-2)', opacity: 0.4 }} />
                <div style={{ fontSize: '13px', color: 'var(--text-high)', fontWeight: 500 }}>
                  No AI Analysis Cached
                </div>
                <p style={{ fontSize: '12px', margin: '4px 0 var(--space-3) 0' }}>
                  Run the AI Security Analyst to generate contextual risk, attack paths, and blast radius.
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => aiMutation.mutate(finding.finding_id)}
                  disabled={aiMutation.isPending}
                >
                  {aiMutation.isPending ? 'Analyzing...' : 'Generate Analysis'}
                </Button>
              </div>
            )}
          </CardBody>
        </Card>

        {/* PANEL 3: RECOMMENDATIONS & REMEDIATION HANDOFF */}
        <Card variant="elevated" style={{ display: 'flex', flexDirection: 'column' }}>
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Wrench size={15} style={{ color: 'var(--text-success)' }} />
                <span>Remediation Guidance</span>
              </div>
            }
            action={
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--status-success-bg)',
                  border: '1px solid var(--border-success)',
                  color: 'var(--text-success)',
                  textTransform: 'uppercase',
                }}
              >
                Actionable Control
              </span>
            }
          />
          <CardBody style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {/* Remediation Safety Class */}
            <div>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                Automation Safety Classification
              </div>
              <div
                style={{
                  padding: 'var(--space-3)',
                  background: 'var(--surface-overlay)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                }}
              >
                <ShieldCheck size={18} style={{ color: 'var(--text-success)' }} />
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)' }}>
                    {finding.remediation_safety || 'REQUIRES_APPROVAL'}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    State machine enforces human sign-off before cloud mutation.
                  </div>
                </div>
              </div>
            </div>

            {/* Recommended Action */}
            <div>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                Recommended Remediation Procedure
              </div>
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
                {finding.remediation_guidance || rule?.remediation || 'Apply targeted cloud configuration fix according to CIS Benchmark standards.'}
              </div>
            </div>

            {/* Compliance Frameworks */}
            {finding.compliance_mappings && finding.compliance_mappings.length > 0 && (
              <div>
                <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-2)' }}>
                  Regulatory Compliance Mappings
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
                  {finding.compliance_mappings.map((comp) => (
                    <span
                      key={comp}
                      className="font-mono"
                      style={{
                        padding: '2px 6px',
                        background: 'var(--surface-overlay)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '10px',
                        color: 'var(--accent-primary)',
                      }}
                    >
                      {comp}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation Center Callout Button */}
            <div style={{ marginTop: 'auto', paddingTop: 'var(--space-3)', borderTop: '1px solid var(--border-subtle)' }}>
              <Button
                variant="primary"
                style={{ width: '100%' }}
                onClick={() => navigate(`/remediation?finding_id=${finding.finding_id}`)}
              >
                <Wrench size={15} />
                Launch Remediation Workflow
              </Button>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
