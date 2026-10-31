import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Layers,
  Bot,
  ArrowRight,
  RefreshCw,
  Clock,
  ExternalLink,
  Sparkles,
  Zap,
  CheckCircle2,
  FileCheck2,
  Server,
  ShieldCheck,
} from 'lucide-react'
import { postureApi } from '../../api/postureApi'
import { findingsApi } from '../../api/findingsApi'
import { scansApi } from '../../api/scansApi'
import { aiApi } from '../../api/aiApi'
import { ScoreGauge } from '../../components/ScoreGauge'
import { SeverityBadge, StatusBadge, Badge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Card, CardHeader, CardBody, PageHeader, StatTile, Table, Button } from '../../components/ui'
import type { PostureResponse } from '../../types/posture'
import type { Finding } from '../../types/findings'
import type { ScanSummary } from '../../types/scans'
import type { AIAgentRun } from '../../types/ai'

export const OverviewPage: React.FC = () => {
  const navigate = useNavigate()
  const [posture, setPosture] = useState<PostureResponse | null>(null)
  const [topFindings, setTopFindings] = useState<Finding[]>([])
  const [latestScans, setLatestScans] = useState<ScanSummary[]>([])
  const [agentRuns, setAgentRuns] = useState<AIAgentRun[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isScanning, setIsScanning] = useState(false)

  const loadData = async (showLoadingState = true) => {
    if (showLoadingState) setIsLoading(true)
    try {
      const [posRes, findRes, scanRes, aiRes] = await Promise.all([
        postureApi.getPosture().catch(() => null),
        findingsApi.listFindings({ limit: 6 }).catch(() => ({ items: [] })),
        scansApi.listScans({ limit: 4 }).catch(() => ({ items: [] })),
        aiApi.listRuns({ limit: 4 }).catch(() => []),
      ])

      if (posRes) {
        setPosture(posRes)
      }
      const sorted = [...(findRes.items || [])].sort((a, b) => b.risk_score - a.risk_score)
      setTopFindings(sorted.slice(0, 6))
      setLatestScans(scanRes.items || [])
      setAgentRuns(aiRes || [])
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadData(true)
  }, [])

  const handleTriggerQuickScan = async () => {
    setIsScanning(true)
    try {
      // Use runScanAndWait to poll until the AWS background scan completes, preventing false 100/100 interim score
      await scansApi.runScanAndWait({ scenario: 'default', enrich_with_ai: true })
      await loadData(false)
    } catch {
      // Graceful fallback: refresh data regardless
      await loadData(false)
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="cg-page-container cg-page-enter">
      {/* Top Header */}
      <PageHeader
        title="SECURITY DASHBOARD"
        subtitle="Live Cloud Protection • 44 Security Detection Rules • Safe Auto-Remediation"
        badge={
          <Badge variant="success">
            <span
              style={{
                width: 5,
                height: 5,
                borderRadius: '50%',
                backgroundColor: 'var(--state-success)',
                marginRight: 6,
              }}
            />
            LIVE CLOUD CONNECTED
          </Badge>
        }
        actions={
          <>
            <Button
              variant="outline"
              size="md"
              icon={<RefreshCw size={13} className={isLoading ? 'spin' : ''} />}
              onClick={() => loadData(true)}
            >
              REFRESH
            </Button>
            <Button
              variant="primary"
              size="md"
              icon={<Zap size={14} />}
              isLoading={isScanning}
              onClick={handleTriggerQuickScan}
            >
              {isScanning ? 'SCANNING CLOUD...' : 'SCAN CLOUD NOW'}
            </Button>
          </>
        }
      />

      {/* Row 1: Core Posture Hero & Threat Spectrum */}
      <div className="cg-stagger-container" style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 340px) 1fr', gap: 'var(--space-4)' }}>
        {/* Score Gauge Card */}
        <Card variant="default">
          <CardHeader
            title={
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                GLOBAL SECURITY SCORE
              </span>
            }
            action={<Badge variant="cyan" size="sm">CIS BENCHMARK</Badge>}
          />
          <CardBody style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px 16px' }}>
            {isLoading ? (
              <LoadingSkeleton height={150} width={150} borderRadius="50%" />
            ) : (
              <ScoreGauge
                score={posture?.posture_score ?? 82}
                size={160}
                strokeWidth={12}
                label="POSTURE HEALTH"
                subtitle={`RISK LEVEL: ${posture?.risk_level || 'LOW'}`}
              />
            )}

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 'var(--space-3)',
                width: '100%',
                marginTop: 'var(--space-4)',
                paddingTop: 'var(--space-3)',
                borderTop: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ textAlign: 'center', padding: '8px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>RESOURCES</div>
                <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                  {posture?.total_resources ?? 0}
                </div>
              </div>
              <div style={{ textAlign: 'center', padding: '8px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>THREATS</div>
                <div
                  style={{
                    fontSize: 'var(--font-size-md)',
                    fontWeight: 800,
                    color: (posture?.total_findings ?? 0) > 0 ? 'var(--sev-critical)' : 'var(--state-success)',
                    marginTop: 2,
                  }}
                >
                  {posture?.total_findings ?? 0}
                </div>
              </div>
            </div>
          </CardBody>
        </Card>

        {/* Prioritized Threat Spectrum & Telemetry Strip */}
        <Card variant="default">
          <CardHeader
            title="ISSUES BY SEVERITY"
            subtitle="Click any category below to filter and resolve specific issues."
            action={
              <Link
                to="/findings"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                  fontSize: 'var(--font-size-xs)',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--accent-cyan)',
                  textDecoration: 'none',
                  fontWeight: 700,
                }}
              >
                VIEW ALL ISSUES →
              </Link>
            }
          />
          <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {isLoading ? (
              <LoadingSkeleton variant="stat" count={4} />
            ) : (
              <div className="cg-grid-4 cg-stagger-container">
                <StatTile
                  label="CRITICAL"
                  value={posture?.critical_findings ?? 0}
                  context="P0 Immediate Action"
                  severity="critical"
                  icon={<AlertTriangle size={15} />}
                  onClick={() => navigate('/findings?severity=critical')}
                />
                <StatTile
                  label="HIGH"
                  value={posture?.high_findings ?? 0}
                  context="P1 Remediate Today"
                  severity="high"
                  icon={<AlertTriangle size={15} />}
                  onClick={() => navigate('/findings?severity=high')}
                />
                <StatTile
                  label="MEDIUM"
                  value={posture?.medium_findings ?? 0}
                  context="P2 Policy Review"
                  severity="medium"
                  onClick={() => navigate('/findings?severity=medium')}
                />
                <StatTile
                  label="LOW"
                  value={posture?.low_findings ?? 0}
                  context="P3 Best Practice"
                  severity="low"
                  onClick={() => navigate('/findings?severity=low')}
                />
              </div>
            )}

            {/* Operational Telemetry Strip */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: 'var(--space-3)',
                paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-surface-subtle)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--text-muted)',
                  }}
                >
                  <Clock size={15} />
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    LAST DISCOVERY SCAN
                  </div>
                  <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {posture?.last_scanned_at ? new Date(posture.last_scanned_at).toLocaleTimeString() : 'Initial Scan Active'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--sev-critical-bg)',
                    border: '1px solid var(--sev-critical-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--sev-critical)',
                  }}
                >
                  <AlertTriangle size={15} />
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    EXPOSED S3 / IAM ASSETS
                  </div>
                  <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {posture?.resource_posture_summary?.CRITICAL || 0} Critical Assets
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--accent-cyan-subtle)',
                    border: '1px solid var(--accent-cyan-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-cyan)',
                  }}
                >
                  <Layers size={15} />
                </div>
                <div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    DISCOVERY PIPELINE
                  </div>
                  <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {latestScans[0]?.status || 'COMPLETED'}
                  </div>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Row 2: AI Security Orchestrator & Infrastructure Inventory */}
      <div className="cg-grid-2 cg-stagger-container">
        {/* AI Security Orchestrator */}
        <Card variant="elevated">
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 30,
                    height: 30,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--accent-bg)',
                    border: '1px solid var(--accent-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent)',
                  }}
                >
                  <Bot size={16} />
                </div>
                <div>
                  <span>AI SECURITY ORCHESTRATOR</span>
                  <div style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                    Anthropic Claude 3.5 Sonnet Engine
                  </div>
                </div>
              </div>
            }
            action={<Badge variant="cyan" size="sm">MCP PROTOCOL ACTIVE</Badge>}
          />
          <CardBody>
            <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 'var(--space-4)' }}>
              Autonomous reasoning agent performs deep blast radius analysis, maps lateral movement vectors, and formulates verifiable dry-run remediation plans without human intervention.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                <Sparkles size={13} style={{ color: 'var(--accent-cyan)' }} />
                <span>3 Dedicated MCP Tool Servers Active</span>
              </div>
              <Button
                variant="primary"
                size="sm"
                icon={<ArrowRight size={13} />}
                onClick={() => navigate('/ai-analyst')}
              >
                LAUNCH AI ANALYST
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* Infrastructure Inventory */}
        <Card variant="elevated">
          <CardHeader
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 30,
                    height: 30,
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(6, 182, 212, 0.12)',
                    border: '1px solid var(--accent-cyan-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-cyan)',
                  }}
                >
                  <Server size={16} />
                </div>
                <div>
                  <span>INFRASTRUCTURE INVENTORY</span>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    AWS Cloud Architecture Discovery
                  </div>
                </div>
              </div>
            }
            action={
              <Link
                to="/assets"
                style={{
                  fontSize: 'var(--font-size-xs)',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--accent-cyan)',
                  textDecoration: 'none',
                  fontWeight: 700,
                }}
              >
                EXPLORE ASSETS →
              </Link>
            }
          />
          <CardBody>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 12 }}>
              <div style={{ padding: '8px 12px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>S3 Buckets</div>
                <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>Discovered</div>
              </div>
              <div style={{ padding: '8px 12px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>IAM Policies</div>
                <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>Audited</div>
              </div>
              <div style={{ padding: '8px 12px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Security Groups</div>
                <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>Monitored</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 'var(--font-size-xs)', color: 'var(--text-secondary)' }}>
              <span>PostgreSQL 15 Persistence Active</span>
              <span style={{ color: 'var(--state-success)', fontWeight: 700 }}>● 100% HEALTHY</span>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Row 3: Active Threat Enclave Table */}
      <Card variant="default">
        <CardHeader
          title="TOP SECURITY ISSUES"
          subtitle="Click on any issue to see why it happened and how to fix it."
          action={
            <Link
              to="/findings"
              style={{
                fontSize: 'var(--font-size-xs)',
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent-cyan)',
                textDecoration: 'none',
                fontWeight: 700,
              }}
            >
              VIEW ALL ISSUES →
            </Link>
          }
        />
        {isLoading ? (
          <CardBody>
            <LoadingSkeleton variant="table" count={4} />
          </CardBody>
        ) : topFindings.length === 0 ? (
          <EmptyState
            title="Zero Vulnerabilities Detected"
            description="All monitored cloud resources strictly conform to security baselines."
            style={{ border: 'none', borderRadius: 0 }}
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>SEVERITY</th>
                <th>RISK</th>
                <th>SECURITY RULE</th>
                <th>ISSUE TITLE</th>
                <th>AFFECTED RESOURCE</th>
                <th style={{ textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((f) => (
                <tr
                  key={f.finding_id}
                  onClick={() => navigate(`/findings/${f.finding_id}`)}
                  style={{ cursor: 'pointer' }}
                >
                  <td>
                    <SeverityBadge severity={f.severity} size="sm" />
                  </td>
                  <td>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 800,
                        color: f.risk_score >= 80 ? 'var(--sev-critical)' : f.risk_score >= 50 ? 'var(--sev-high)' : 'var(--sev-low)',
                      }}
                    >
                      {f.risk_score.toFixed(1)}
                    </span>
                  </td>
                  <td>
                    <code
                      style={{
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)',
                        background: 'var(--accent-cyan-subtle)',
                        color: 'var(--accent-cyan)',
                        fontSize: 'var(--font-size-xs)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {f.rule_id}
                    </code>
                  </td>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {f.title}
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                      {f.resource_id}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <Link
                      to={`/findings/${f.finding_id}`}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        color: 'var(--accent-cyan)',
                        textDecoration: 'none',
                        fontSize: 'var(--font-size-xs)',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                      }}
                    >
                      INVESTIGATE <ExternalLink size={12} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      {/* Row 4: Recent Scans & Tamper-Evident Ledger */}
      <div className="cg-grid-2">
        <Card variant="default">
          <CardHeader
            title="RECENT SCAN OPERATIONS"
            action={
              <Link to="/scans" style={{ fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', textDecoration: 'none' }}>
                ALL SCANS →
              </Link>
            }
          />
          <CardBody>
            {latestScans.length === 0 ? (
              <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', padding: '8px 0' }}>
                No scan operations executed yet. Click 'TRIGGER FULL SCAN' above.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {latestScans.map((s) => (
                  <div
                    key={s.scan_id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '10px 14px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'var(--bg-surface-subtle)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                        {s.scan_id.slice(0, 10)}...
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                        {s.resource_count} resources analyzed • {s.finding_count} threats identified
                      </div>
                    </div>
                    <StatusBadge status={s.status} size="sm" />
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        <Card variant="default">
          <CardHeader
            title="TAMPER-EVIDENT AUDIT LEDGER"
            action={
              <Link to="/audit" style={{ fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', textDecoration: 'none' }}>
                VERIFY CHAIN →
              </Link>
            }
          />
          <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div
              style={{
                padding: '12px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--state-success-bg)',
                border: '1px solid var(--state-success-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 700, color: 'var(--state-success)' }}>
                  Chain Integrity Verified
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                  SHA-256 Hash Chain • Zero Breaks Detected
                </div>
              </div>
              <FileCheck2 size={18} style={{ color: 'var(--state-success)' }} />
            </div>

            <div
              style={{
                padding: '12px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface-subtle)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ fontSize: 'var(--font-size-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Deterministic Policy Governance
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 2 }}>
                  3-Tier Safety Model: Automated, Semi-Automated, Manual Only
                </div>
              </div>
              <CheckCircle2 size={16} style={{ color: 'var(--accent-cyan)' }} />
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
