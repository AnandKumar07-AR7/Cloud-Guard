import React, { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Server,
  Wrench,
  Play,
  RotateCw,
  ChevronDown,
  ShieldCheck,
  AlertTriangle,
  XCircle,
  Clock,
  Activity,
} from 'lucide-react'
import { mcpApi } from '../../api/mcpApi'
import { OpClassBadge } from '../../components/Badge'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { Drawer } from '../../components/Drawer'
import { Modal } from '../../components/Modal'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import type { MCPServer, MCPTool } from '../../types/mcp'

/* ────────────────────────────────────────────────────────────
   SCOPE POPOVER BUTTON
   Click → dropdown listing each permission scope as a tag
──────────────────────────────────────────────────────────── */
const ScopeButton: React.FC<{ scope: string[] }> = ({ scope }) => {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Click to view permission scope"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 5,
          padding: '5px 11px',
          borderRadius: 8,
          border: `1px solid ${open ? 'rgba(99,102,241,0.55)' : 'rgba(99,102,241,0.3)'}`,
          background: open ? 'rgba(99,102,241,0.2)' : 'rgba(99,102,241,0.08)',
          color: '#818cf8',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          fontWeight: 700,
          cursor: 'pointer',
          letterSpacing: '0.04em',
          transition: 'all 0.15s ease',
          whiteSpace: 'nowrap',
          boxShadow: open ? '0 0 12px rgba(99,102,241,0.2)' : 'none',
        }}
        onMouseEnter={(e) => {
          if (!open) {
            e.currentTarget.style.background = 'rgba(99,102,241,0.16)'
            e.currentTarget.style.borderColor = 'rgba(99,102,241,0.5)'
          }
        }}
        onMouseLeave={(e) => {
          if (!open) {
            e.currentTarget.style.background = 'rgba(99,102,241,0.08)'
            e.currentTarget.style.borderColor = 'rgba(99,102,241,0.3)'
          }
        }}
      >
        <ShieldCheck size={12} />
        SCOPE &nbsp;·&nbsp; {scope.length}
        <ChevronDown size={11} style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }} />
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            bottom: 'calc(100% + 8px)',
            left: 0,
            zIndex: 300,
            minWidth: 230,
            background: 'rgba(11, 16, 30, 0.98)',
            border: '1px solid rgba(99,102,241,0.3)',
            borderRadius: 12,
            boxShadow: '0 16px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(99,102,241,0.08)',
            padding: '12px 12px',
            animation: 'cg-pop-in 0.16s cubic-bezier(0.16,1,0.3,1) both',
          }}
        >
          <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase', marginBottom: 8 }}>
            Permission Scope ({scope.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {scope.map((s, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '5px 9px',
                  borderRadius: 7,
                  background: 'rgba(99,102,241,0.1)',
                  border: '1px solid rgba(99,102,241,0.18)',
                }}
              >
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#818cf8', flexShrink: 0 }} />
                <code style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#a5b4fc', wordBreak: 'break-all' }}>
                  {s}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ────────────────────────────────────────────────────────────
   HEALTH POPOVER BUTTON
   Color-coded pill (green/yellow/red).
   Click → dropdown with health metrics.
──────────────────────────────────────────────────────────── */
const HealthButton: React.FC<{ srv: MCPServer }> = ({ srv }) => {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const status = (srv.status || 'unknown').toLowerCase()

  const getTheme = () => {
    if (status === 'healthy') return {
      bg: 'rgba(16,185,129,0.1)', bgHover: 'rgba(16,185,129,0.2)', bgOpen: 'rgba(16,185,129,0.22)',
      border: 'rgba(16,185,129,0.35)', borderOpen: 'rgba(16,185,129,0.55)',
      color: '#34d399', dot: '#10b981', glow: 'rgba(16,185,129,0.2)',
      icon: <ShieldCheck size={12} />, label: 'HEALTHY', pulse: true,
    }
    if (status === 'degraded') return {
      bg: 'rgba(245,158,11,0.1)', bgHover: 'rgba(245,158,11,0.18)', bgOpen: 'rgba(245,158,11,0.2)',
      border: 'rgba(245,158,11,0.35)', borderOpen: 'rgba(245,158,11,0.55)',
      color: '#fbbf24', dot: '#f59e0b', glow: 'rgba(245,158,11,0.2)',
      icon: <AlertTriangle size={12} />, label: 'DEGRADED', pulse: false,
    }
    if (['unhealthy', 'error', 'failed', 'down'].includes(status)) return {
      bg: 'rgba(244,63,94,0.1)', bgHover: 'rgba(244,63,94,0.18)', bgOpen: 'rgba(244,63,94,0.22)',
      border: 'rgba(244,63,94,0.35)', borderOpen: 'rgba(244,63,94,0.55)',
      color: '#fb7185', dot: '#f43f5e', glow: 'rgba(244,63,94,0.2)',
      icon: <XCircle size={12} />, label: 'UNHEALTHY', pulse: false,
    }
    return {
      bg: 'rgba(100,116,139,0.1)', bgHover: 'rgba(100,116,139,0.18)', bgOpen: 'rgba(100,116,139,0.2)',
      border: 'rgba(100,116,139,0.25)', borderOpen: 'rgba(100,116,139,0.4)',
      color: '#94a3b8', dot: '#64748b', glow: 'none',
      icon: <Activity size={12} />, label: (srv.status || 'UNKNOWN').toUpperCase(), pulse: false,
    }
  }

  const t = getTheme()
  const errorRate = srv.request_count > 0
    ? ((srv.error_count / srv.request_count) * 100).toFixed(1)
    : '0.0'

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Click to view health details"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '5px 11px',
          borderRadius: 8,
          border: `1px solid ${open ? t.borderOpen : t.border}`,
          background: open ? t.bgOpen : t.bg,
          color: t.color,
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          fontWeight: 700,
          cursor: 'pointer',
          letterSpacing: '0.04em',
          transition: 'all 0.15s ease',
          whiteSpace: 'nowrap',
          boxShadow: open ? `0 0 14px ${t.glow}` : 'none',
        }}
        onMouseEnter={(e) => {
          if (!open) {
            e.currentTarget.style.background = t.bgHover
            e.currentTarget.style.borderColor = t.borderOpen
            e.currentTarget.style.boxShadow = `0 0 14px ${t.glow}`
          }
        }}
        onMouseLeave={(e) => {
          if (!open) {
            e.currentTarget.style.background = t.bg
            e.currentTarget.style.borderColor = t.border
            e.currentTarget.style.boxShadow = 'none'
          }
        }}
      >
        {/* Animated status dot */}
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: t.dot,
            flexShrink: 0,
            animation: t.pulse ? 'pulse-dot 2s ease-in-out infinite' : 'none',
          }}
        />
        {t.icon}
        {t.label}
        <ChevronDown size={11} style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }} />
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            bottom: 'calc(100% + 8px)',
            right: 0,
            zIndex: 300,
            minWidth: 248,
            background: 'rgba(11, 16, 30, 0.98)',
            border: `1px solid ${t.borderOpen}`,
            borderRadius: 12,
            boxShadow: `0 16px 40px rgba(0,0,0,0.6), 0 0 20px ${t.glow}`,
            padding: 14,
            animation: 'cg-pop-in 0.16s cubic-bezier(0.16,1,0.3,1) both',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, paddingBottom: 10, borderBottom: `1px solid ${t.border}` }}>
            <div
              style={{
                width: 34, height: 34, borderRadius: 9,
                background: t.bg, border: `1px solid ${t.border}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: t.color, flexShrink: 0,
              }}
            >
              {t.icon}
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 800, color: t.color, lineHeight: 1.1 }}>{t.label}</div>
              <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 2 }}>
                {srv.server_name}
              </div>
            </div>
          </div>

          {/* Metric rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              { icon: <Activity size={11} />, label: 'Total Requests', value: srv.request_count.toLocaleString(), color: '#38bdf8' },
              { icon: <XCircle size={11} />, label: 'Errors', value: `${srv.error_count} (${errorRate}%)`, color: srv.error_count > 0 ? '#fb7185' : '#34d399' },
              {
                icon: <Clock size={11} />, label: 'Avg Latency',
                value: srv.avg_latency_ms !== undefined ? `${srv.avg_latency_ms.toFixed(1)} ms` : '—',
                color: srv.avg_latency_ms < 100 ? '#34d399' : srv.avg_latency_ms < 300 ? '#fbbf24' : '#fb7185',
              },
              ...(srv.last_health_check ? [{ icon: <ShieldCheck size={11} />, label: 'Last Check', value: new Date(srv.last_health_check).toLocaleTimeString(), color: 'var(--text-secondary)' }] : []),
            ].map((row, i) => (
              <div
                key={i}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  gap: 8, padding: '5px 8px', borderRadius: 7,
                  background: 'rgba(255,255,255,0.025)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)' }}>
                  {row.icon}
                  <span style={{ fontSize: 11 }}>{row.label}</span>
                </div>
                <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 700, color: row.color }}>
                  {row.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* Inject popover animation once */
const PopoverStyles = () => (
  <style>{`
    @keyframes cg-pop-in {
      from { opacity: 0; transform: translateY(6px) scale(0.95); }
      to   { opacity: 1; transform: translateY(0)   scale(1);    }
    }
  `}</style>
)

/* ────────────────────────────────────────────────────────────
   MAIN PAGE
──────────────────────────────────────────────────────────── */
export const MCPServersPage: React.FC = () => {
  const queryClient = useQueryClient()
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null)
  const [invokingTool, setInvokingTool] = useState<MCPTool | null>(null)
  const [invokeArgsJson, setInvokeArgsJson] = useState<string>('{}')
  const [invokeResult, setInvokeResult] = useState<unknown | null>(null)
  const [invokeError, setInvokeError] = useState<string | null>(null)

  const { data: servers, isLoading: loadingServers, refetch: refetchServers, isFetching } = useQuery({
    queryKey: ['mcp', 'servers'],
    queryFn: () => mcpApi.listServers(),
  })

  const { data: tools, isLoading: loadingTools } = useQuery({
    queryKey: ['mcp', 'tools'],
    queryFn: () => mcpApi.listTools(),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ serverId, enabled }: { serverId: string; enabled: boolean }) =>
      mcpApi.toggleServer(serverId, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mcp', 'servers'] })
      queryClient.invalidateQueries({ queryKey: ['mcp', 'tools'] })
    },
  })

  const invokeMutation = useMutation({
    mutationFn: ({ serverId, toolName, args }: { serverId: string; toolName: string; args: Record<string, unknown> }) =>
      mcpApi.invokeTool(serverId, toolName, args),
    onSuccess: (res) => {
      setInvokeResult(res.data)
      setInvokeError(null)
      queryClient.invalidateQueries({ queryKey: ['mcp', 'audit'] })
    },
    onError: (err: Error) => {
      setInvokeError(err.message)
      setInvokeResult(null)
    },
  })

  return (
    <div className="cg-page-container">
      <PopoverStyles />

      {/* Header */}
      <PageHeader
        title="MCP Control Center"
        subtitle="Governed MCP servers, schema-enforced tool catalogs, live latency metrics, and tamper-evident audit traces."
        badge={
          <span style={{ fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: 'var(--status-info-bg)', border: '1px solid var(--border-accent)', color: 'var(--accent-primary)', textTransform: 'uppercase' }}>
            Model Context Protocol Gateway
          </span>
        }
        actions={
          <Button variant="outline" size="sm" onClick={() => refetchServers()} disabled={isFetching}>
            <RotateCw size={14} className={isFetching ? 'spin' : ''} />
            Refresh
          </Button>
        }
      />

      {/* ── SECTION 1: MCP SERVER CARDS ── */}
      <div>
        <h2 style={{ fontSize: '13px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginBottom: 'var(--space-3)' }}>
          Registered MCP Servers ({servers?.length || 0})
        </h2>

        {loadingServers ? (
          <LoadingSkeleton variant="card" count={3} height="160px" />
        ) : !servers || servers.length === 0 ? (
          <Card variant="elevated">
            <CardBody style={{ padding: 'var(--space-6)' }}>
              <EmptyState icon={Server} title="No MCP Servers Registered" description="The Phase 10 MCP Control Plane has not detected any running MCP server instances." />
            </CardBody>
          </Card>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 'var(--space-4)' }}>
            {servers.map((srv) => (
              <Card key={srv.server_id} variant="elevated">
                <CardBody style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>

                  {/* Server header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                      <div style={{ width: '36px', height: '36px', borderRadius: 'var(--radius-sm)', background: 'var(--status-info-bg)', border: '1px solid var(--border-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-primary)' }}>
                        <Server size={18} />
                      </div>
                      <div>
                        <div className="font-mono text-cyan" style={{ fontSize: '14px', fontWeight: 600 }}>{srv.server_name}</div>
                        <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>v{srv.version} • {srv.server_type}</div>
                      </div>
                    </div>
                    {/* Enable/Disable toggle */}
                    <button
                      onClick={() => toggleMutation.mutate({ serverId: srv.server_id, enabled: !srv.enabled })}
                      disabled={toggleMutation.isPending}
                      style={{ padding: '3px 8px', borderRadius: 'var(--radius-sm)', fontSize: '11px', fontWeight: 600, background: srv.enabled ? 'var(--status-success-bg)' : 'var(--status-critical-bg)', border: srv.enabled ? '1px solid var(--border-success)' : '1px solid var(--border-critical)', color: srv.enabled ? 'var(--text-success)' : 'var(--text-critical)', cursor: 'pointer' }}
                    >
                      {srv.enabled ? 'ENABLED' : 'DISABLED'}
                    </button>
                  </div>

                  {/* Metrics strip */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-overlay)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tools</div>
                      <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)' }}>{srv.tool_count}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Requests</div>
                      <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-high)' }}>{srv.request_count}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Latency</div>
                      <div className="font-mono" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--accent-primary)' }}>
                        {srv.avg_latency_ms !== undefined ? `${srv.avg_latency_ms.toFixed(1)}ms` : '—'}
                      </div>
                    </div>
                  </div>

                  {/* ── Interactive Scope + Health buttons ── */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, paddingTop: 2 }}>
                    <ScopeButton
                      scope={
                        Array.isArray(srv.permission_scope)
                          ? srv.permission_scope
                          : [String(srv.permission_scope)]
                      }
                    />
                    <HealthButton srv={srv} />
                  </div>

                </CardBody>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* ── SECTION 2: MCP TOOL INSPECTOR ── */}
      <Card variant="elevated">
        <CardHeader
          title="MCP Tool Catalog & Schema Inspector"
          action={
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Available Tools: <strong className="font-mono text-cyan">{tools?.length || 0}</strong>
            </span>
          }
        />

        <CardBody style={{ padding: 0 }}>
          {loadingTools ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <LoadingSkeleton variant="table" count={6} height="48px" />
            </div>
          ) : !tools || tools.length === 0 ? (
            <div style={{ padding: 'var(--space-6)' }}>
              <EmptyState icon={Wrench} title="No Tools Cataloged" description="No MCP tools registered across active MCP servers." />
            </div>
          ) : (
            <div className="cg-table-responsive">
              <table className="cg-table">
                <thead>
                  <tr>
                    <th style={{ width: '130px' }}>Operation Class</th>
                    <th style={{ width: '220px' }}>Tool Name & Server</th>
                    <th>Description</th>
                    <th style={{ width: '160px' }}>Permission Required</th>
                    <th style={{ textAlign: 'right', width: '140px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tools.map((tool) => (
                    <tr key={tool.tool_id}>
                      <td><OpClassBadge opClass={tool.operation_class} /></td>
                      <td>
                        <div className="font-mono text-cyan" style={{ fontSize: '13px', fontWeight: 600 }}>{tool.tool_name}</div>
                        <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{tool.server_id}</div>
                      </td>
                      <td>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{tool.description}</div>
                      </td>
                      <td>
                        <code className="font-mono text-cyan" style={{ fontSize: '11px' }}>{tool.required_permission}</code>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                          <Button variant="outline" size="sm" onClick={() => setSelectedTool(tool)}>Schema</Button>
                          <Button variant="primary" size="sm" onClick={() => { setInvokingTool(tool); setInvokeArgsJson('{}'); setInvokeResult(null); setInvokeError(null) }}>
                            <Play size={11} /> Test
                          </Button>
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

      {/* Tool Schema Drawer */}
      <Drawer
        isOpen={Boolean(selectedTool)}
        onClose={() => setSelectedTool(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span>Tool Specification:</span>
            <span className="font-mono text-cyan" style={{ fontSize: '13px' }}>{selectedTool?.tool_name}</span>
          </div>
        }
        width="660px"
      >
        {selectedTool && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                <OpClassBadge opClass={selectedTool.operation_class} />
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Server: {selectedTool.server_id}</span>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0 }}>{selectedTool.description}</p>
            </div>

            <div>
              <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>Input JSON Schema</h3>
              <pre className="font-mono" style={{ padding: 'var(--space-3)', background: 'var(--surface-overlay)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', fontSize: '11px', color: 'var(--accent-primary)', overflowX: 'auto', margin: 0 }}>
                {JSON.stringify(selectedTool.input_schema, null, 2)}
              </pre>
            </div>

            {selectedTool.output_schema && (
              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-high)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 'var(--space-2)' }}>Output JSON Schema</h3>
                <pre className="font-mono" style={{ padding: 'var(--space-3)', background: 'var(--surface-overlay)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', fontSize: '11px', color: 'var(--text-high)', overflowX: 'auto', margin: 0 }}>
                  {JSON.stringify(selectedTool.output_schema, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>

      {/* Controlled Invocations Modal */}
      <Modal
        isOpen={Boolean(invokingTool)}
        onClose={() => setInvokingTool(null)}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Play size={15} style={{ color: 'var(--accent-primary)' }} />
            <span>Invoke MCP Tool: {invokingTool?.tool_name}</span>
          </div>
        }
      >
        {invokingTool && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                <OpClassBadge opClass={invokingTool.operation_class} />
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Server: {invokingTool.server_id}</span>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0 }}>{invokingTool.description}</p>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-muted)', marginBottom: 'var(--space-1)' }}>
                Invocation Arguments (JSON format)
              </label>
              <textarea
                value={invokeArgsJson}
                onChange={(e) => setInvokeArgsJson(e.target.value)}
                rows={5}
                style={{ width: '100%', padding: 'var(--space-2)', background: 'var(--surface-overlay)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', color: 'var(--text-high)', fontFamily: 'var(--font-mono)', fontSize: '12px', outline: 'none' }}
              />
            </div>

            {invokeError && (
              <div style={{ padding: 'var(--space-2) var(--space-3)', background: 'var(--status-critical-bg)', border: '1px solid var(--border-critical)', borderRadius: 'var(--radius-sm)', color: 'var(--text-critical)', fontSize: '12px' }}>
                Error: {invokeError}
              </div>
            )}

            {Boolean(invokeResult) && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-success)', fontWeight: 600, marginBottom: '4px' }}>Invocation Result (Success):</div>
                <pre className="font-mono" style={{ padding: 'var(--space-2)', background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', fontSize: '11px', color: 'var(--text-high)', overflowX: 'auto', margin: 0 }}>
                  {JSON.stringify(invokeResult, null, 2)}
                </pre>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
              <Button variant="outline" size="sm" onClick={() => setInvokingTool(null)}>Close</Button>
              <Button
                variant="primary"
                size="sm"
                disabled={invokeMutation.isPending}
                onClick={() => {
                  try {
                    const parsedArgs = JSON.parse(invokeArgsJson)
                    invokeMutation.mutate({ serverId: invokingTool.server_id, toolName: invokingTool.tool_name, args: parsedArgs })
                  } catch (err) {
                    setInvokeError('Invalid JSON format for arguments: ' + (err as Error).message)
                  }
                }}
              >
                {invokeMutation.isPending ? 'Invoking Tool...' : 'Invoke Tool'}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
