import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Compass, ShieldAlert, Database, Layers, Wrench, Terminal, Cpu } from 'lucide-react'
import { findingsApi } from '../api/findingsApi'
import { resourcesApi } from '../api/resourcesApi'
import { scansApi } from '../api/scansApi'
import { mcpApi } from '../api/mcpApi'
import type { Finding } from '../types/findings'
import type { Resource } from '../types/resources'
import type { ScanSummary } from '../types/scans'
import type { MCPServer } from '../types/mcp'

interface PaletteItem {
  id: string
  title: string
  category: 'NAVIGATION' | 'FINDING' | 'RESOURCE' | 'SCAN' | 'MCP'
  subtitle?: string
  action: () => void
  icon: React.ReactNode
}

const STATIC_PAGES = [
  { path: '/overview', title: 'Command Enclave', category: 'COMMAND' },
  { path: '/posture', title: 'Security Posture', category: 'COMMAND' },
  { path: '/activity', title: 'Live Activity Stream', category: 'COMMAND' },
  { path: '/assets', title: 'Assets Explorer', category: 'DISCOVER' },
  { path: '/accounts', title: 'Cloud Accounts', category: 'DISCOVER' },
  { path: '/findings', title: 'Findings Directory', category: 'SECURITY' },
  { path: '/rules', title: 'Detection Rules Catalog', category: 'SECURITY' },
  { path: '/risk', title: 'Risk Analysis & Context', category: 'SECURITY' },
  { path: '/ai-analyst', title: 'AI Security Analyst Workspace', category: 'INTELLIGENCE' },
  { path: '/agent-orchestrator', title: 'Agent Orchestration Control Plane', category: 'INTELLIGENCE' },
  { path: '/agent-runs', title: 'Agent Runs History', category: 'INTELLIGENCE' },
  { path: '/remediation', title: 'Remediation Center', category: 'REMEDIATION' },
  { path: '/approvals', title: 'Remediation Approvals Queue', category: 'REMEDIATION' },
  { path: '/compliance', title: 'Compliance Mapping Posture', category: 'COMPLIANCE' },
  { path: '/scans', title: 'Scan Operations', category: 'OPERATIONS' },
  { path: '/audit', title: 'Audit Trail', category: 'OPERATIONS' },
  { path: '/mcp', title: 'MCP Servers & Control Center', category: 'SYSTEM' },
  { path: '/policies', title: 'Policy Governance & Automation', category: 'SYSTEM' },
  { path: '/settings', title: 'System Settings', category: 'SYSTEM' },
]

export const CommandPalette: React.FC<{ isOpen: boolean; onClose: () => void }> = ({
  isOpen,
  onClose,
}) => {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Real backend search data caches
  const [findings, setFindings] = useState<Finding[]>([])
  const [resources, setResources] = useState<Resource[]>([])
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [mcpServers, setMcpServers] = useState<MCPServer[]>([])

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)

      // Fetch active search candidates from real backend
      findingsApi.listFindings({ limit: 30 }).then((res) => setFindings(res.items)).catch(() => {})
      resourcesApi.listResources({ limit: 30 }).then((res) => setResources(res.items)).catch(() => {})
      scansApi.listScans({ limit: 10 }).then((res) => setScans(res.items)).catch(() => {})
      mcpApi.listServers().then((servers) => setMcpServers(servers)).catch(() => {})
    }
  }, [isOpen])

  // Build items list based on real data
  const allItems: PaletteItem[] = []

  // 1. Pages
  STATIC_PAGES.forEach((p) => {
    allItems.push({
      id: `page-${p.path}`,
      title: p.title,
      subtitle: `${p.category} › ${p.path}`,
      category: 'NAVIGATION',
      icon: <Compass size={14} className="text-cyan" />,
      action: () => {
        navigate(p.path)
        onClose()
      },
    })
  })

  // 2. Real Findings
  findings.forEach((f) => {
    allItems.push({
      id: `finding-${f.finding_id}`,
      title: `${f.rule_id}: ${f.title}`,
      subtitle: `${f.severity.toUpperCase()} • ${f.resource_id}`,
      category: 'FINDING',
      icon: <ShieldAlert size={14} className="text-critical" />,
      action: () => {
        navigate(`/findings/${f.finding_id}`)
        onClose()
      },
    })
  })

  // 3. Real Resources
  resources.forEach((r) => {
    allItems.push({
      id: `res-${r.resource_id}`,
      title: r.name || r.resource_id,
      subtitle: `${r.service.toUpperCase()} • ${r.resource_type} • ${r.account_id}`,
      category: 'RESOURCE',
      icon: <Database size={14} className="text-medium" />,
      action: () => {
        navigate(`/assets?resource_id=${encodeURIComponent(r.resource_id)}`)
        onClose()
      },
    })
  })

  // 4. Real Scans
  scans.forEach((s) => {
    allItems.push({
      id: `scan-${s.scan_id}`,
      title: `Scan ${s.scan_id.slice(0, 8)}...`,
      subtitle: `${s.status} • ${s.finding_count} findings • ${s.mode.toUpperCase()}`,
      category: 'SCAN',
      icon: <Layers size={14} className="text-low" />,
      action: () => {
        navigate('/scans')
        onClose()
      },
    })
  })

  // 5. Real MCP Servers
  mcpServers.forEach((m) => {
    allItems.push({
      id: `mcp-${m.server_id}`,
      title: m.server_name,
      subtitle: `${m.server_id} • ${m.enabled ? 'ENABLED' : 'DISABLED'} • ${m.tool_count} tools`,
      category: 'MCP',
      icon: <Cpu size={14} className="text-cyan" />,
      action: () => {
        navigate('/mcp')
        onClose()
      },
    })
  })

  // Filter items matching query
  const filtered = allItems.filter((item) => {
    if (!query.trim()) return true
    const q = query.toLowerCase()
    return (
      item.title.toLowerCase().includes(q) ||
      (item.subtitle && item.subtitle.toLowerCase().includes(q)) ||
      item.category.toLowerCase().includes(q)
    )
  }).slice(0, 20)

  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filtered.length))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev - 1 + filtered.length) % Math.max(1, filtered.length))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (filtered[selectedIndex]) {
        filtered[selectedIndex].action()
      }
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }

  if (!isOpen) return null

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 10000,
        backgroundColor: 'rgba(5, 7, 10, 0.75)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '12vh',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 620,
          backgroundColor: 'var(--bg-surface-1)',
          border: '1px solid var(--border-medium)',
          borderRadius: 8,
          boxShadow: 'var(--shadow-lg)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '70vh',
        }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '12px 16px',
            borderBottom: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-surface-2)',
          }}
        >
          <Search size={18} className="text-muted" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search pages, findings, resources, scans, MCP servers... (Esc to close)"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-sans)',
              fontSize: 14,
            }}
          />
          <kbd
            className="mono-val text-xs text-muted"
            style={{
              padding: '2px 6px',
              background: 'var(--bg-surface-3)',
              borderRadius: 4,
              border: '1px solid var(--border-medium)',
            }}
          >
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div style={{ padding: 6, overflowY: 'auto', flex: 1 }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '24px 16px', textAlign: 'center' }} className="text-xs text-muted">
              No matching entities found.
            </div>
          ) : (
            filtered.map((item, idx) => {
              const isSelected = idx === selectedIndex
              return (
                <div
                  key={item.id}
                  onClick={() => item.action()}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '8px 12px',
                    borderRadius: 6,
                    cursor: 'pointer',
                    backgroundColor: isSelected ? 'var(--bg-surface-3)' : 'transparent',
                    borderLeft: isSelected ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 20 }}>
                    {item.icon}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="text-sm font-medium text-primary text-truncate">{item.title}</div>
                    {item.subtitle && (
                      <div className="text-xs font-mono text-muted text-truncate">{item.subtitle}</div>
                    )}
                  </div>
                  <span
                    className="text-xs font-mono"
                    style={{
                      padding: '1px 6px',
                      borderRadius: 3,
                      backgroundColor: 'var(--bg-surface-2)',
                      color: 'var(--text-muted)',
                      fontSize: 10,
                    }}
                  >
                    {item.category}
                  </span>
                </div>
              )
            })
          )}
        </div>

        {/* Footer info */}
        <div
          style={{
            padding: '8px 16px',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--bg-surface-2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 11,
          }}
          className="text-muted font-mono"
        >
          <span>Navigate: ↑ ↓ • Select: Enter</span>
          <span>Entity Search: Live Backend Telemetry</span>
        </div>
      </div>
    </div>
  )
}
