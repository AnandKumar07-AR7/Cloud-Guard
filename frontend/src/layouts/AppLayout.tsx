import React, { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { PageBackground } from '../components/brand/PageBackground'
import { AegisByteLogo } from '../components/brand/CloudGuardLogo'
import {
  LayoutDashboard,
  Activity,
  Layers,
  Cloud,
  AlertTriangle,
  BookOpen,
  TrendingUp,
  BrainCircuit,
  Bot,
  PlaySquare,
  Wrench,
  CheckSquare,
  CheckCircle2,
  Scan,
  FileText,
  Cpu,
  Sliders,
  Settings,
  Search,
  Power,
  LogOut,
  Radio,
  Sparkles,
  Menu,
  X,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { authApi } from '../api/authApi'
import { automationApi } from '../api/automationApi'
import { systemApi } from '../api/systemApi'
import { mcpApi } from '../api/mcpApi'
import { CommandPalette } from '../components/CommandPalette'
import { Modal } from '../components/Modal'
import type { KillSwitchStatus } from '../types/automation'
import type { HealthResponse } from '../types/system'

export const AppLayout: React.FC = () => {
  const { user, logout, hasRole } = useAuth()
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false)
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [killSwitch, setKillSwitch] = useState<KillSwitchStatus>({ enabled: false, active: false })
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [mcpServerCount, setMcpServerCount] = useState<number>(3)
  const [isKillSwitchModalOpen, setIsKillSwitchModalOpen] = useState(false)
  const [killSwitchReason, setKillSwitchReason] = useState('')
  const [isUpdatingKillSwitch, setIsUpdatingKillSwitch] = useState(false)
  const [killSwitchError, setKillSwitchError] = useState<string | null>(null)

  // Listen for Ctrl+K / Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setIsCommandPaletteOpen((prev) => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Poll system telemetry periodically
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const [h, ks, servers] = await Promise.all([
          systemApi.getHealth().catch(() => null),
          automationApi.getKillSwitchStatus().catch(() => ({ enabled: false, active: false })),
          mcpApi.listServers().catch(() => []),
        ])
        if (h) setHealth(h)
        setKillSwitch(ks)
        if (servers) setMcpServerCount(servers.length)
      } catch {
        // Fallback gracefully
      }
    }

    fetchStatus()
    const interval = setInterval(fetchStatus, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleToggleKillSwitch = async () => {
    if (!killSwitchReason.trim()) {
      setKillSwitchError('A valid operational reason is strictly required.')
      return
    }
    setIsUpdatingKillSwitch(true)
    setKillSwitchError(null)
    try {
      if (killSwitch.active) {
        const res = await automationApi.disableKillSwitch(killSwitchReason)
        setKillSwitch(res)
      } else {
        const res = await automationApi.enableKillSwitch(killSwitchReason)
        setKillSwitch(res)
      }
      setIsKillSwitchModalOpen(false)
      setKillSwitchReason('')
    } catch (err) {
      setKillSwitchError(err instanceof Error ? err.message : 'Action failed')
    } finally {
      setIsUpdatingKillSwitch(false)
    }
  }

  const isAdmin = hasRole('ADMIN')

  // Get user role color
  const getRoleBadgeStyle = (role?: string) => {
    switch (role?.toUpperCase()) {
      case 'ADMIN':
        return { bg: 'rgba(99, 102, 241, 0.2)', border: 'rgba(99, 102, 241, 0.4)', text: '#818cf8' }
      case 'SECURITY_ANALYST':
        return { bg: 'rgba(6, 182, 212, 0.2)', border: 'rgba(6, 182, 212, 0.4)', text: '#22d3ee' }
      case 'OPERATOR':
        return { bg: 'rgba(16, 185, 129, 0.2)', border: 'rgba(16, 185, 129, 0.4)', text: '#34d399' }
      default:
        return { bg: 'rgba(244, 63, 94, 0.2)', border: 'rgba(244, 63, 94, 0.4)', text: '#fb7185' }
    }
  }

  const roleStyle = getRoleBadgeStyle(user?.role)

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _location = useLocation() // consumed by PageBackground via its own hook

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', overflow: 'hidden', position: 'relative' }}>
      {/* Live 3D animated background — changes per module/route */}
      <PageBackground />
      {/* Top Luminous Header Bar */}
      <header
        style={{
          height: 60,
          background: 'rgba(11, 15, 26, 0.85)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          zIndex: 100,
        }}
      >
        {/* Brand & Mode Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Mobile Drawer Hamburger */}
          <button
            type="button"
            className="mobile-nav-toggle"
            onClick={() => setIsMobileNavOpen((prev) => !prev)}
            aria-label="Toggle navigation drawer"
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: 8,
              color: '#ffffff',
              padding: 6,
              cursor: 'pointer',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {isMobileNavOpen ? <X size={18} /> : <Menu size={18} />}
          </button>

          <Link to="/overview" style={{ display: 'flex', alignItems: 'center', textDecoration: 'none' }}>
            <AegisByteLogo variant="full" size={34} />
          </Link>

          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              padding: '3px 10px',
              borderRadius: 999,
              background: 'rgba(6, 182, 212, 0.12)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              color: '#38bdf8',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
            }}
          >
            <span
              className="pulse"
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                backgroundColor: '#06b6d4',
              }}
            />
            {health?.mode === 'aws' ? 'LIVE AWS CLOUD' : health?.mode ? health.mode.toUpperCase() : 'DEMO MODE'}
          </span>

          <button
            type="button"
            onClick={async () => {
              const current = user?.aws_account_id || '371700247056'
              const newAcc = window.prompt('Enter 12-digit AWS Account ID to switch active context:', current)
              if (newAcc && newAcc.trim().length === 12 && /^\d{12}$/.test(newAcc.trim())) {
                try {
                  await authApi.switchAccount(newAcc.trim())
                  window.location.reload()
                } catch (e: any) {
                  alert(e?.message || 'Failed to switch AWS Account')
                }
              } else if (newAcc) {
                alert('Invalid AWS Account ID: Must be exactly 12 numeric digits.')
              }
            }}
            title="Click to switch active AWS Account context"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              padding: '3px 8px',
              borderRadius: 6,
              background: 'rgba(56, 189, 248, 0.1)',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              color: '#38bdf8',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            <Radio size={11} className="text-cyan" />
            {user?.aws_account_id ? `AWS: ${user.aws_account_id}` : 'AWS: 817760095153'}
          </button>
        </div>

        {/* Center Search Command Palette Trigger */}
        <button
          type="button"
          onClick={() => setIsCommandPaletteOpen(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '7px 16px',
            background: 'rgba(18, 25, 43, 0.75)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: 12,
            color: 'var(--text-muted)',
            cursor: 'pointer',
            minWidth: 320,
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.4)'
            e.currentTarget.style.boxShadow = '0 0 15px rgba(99, 102, 241, 0.15)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)'
            e.currentTarget.style.boxShadow = 'none'
          }}
        >
          <Search size={14} className="text-cyan" />
          <span style={{ flex: 1, textAlign: 'left', fontSize: 12 }}>
            Search dashboard, issues, fixes...
          </span>
          <kbd
            style={{
              padding: '2px 6px',
              background: 'rgba(255, 255, 255, 0.08)',
              borderRadius: 6,
              border: '1px solid rgba(255, 255, 255, 0.12)',
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-secondary)',
            }}
          >
            Ctrl+K
          </kbd>
        </button>

        {/* Right Controls: Kill Switch + User Profile */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {/* Emergency Kill Switch Button */}
          <button
            type="button"
            onClick={() => {
              if (isAdmin) {
                setKillSwitchError(null)
                setKillSwitchReason('')
                setIsKillSwitchModalOpen(true)
              }
            }}
            title={isAdmin ? 'Toggle Global Remediation Kill Switch' : 'Kill Switch Status (Admin required to toggle)'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              padding: '6px 12px',
              borderRadius: 10,
              border: `1px solid ${killSwitch.active ? 'rgba(244, 63, 94, 0.5)' : 'rgba(16, 185, 129, 0.4)'}`,
              background: killSwitch.active
                ? 'linear-gradient(135deg, rgba(244, 63, 94, 0.2) 0%, rgba(225, 29, 72, 0.15) 100%)'
                : 'linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(6, 182, 212, 0.1) 100%)',
              color: killSwitch.active ? '#fb7185' : '#34d399',
              cursor: isAdmin ? 'pointer' : 'default',
              fontSize: 11,
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              boxShadow: killSwitch.active ? '0 0 15px rgba(244, 63, 94, 0.25)' : 'none',
            }}
          >
            <Power size={13} style={{ color: killSwitch.active ? '#f43f5e' : '#10b981' }} />
            <span>AUTO-FIX: {killSwitch.active ? 'PAUSED' : 'ACTIVE'}</span>
          </button>

          {/* User Profile Chip */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '4px 10px 4px 6px',
              borderRadius: 999,
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
            }}
          >
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                background: roleStyle.bg,
                border: `1px solid ${roleStyle.border}`,
                color: roleStyle.text,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: 12,
                fontFamily: 'var(--font-mono)',
              }}
            >
              {(user?.username || 'U')[0].toUpperCase()}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#ffffff', lineHeight: 1.2 }}>
                {user?.username || 'Commander'}
              </span>
              <span
                style={{
                  fontSize: 9,
                  fontFamily: 'var(--font-mono)',
                  color: roleStyle.text,
                  fontWeight: 600,
                  letterSpacing: '0.04em',
                }}
              >
                {user?.role || 'VIEWER'}
              </span>
            </div>

            <button
              type="button"
              onClick={() => logout()}
              title="Sign Out"
              style={{
                background: 'rgba(255, 255, 255, 0.08)',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '5px 7px',
                marginLeft: 2,
                borderRadius: 8,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = '#f43f5e'
                e.currentTarget.style.background = 'rgba(244, 63, 94, 0.15)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--text-muted)'
                e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'
              }}
            >
              <LogOut size={13} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container: Sidebar + Content */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', position: 'relative', zIndex: 1 }}>
        {/* Mobile Backdrop */}
        {isMobileNavOpen && (
          <div
            className="enclave-sidebar-backdrop"
            onClick={() => setIsMobileNavOpen(false)}
            aria-hidden="true"
          />
        )}

        {/* Luminous Sidebar Navigation */}
        <aside
          className={`enclave-sidebar ${isMobileNavOpen ? 'open' : ''}`}
          style={{
            width: 230,
            background: 'rgba(11, 15, 26, 0.85)',
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            borderRight: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            overflowY: 'auto',
            padding: '16px 10px',
          }}
        >
          <div>
            {/* 4 CORE PRIMARY TABS */}
            <NavSection label="MAIN NAVIGATION">
              <NavItem
                to="/overview"
                icon={<LayoutDashboard size={17} />}
                label="Dashboard"
                subtitle="Overview & Health"
                color="#818cf8"
                onClick={() => setIsMobileNavOpen(false)}
              />
              <NavItem
                to="/scans"
                icon={<Scan size={17} />}
                label="Scans"
                subtitle="Run & Track Cloud Scans"
                color="#06b6d4"
                onClick={() => setIsMobileNavOpen(false)}
              />
              <NavItem
                to="/findings"
                icon={<AlertTriangle size={17} />}
                label="Issues"
                subtitle="Cloud Misconfigurations"
                color="#fb7185"
                onClick={() => setIsMobileNavOpen(false)}
              />
              <NavItem
                to="/remediation"
                icon={<Wrench size={17} />}
                label="Fixes"
                subtitle="Auto-Remediation & Plans"
                color="#34d399"
                onClick={() => setIsMobileNavOpen(false)}
              />
            </NavSection>

            {/* EXPANDABLE MORE TOOLS (ADVANCED) */}
            <div style={{ marginTop: 12 }}>
              <button
                type="button"
                onClick={() => setShowAdvanced((prev) => !prev)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '7px 10px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(255, 255, 255, 0.07)',
                  borderRadius: 8,
                  color: 'var(--text-muted)',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {showAdvanced ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                  <span>{showAdvanced ? 'Hide Advanced' : 'More Tools'}</span>
                </span>
                <span style={{ fontSize: 10, opacity: 0.6 }}>{showAdvanced ? '' : 'AI, Compliance'}</span>
              </button>

              {showAdvanced && (
                <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 2, paddingLeft: 4 }}>
                  <NavItem to="/ai-analyst" icon={<BrainCircuit size={15} />} label="AI Assistant" subtitle="Ask security questions" color="#c084fc" onClick={() => setIsMobileNavOpen(false)} />
                  <NavItem to="/posture" icon={<TrendingUp size={15} />} label="Security Posture" subtitle="Score trends" color="#38bdf8" onClick={() => setIsMobileNavOpen(false)} />
                  <NavItem to="/compliance" icon={<CheckCircle2 size={15} />} label="Compliance (CIS)" subtitle="Industry standards" color="#10b981" onClick={() => setIsMobileNavOpen(false)} />
                  <NavItem to="/assets" icon={<Layers size={15} />} label="Cloud Assets" subtitle="Raw inventory" color="#a78bfa" onClick={() => setIsMobileNavOpen(false)} />
                  <NavItem to="/settings" icon={<Settings size={15} />} label="Settings" subtitle="System config" color="#94a3b8" onClick={() => setIsMobileNavOpen(false)} />
                </div>
              )}
            </div>
          </div>

          {/* Bottom Sidebar Status Card */}
          <div
            style={{
              marginTop: 16,
              padding: '12px 14px',
              borderRadius: 14,
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(6, 182, 212, 0.08) 100%)',
              border: '1px solid rgba(99, 102, 241, 0.25)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Sparkles size={14} style={{ color: '#38bdf8' }} />
              <span style={{ fontSize: 11, fontWeight: 700, color: '#ffffff' }}>Protection Status</span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Active Cloud Defense • Safe Auto-Fix Enabled
            </div>
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main
          style={{
            flex: 1,
            overflowY: 'auto',
            background: 'transparent',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ flex: 1, padding: '24px 28px', maxWidth: 1600, width: '100%', margin: '0 auto' }}>
            <Outlet />
          </div>

          {/* Bottom Operational Status Bar */}
          <footer
            style={{
              height: 32,
              background: 'rgba(11, 15, 26, 0.9)',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0 20px',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)',
              zIndex: 90,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    backgroundColor: health?.status === 'healthy' ? '#10b981' : '#f59e0b',
                  }}
                />
                SYSTEM: {health?.status === 'healthy' ? 'HEALTHY' : 'STANDBY'}
              </span>

              <span>AWS: {user?.aws_account_id || '817760095153'} (AP-SOUTHEAST-2)</span>
              <span>44 SECURITY RULES ACTIVE</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <span>ROLE: {user?.role || 'VIEWER'}</span>
              <span>
                AUTO-FIX:{' '}
                <strong style={{ color: killSwitch.active ? '#f43f5e' : '#10b981' }}>
                  {killSwitch.active ? 'PAUSED' : 'ACTIVE & READY'}
                </strong>
              </span>
            </div>
          </footer>
        </main>
      </div>

      {/* Command Palette Modal */}
      <CommandPalette isOpen={isCommandPaletteOpen} onClose={() => setIsCommandPaletteOpen(false)} />

      {/* Kill Switch Toggle Modal */}
      <Modal
        isOpen={isKillSwitchModalOpen}
        onClose={() => setIsKillSwitchModalOpen(false)}
        title={killSwitch.active ? 'RESTORE AUTO-REMEDIATION (DEACTIVATE KILL SWITCH)' : 'EMERGENCY HALT (ACTIVATE KILL SWITCH)'}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.5 }}>
            {killSwitch.active
              ? 'Deactivating the emergency kill switch restores automated remediation progression and policy execution across all cloud environments.'
              : 'CRITICAL ACTION: Activating the emergency kill switch immediately halts all automated remediation plan approvals, progression, and execution across all cloud environments.'}
          </p>

          <div>
            <label style={{ display: 'block', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 6 }}>
              OPERATIONAL JUSTIFICATION (REQUIRED):
            </label>
            <textarea
              rows={3}
              value={killSwitchReason}
              onChange={(e) => setKillSwitchReason(e.target.value)}
              placeholder="Provide exact operational reason for cryptographic audit trail recording..."
              style={{
                width: '100%',
                padding: '10px 12px',
                borderRadius: 10,
                border: '1px solid rgba(255, 255, 255, 0.14)',
                backgroundColor: 'rgba(10, 14, 25, 0.8)',
                color: '#ffffff',
                fontSize: 13,
                outline: 'none',
              }}
            />
          </div>

          {killSwitchError && (
            <div
              style={{
                padding: '8px 12px',
                borderRadius: 8,
                backgroundColor: 'rgba(244, 63, 94, 0.15)',
                border: '1px solid rgba(244, 63, 94, 0.35)',
                color: '#f43f5e',
                fontSize: 12,
              }}
            >
              {killSwitchError}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
            <button
              type="button"
              onClick={() => setIsKillSwitchModalOpen(false)}
              style={{
                padding: '8px 16px',
                borderRadius: 8,
                border: '1px solid rgba(255, 255, 255, 0.14)',
                backgroundColor: 'transparent',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleToggleKillSwitch}
              disabled={isUpdatingKillSwitch}
              style={{
                padding: '8px 18px',
                borderRadius: 8,
                border: 'none',
                backgroundColor: killSwitch.active ? '#10b981' : '#e11d48',
                color: '#ffffff',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
              }}
            >
              {isUpdatingKillSwitch ? 'Updating...' : killSwitch.active ? 'RESTORE AUTOMATION' : 'ACTIVATE EMERGENCY HALT'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

const NavSection: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div style={{ marginBottom: 14 }}>
    <div
      style={{
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: '0.08em',
        padding: '3px 8px',
        marginBottom: 3,
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}
    >
      {label}
    </div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>{children}</div>
  </div>
)

const NavItem: React.FC<{
  to: string
  icon: React.ReactNode
  label: string
  subtitle?: string
  color?: string
  onClick?: () => void
}> = ({
  to,
  icon,
  label,
  subtitle,
  color = 'var(--text-muted)',
  onClick,
}) => (
  <NavLink
    to={to}
    onClick={onClick}
    className={({ isActive }) => `cg-nav-3d ${isActive ? 'active' : ''}`}
    style={({ isActive }) => ({
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: '8px 10px',
      borderRadius: 'var(--radius-sm)',
      textDecoration: 'none',
      color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
      background: isActive ? 'var(--accent-bg)' : 'transparent',
      border: isActive ? '1px solid var(--accent-border)' : '1px solid transparent',
      transition: 'all 0.15s ease',
      marginBottom: 3,
    })}
  >
    {({ isActive }) => (
      <>
        <span
          style={{
            color: isActive ? 'var(--accent-cyan)' : color,
            display: 'flex',
            alignItems: 'center',
            opacity: isActive ? 1 : 0.85,
            padding: 5,
            borderRadius: 6,
            background: isActive ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255, 255, 255, 0.03)',
          }}
        >
          {icon}
        </span>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <span style={{ fontSize: 13, fontWeight: isActive ? 700 : 600 }}>{label}</span>
          {subtitle && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, lineHeight: 1.1 }}>{subtitle}</span>
          )}
        </div>
      </>
    )}
  </NavLink>
)
