import React from 'react'
import { Outlet } from 'react-router-dom'
import { Shield } from 'lucide-react'

export const AuthLayout: React.FC = () => {
  return (
    <div
      style={{
        minHeight: '100vh',
        width: '100vw',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-app)',
        padding: 24,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 28 }}>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            backgroundColor: 'var(--bg-surface-3)',
            border: '1px solid var(--accent-cyan-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-cyan)',
          }}
        >
          <Shield size={20} />
        </div>
        <span className="font-mono font-bold text-primary" style={{ letterSpacing: '0.08em', fontSize: 18 }}>
          CLOUD<span className="text-cyan">GUARD</span>
        </span>
      </div>

      <div style={{ width: '100%', maxWidth: 380 }}>
        <Outlet />
      </div>

      <div
        className="text-xs font-mono text-muted"
        style={{ marginTop: 28, letterSpacing: '0.04em', textAlign: 'center' }}
      >
        CLOUDGUARD SECURITY PLATFORM • OBSIDIAN COMMAND CENTER
      </div>
    </div>
  )
}
