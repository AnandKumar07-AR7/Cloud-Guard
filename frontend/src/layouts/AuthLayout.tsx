import React from 'react'
import { Outlet } from 'react-router-dom'
import { CloudGuardLogo } from '../components/brand/CloudGuardLogo'

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
      <div style={{ marginBottom: 28 }}>
        <CloudGuardLogo variant="full" size={42} />
      </div>

      <div style={{ width: '100%', maxWidth: 380 }}>
        <Outlet />
      </div>

      <div
        className="text-xs font-mono text-muted"
        style={{ marginTop: 28, letterSpacing: '0.04em', textAlign: 'center' }}
      >
        CLOUDGUARD SECURITY PLATFORM • AUTONOMOUS CLOUD DEFENSE
      </div>
    </div>
  )
}
