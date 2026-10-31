import React from 'react'

export interface StatTileProps {
  label: string
  value: React.ReactNode
  context?: React.ReactNode
  icon?: React.ReactNode
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'success' | 'default'
  onClick?: () => void
}

export const StatTile: React.FC<StatTileProps> = ({
  label,
  value,
  context,
  icon,
  severity = 'default',
  onClick,
}) => {
  const getColors = () => {
    switch (severity) {
      case 'critical':
        return {
          bg: 'var(--sev-critical-bg)',
          border: 'var(--sev-critical-border)',
          valColor: 'var(--sev-critical)',
          labelColor: '#fda4af',
        }
      case 'high':
        return {
          bg: 'var(--sev-high-bg)',
          border: 'var(--sev-high-border)',
          valColor: 'var(--sev-high)',
          labelColor: '#fed7aa',
        }
      case 'medium':
        return {
          bg: 'var(--sev-medium-bg)',
          border: 'var(--sev-medium-border)',
          valColor: 'var(--sev-medium)',
          labelColor: '#fef08a',
        }
      case 'low':
        return {
          bg: 'var(--sev-low-bg)',
          border: 'var(--sev-low-border)',
          valColor: 'var(--sev-low)',
          labelColor: '#bae6fd',
        }
      case 'success':
        return {
          bg: 'var(--state-success-bg)',
          border: 'var(--state-success-border)',
          valColor: 'var(--state-success)',
          labelColor: '#a7f3d0',
        }
      default:
        return {
          bg: 'var(--surface-base)',
          border: 'var(--border-subtle)',
          valColor: 'var(--text-primary)',
          labelColor: 'var(--text-muted)',
        }
    }
  }

  const { bg, border, valColor, labelColor } = getColors()

  return (
    <div
      onClick={onClick}
      style={{
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: 'var(--radius-lg)',
        padding: '16px 18px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        cursor: onClick ? 'pointer' : undefined,
        transition: 'transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease',
        boxShadow: 'var(--shadow-sm)',
      }}
      className={onClick ? 'cg-stat-tile-interactive cg-3d-card' : 'cg-glass-3d'}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 700,
            fontFamily: 'var(--font-mono)',
            color: labelColor,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
          }}
        >
          {label}
        </span>
        {icon && <span style={{ color: valColor, opacity: 0.85 }}>{icon}</span>}
      </div>

      <div>
        <div
          style={{
            fontSize: 'var(--font-size-2xl)',
            fontWeight: 800,
            color: valColor,
            fontFamily: 'var(--font-mono)',
            lineHeight: 1.1,
          }}
        >
          {value}
        </div>
        {context && (
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 4 }}>
            {context}
          </div>
        )}
      </div>
    </div>
  )
}
