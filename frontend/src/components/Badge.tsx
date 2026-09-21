import React from 'react'

export interface BadgeProps {
  children: React.ReactNode
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'error' | 'cyan' | 'default'
  size?: 'sm' | 'md'
  className?: string
  style?: React.CSSProperties
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'md',
  className = '',
  style = {},
}) => {
  const getStyles = () => {
    switch (variant) {
      case 'critical':
        return {
          background: 'var(--sev-critical-bg)',
          color: 'var(--sev-critical)',
          borderColor: 'var(--sev-critical-border)',
        }
      case 'high':
        return {
          background: 'var(--sev-high-bg)',
          color: 'var(--sev-high)',
          borderColor: 'var(--sev-high-border)',
        }
      case 'medium':
        return {
          background: 'var(--sev-medium-bg)',
          color: 'var(--sev-medium)',
          borderColor: 'var(--sev-medium-border)',
        }
      case 'low':
        return {
          background: 'var(--sev-low-bg)',
          color: 'var(--sev-low)',
          borderColor: 'var(--sev-low-border)',
        }
      case 'info':
        return {
          background: 'var(--sev-info-bg)',
          color: 'var(--sev-info)',
          borderColor: 'var(--sev-info-border)',
        }
      case 'success':
        return {
          background: 'var(--state-success-bg)',
          color: 'var(--state-success)',
          borderColor: 'var(--state-success-border)',
        }
      case 'cyan':
        return {
          background: 'var(--accent-cyan-subtle)',
          color: 'var(--accent-cyan)',
          borderColor: 'var(--accent-cyan-border)',
        }
      case 'error':
        return {
          background: 'var(--state-error-bg)',
          color: 'var(--state-error)',
          borderColor: 'rgba(239, 68, 68, 0.3)',
        }
      default:
        return {
          background: 'var(--bg-surface-2)',
          color: 'var(--text-secondary)',
          borderColor: 'var(--border-medium)',
        }
    }
  }

  const vStyle = getStyles()
  const isSm = size === 'sm'

  return (
    <span
      className={`mono-val ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: isSm ? '1px 6px' : '2px 8px',
        fontSize: isSm ? 10 : 11,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        borderRadius: 4,
        border: `1px solid ${vStyle.borderColor}`,
        backgroundColor: vStyle.background,
        color: vStyle.color,
        lineHeight: 1.4,
        whiteSpace: 'nowrap',
        ...style,
      }}
    >
      {children}
    </span>
  )
}

export const SeverityBadge: React.FC<{ severity: string; size?: 'sm' | 'md'; count?: number }> = ({
  severity,
  size,
  count,
}) => {
  const s = severity?.toLowerCase() || 'info'
  const variantMap: Record<string, BadgeProps['variant']> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'info',
    info: 'info',
  }
  const variant = variantMap[s] || 'default'

  return (
    <Badge variant={variant} size={size}>
      {severity}
      {count !== undefined && <span style={{ marginLeft: 4, opacity: 0.85 }}>({count})</span>}
    </Badge>
  )
}

export const StatusBadge: React.FC<{ status: string; size?: 'sm' | 'md' }> = ({ status, size }) => {
  const s = status?.toUpperCase() || 'UNKNOWN'
  let variant: BadgeProps['variant'] = 'default'

  if (['COMPLETED', 'RESOLVED', 'VERIFIED_FIXED', 'APPROVED', 'HEALTHY', 'SECURE'].includes(s)) {
    variant = 'success'
  } else if (['RUNNING', 'ANALYZING', 'DISCOVERING', 'EXECUTING', 'PENDING_APPROVAL'].includes(s)) {
    variant = 'cyan'
  } else if (['FAILED', 'CRITICAL', 'EXECUTION_FAILED', 'VERIFICATION_FAILED', 'UNHEALTHY'].includes(s)) {
    variant = 'critical'
  } else if (['AT_RISK', 'HIGH_RISK', 'DEGRADED', 'STILL_VULNERABLE'].includes(s)) {
    variant = 'high'
  } else if (['DISABLED', 'CANCELLED', 'SUPPRESSED'].includes(s)) {
    variant = 'info'
  }

  return (
    <Badge variant={variant} size={size}>
      {status}
    </Badge>
  )
}

export const OpClassBadge: React.FC<{ opClass: string; size?: 'sm' | 'md' }> = ({ opClass, size }) => {
  const op = opClass?.toUpperCase() || 'READ'
  let variant: BadgeProps['variant'] = 'info'
  if (op === 'WRITE') variant = 'medium'
  if (op === 'DESTRUCTIVE') variant = 'critical'
  if (op === 'READ') variant = 'cyan'

  return (
    <Badge variant={variant} size={size}>
      {op}
    </Badge>
  )
}
