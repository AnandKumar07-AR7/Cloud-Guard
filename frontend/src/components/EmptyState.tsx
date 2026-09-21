import React from 'react'
import { ShieldCheck } from 'lucide-react'

export interface EmptyStateProps {
  title?: string
  description?: string
  icon?: React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }> | React.ReactNode
  action?: React.ReactNode
  style?: React.CSSProperties
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No Data Available',
  description = 'No entities match the current operational criteria.',
  icon,
  action,
  style,
}) => {
  const renderIcon = () => {
    if (!icon) return <ShieldCheck size={24} style={{ color: 'var(--accent-cyan)' }} />
    if (React.isValidElement(icon)) return icon
    if (typeof icon === 'function') {
      const IconComponent = icon as React.ComponentType<{ size?: number }>
      return <IconComponent size={24} />
    }
    return <ShieldCheck size={24} style={{ color: 'var(--accent-cyan)' }} />
  }

  return (
    <div
      style={{
        padding: '48px 24px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        backgroundColor: 'var(--surface-base)',
        border: '1px dashed var(--border-medium)',
        borderRadius: 'var(--radius-lg)',
        ...style,
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          borderRadius: 'var(--radius-md)',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--text-muted)',
          marginBottom: 16,
          boxShadow: 'var(--shadow-sm)',
        }}
      >
        {renderIcon()}
      </div>
      <span
        style={{
          fontSize: 'var(--font-size-md)',
          fontWeight: 700,
          color: 'var(--text-primary)',
          marginBottom: 6,
          letterSpacing: '-0.01em',
        }}
      >
        {title}
      </span>
      <p
        style={{
          fontSize: 'var(--font-size-sm)',
          color: 'var(--text-muted)',
          maxWidth: 420,
          lineHeight: 1.5,
          marginBottom: action ? 20 : 0,
        }}
      >
        {description}
      </p>
      {action && <div>{action}</div>}
    </div>
  )
}
