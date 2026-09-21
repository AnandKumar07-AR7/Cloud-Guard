import React from 'react'

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'elevated' | 'overlay' | 'subtle' | 'critical'
  interactive?: boolean
}

export const Card: React.FC<CardProps> = ({
  variant = 'default',
  interactive = false,
  className = '',
  style,
  children,
  ...props
}) => {
  const getBg = () => {
    switch (variant) {
      case 'elevated':
        return 'var(--surface-elevated)'
      case 'overlay':
        return 'var(--surface-overlay)'
      case 'subtle':
        return 'var(--bg-surface-subtle)'
      case 'critical':
        return 'var(--sev-critical-bg)'
      default:
        return 'var(--surface-base)'
    }
  }

  const getBorder = () => {
    switch (variant) {
      case 'critical':
        return '1px solid var(--sev-critical-border)'
      case 'elevated':
        return '1px solid var(--border-medium)'
      default:
        return '1px solid var(--border-subtle)'
    }
  }

  return (
    <div
      className={`cg-card ${className}`}
      style={{
        background: getBg(),
        border: getBorder(),
        borderRadius: 'var(--radius-lg)',
        boxShadow: 'var(--shadow-sm)',
        transition: interactive ? 'border-color 0.18s ease, transform 0.18s ease, box-shadow 0.18s ease' : undefined,
        cursor: interactive ? 'pointer' : undefined,
        overflow: 'hidden',
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  )
}

export interface CardHeaderProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode
  subtitle?: React.ReactNode
  action?: React.ReactNode
}

export const CardHeader: React.FC<CardHeaderProps> = ({
  title,
  subtitle,
  action,
  children,
  style,
  ...props
}) => {
  return (
    <div
      style={{
        padding: '16px 20px',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 'var(--space-2)',
        ...style,
      }}
      {...props}
    >
      <div>
        {title && (
          <div style={{ fontSize: 'var(--font-size-md)', fontWeight: 700, color: 'var(--text-primary)' }}>
            {title}
          </div>
        )}
        {subtitle && (
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
            {subtitle}
          </div>
        )}
        {children}
      </div>
      {action && <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>{action}</div>}
    </div>
  )
}

export const CardBody: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  style,
  ...props
}) => {
  return (
    <div
      style={{
        padding: '20px',
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  )
}

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  style,
  ...props
}) => {
  return (
    <div
      style={{
        padding: '12px 20px',
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(0, 0, 0, 0.15)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: 'var(--font-size-xs)',
        color: 'var(--text-muted)',
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  )
}
