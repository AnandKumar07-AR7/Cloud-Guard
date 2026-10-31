import React from 'react'
import { Loader2 } from 'lucide-react'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  icon?: React.ReactNode
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'secondary',
  size = 'md',
  isLoading = false,
  icon,
  children,
  style,
  disabled,
  ...props
}) => {
  const getStyles = () => {
    const base: React.CSSProperties = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 'var(--space-2)',
      borderRadius: 'var(--radius-md)',
      fontFamily: 'var(--font-sans)',
      fontWeight: 600,
      cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
      opacity: disabled || isLoading ? 0.65 : 1,
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      border: '1px solid transparent',
      transition: 'all 0.18s cubic-bezier(0.4, 0, 0.2, 1)',
    }

    // Size
    switch (size) {
      case 'sm':
        base.padding = '5px 10px'
        base.fontSize = 'var(--font-size-xs)'
        break
      case 'lg':
        base.padding = '12px 22px'
        base.fontSize = 'var(--font-size-base)'
        break
      default:
        base.padding = '8px 16px'
        base.fontSize = 'var(--font-size-sm)'
    }

    // Variant
    switch (variant) {
      case 'primary':
        base.background = 'var(--gradient-brand)'
        base.color = '#ffffff'
        base.boxShadow = '0 2px 10px rgba(99, 102, 241, 0.35)'
        break
      case 'danger':
        base.background = 'rgba(244, 63, 94, 0.18)'
        base.borderColor = 'var(--sev-critical-border)'
        base.color = 'var(--sev-critical)'
        break
      case 'outline':
        base.background = 'transparent'
        base.borderColor = 'var(--border-medium)'
        base.color = 'var(--text-secondary)'
        break
      case 'ghost':
        base.background = 'transparent'
        base.color = 'var(--text-muted)'
        break
      default: // secondary
        base.background = 'rgba(255, 255, 255, 0.06)'
        base.borderColor = 'var(--border-subtle)'
        base.color = 'var(--text-primary)'
    }

    return base
  }

  return (
    <button
      className={`cg-btn-3d ${props.className || ''}`}
      disabled={disabled || isLoading}
      style={{
        ...getStyles(),
        ...style,
      }}
      {...props}
    >
      {isLoading ? (
        <Loader2 size={size === 'sm' ? 12 : 15} className="spin" />
      ) : (
        icon
      )}
      {children}
    </button>
  )
}
