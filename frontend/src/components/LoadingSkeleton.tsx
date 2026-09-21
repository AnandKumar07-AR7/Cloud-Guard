import React from 'react'

export interface SkeletonProps {
  variant?: 'text' | 'card' | 'table' | 'stat'
  width?: number | string
  height?: number | string
  borderRadius?: number | string
  count?: number
  style?: React.CSSProperties
}

export const LoadingSkeleton: React.FC<SkeletonProps> = ({
  variant = 'text',
  width = '100%',
  height,
  borderRadius,
  count = 1,
  style,
}) => {
  if (variant === 'card') {
    return (
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 'var(--space-4)',
          width: '100%',
          ...style,
        }}
      >
        {Array.from({ length: count }).map((_, i) => (
          <div
            key={i}
            style={{
              padding: '20px',
              borderRadius: 'var(--radius-lg)',
              background: 'var(--surface-base)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <div
              style={{
                width: '45%',
                height: 14,
                borderRadius: 'var(--radius-xs)',
                background: 'var(--surface-elevated)',
                animation: 'pulse 1.6s ease-in-out infinite',
              }}
            />
            <div
              style={{
                width: '80%',
                height: 24,
                borderRadius: 'var(--radius-xs)',
                background: 'var(--surface-elevated)',
                animation: 'pulse 1.6s ease-in-out infinite',
              }}
            />
            <div
              style={{
                width: '100%',
                height: 38,
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface-subtle)',
                marginTop: 6,
                animation: 'pulse 1.6s ease-in-out infinite',
              }}
            />
          </div>
        ))}
      </div>
    )
  }

  if (variant === 'table') {
    return (
      <div
        style={{
          width: '100%',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
          background: 'var(--surface-base)',
          overflow: 'hidden',
          ...style,
        }}
      >
        <div
          style={{
            height: 40,
            background: 'var(--surface-elevated)',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        />
        <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          {Array.from({ length: Math.max(count, 3) }).map((_, i) => (
            <div
              key={i}
              style={{
                display: 'grid',
                gridTemplateColumns: '80px 1fr 140px 100px',
                gap: 16,
                alignItems: 'center',
                padding: '6px 0',
                borderBottom: i < count - 1 ? '1px solid var(--border-subtle)' : undefined,
              }}
            >
              <div style={{ height: 18, borderRadius: 4, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
              <div style={{ height: 16, borderRadius: 4, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
              <div style={{ height: 16, borderRadius: 4, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
              <div style={{ height: 18, borderRadius: 4, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (variant === 'stat') {
    return (
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 'var(--space-3)',
          width: '100%',
          ...style,
        }}
      >
        {Array.from({ length: count }).map((_, i) => (
          <div
            key={i}
            style={{
              padding: '16px 18px',
              borderRadius: 'var(--radius-lg)',
              background: 'var(--surface-base)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <div style={{ width: '50%', height: 12, borderRadius: 4, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
            <div style={{ width: '35%', height: 28, borderRadius: 6, background: 'var(--surface-elevated)', animation: 'pulse 1.6s ease-in-out infinite' }} />
          </div>
        ))}
      </div>
    )
  }

  // Fallback / default text variant
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, width: '100%', ...style }}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          style={{
            width,
            height: height || 18,
            borderRadius: borderRadius || 4,
            backgroundColor: 'var(--surface-elevated)',
            animation: 'pulse 1.6s ease-in-out infinite',
          }}
        />
      ))}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.45; }
          50% { opacity: 0.85; }
        }
      `}</style>
    </div>
  )
}
