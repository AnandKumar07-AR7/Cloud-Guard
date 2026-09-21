import React from 'react'

interface ScoreGaugeProps {
  score: number
  size?: number
  strokeWidth?: number
  label?: string
  subtitle?: string
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  size = 140,
  strokeWidth = 10,
  label = 'POSTURE SCORE',
  subtitle,
}) => {
  const normalizedScore = Math.max(0, Math.min(100, isNaN(score) ? 0 : score))
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (normalizedScore / 100) * circumference

  const getColor = (s: number) => {
    if (s >= 85) return 'var(--state-success)'
    if (s >= 70) return 'var(--sev-low)'
    if (s >= 50) return 'var(--sev-medium)'
    if (s >= 30) return 'var(--sev-high)'
    return 'var(--sev-critical)'
  }

  const scoreColor = getColor(normalizedScore)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="var(--bg-surface-3)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={scoreColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span className="font-mono font-bold" style={{ fontSize: size * 0.26, color: scoreColor, lineHeight: 1 }}>
            {Math.round(normalizedScore)}
          </span>
          <span className="text-xs font-mono text-muted" style={{ marginTop: 4, letterSpacing: '0.05em' }}>
            / 100
          </span>
        </div>
      </div>
      {label && (
        <span className="text-xs font-mono text-secondary" style={{ marginTop: 8, letterSpacing: '0.08em' }}>
          {label}
        </span>
      )}
      {subtitle && (
        <span className="text-xs text-muted" style={{ marginTop: 2 }}>
          {subtitle}
        </span>
      )}
    </div>
  )
}
