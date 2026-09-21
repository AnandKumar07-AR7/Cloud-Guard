import React from 'react'

export type LogoVariant = 'mark' | 'full' | 'hero'

interface CloudGuardLogoProps {
  variant?: LogoVariant
  /** For 'mark': size of the icon container in px. Default 34 */
  size?: number
  className?: string
  style?: React.CSSProperties
}

/**
 * CloudGuard brand logo component.
 *
 * variant="mark"  — icon only (square shield mark)
 * variant="full"  — icon + CLOUDGUARD wordmark (used in header)
 * variant="hero"  — large icon + wordmark for auth/onboarding pages
 */
export const CloudGuardLogo: React.FC<CloudGuardLogoProps> = ({
  variant = 'full',
  size = 34,
  className,
  style,
}) => {
  const isHero = variant === 'hero'
  const isFull = variant === 'full' || isHero

  const markSize = isHero ? 64 : size
  const wordmarkSize = isHero ? 26 : 15
  const taglineSize = isHero ? 11 : 9

  return (
    <div
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: isHero ? 16 : 10,
        ...style,
      }}
    >
      {/* Shield Mark */}
      <div
        style={{
          position: 'relative',
          width: markSize,
          height: markSize,
          flexShrink: 0,
        }}
      >
        {/* Outer glow ring — animated */}
        <div
          className="cg-logo-glow"
          style={{
            position: 'absolute',
            inset: -3,
            borderRadius: '30%',
            background: 'linear-gradient(135deg, rgba(99,102,241,0.45) 0%, rgba(6,182,212,0.35) 100%)',
            filter: 'blur(8px)',
            zIndex: 0,
          }}
        />

        {/* Shield SVG icon */}
        <svg
          viewBox="0 0 48 48"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          width={markSize}
          height={markSize}
          style={{ position: 'relative', zIndex: 1, display: 'block' }}
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="cg-shield-grad" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#6366f1" />
              <stop offset="50%" stopColor="#818cf8" />
              <stop offset="100%" stopColor="#06b6d4" />
            </linearGradient>
            <linearGradient id="cg-inner-grad" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#ffffff" stopOpacity="0.18" />
              <stop offset="100%" stopColor="#ffffff" stopOpacity="0.04" />
            </linearGradient>
            <linearGradient id="cg-checkmark-grad" x1="14" y1="20" x2="34" y2="34" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#ffffff" />
              <stop offset="100%" stopColor="#e0f2fe" />
            </linearGradient>
            <filter id="cg-shield-shadow" x="-10%" y="-5%" width="120%" height="120%">
              <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#6366f1" floodOpacity="0.4" />
            </filter>
          </defs>

          {/* Shield body */}
          <path
            d="M24 3L6 10v11c0 10.5 7.7 20.4 18 22.8C34.3 41.4 42 31.5 42 21V10L24 3z"
            fill="url(#cg-shield-grad)"
            filter="url(#cg-shield-shadow)"
          />

          {/* Inner gloss */}
          <path
            d="M24 5.5L8 11.8V21c0 9.5 6.7 18.5 16 20.8 9.3-2.3 16-11.3 16-20.8v-9.2L24 5.5z"
            fill="url(#cg-inner-grad)"
          />

          {/* Shield border highlight */}
          <path
            d="M24 3L6 10v11c0 10.5 7.7 20.4 18 22.8C34.3 41.4 42 31.5 42 21V10L24 3z"
            fill="none"
            stroke="rgba(255,255,255,0.22)"
            strokeWidth="0.75"
          />

          {/* Check mark — security tick */}
          <path
            d="M15 24l6 6 12-12"
            stroke="url(#cg-checkmark-grad)"
            strokeWidth="2.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="none"
          />

          {/* Subtle top-left shine */}
          <ellipse cx="19" cy="14" rx="4" ry="2" fill="rgba(255,255,255,0.14)" transform="rotate(-30 19 14)" />
        </svg>
      </div>

      {/* Wordmark */}
      {isFull && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <span
            style={{
              fontSize: wordmarkSize,
              fontWeight: 800,
              letterSpacing: '0.08em',
              fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
              background: 'linear-gradient(135deg, #ffffff 0%, #e2e8f0 45%, #38bdf8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              lineHeight: 1.15,
              display: 'block',
            }}
          >
            CLOUDGUARD
          </span>
          <span
            style={{
              fontSize: taglineSize,
              fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
              color: 'var(--accent-cyan, #06b6d4)',
              letterSpacing: '0.06em',
              fontWeight: 600,
              opacity: 0.9,
            }}
          >
            {isHero ? 'AUTONOMOUS CLOUD SECURITY ENCLAVE' : 'AI POSTURE & DEFENSE'}
          </span>
        </div>
      )}
    </div>
  )
}

export default CloudGuardLogo
