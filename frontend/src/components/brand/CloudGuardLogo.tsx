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
          className={isHero ? 'cg-shield-3d' : ''}
          viewBox="0 0 48 48"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          width={markSize}
          height={markSize}
          style={{ position: 'relative', zIndex: 1, display: 'block' }}
          aria-hidden="true"
        >
          <img
            src="/aegisbyte-logo.jpg"
            alt="CloudGuard Logo"
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'cover',
              display: 'block',
              transform: 'scale(1.03)',
            }}
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span
              style={{
                fontSize: wordmarkSize,
                fontWeight: 800,
                letterSpacing: '0.02em',
                fontFamily: 'var(--font-heading, "Outfit", "Plus Jakarta Sans", sans-serif)',
                background: 'linear-gradient(135deg, #ffffff 0%, #e0f2fe 35%, #38bdf8 70%, #c084fc 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
                lineHeight: 1.15,
                display: 'block',
              }}
            >
              CloudGuard
            </span>
          </div>
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

export const AegisByteLogo = CloudGuardLogo
export default CloudGuardLogo
