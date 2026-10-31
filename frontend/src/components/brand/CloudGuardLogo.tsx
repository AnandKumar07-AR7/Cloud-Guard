import React from 'react'

export type LogoVariant = 'mark' | 'full' | 'hero'

interface AegisByteLogoProps {
  variant?: LogoVariant
  /** For 'mark': size of the icon container in px. Default 36 */
  size?: number
  className?: string
  style?: React.CSSProperties
}

/**
 * AegisByte brand logo component.
 * Features the official AegisByte cyber emblem and glowing typography.
 *
 * variant="mark"  — emblem only (circular neon cyber badge)
 * variant="full"  — emblem + AegisByte wordmark (header / nav)
 * variant="hero"  — large glowing emblem + wordmark (login / splash)
 */
export const AegisByteLogo: React.FC<AegisByteLogoProps> = ({
  variant = 'full',
  size = 36,
  className,
  style,
}) => {
  const isHero = variant === 'hero'
  const isFull = variant === 'full' || isHero

  const markSize = isHero ? 84 : size
  const wordmarkSize = isHero ? 30 : 17
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
      {/* AegisByte Circular Cyber Emblem */}
      <div
        style={{
          position: 'relative',
          width: markSize,
          height: markSize,
          flexShrink: 0,
        }}
      >
        {/* Animated outer cyber glow ring */}
        <div
          className="cg-logo-glow"
          style={{
            position: 'absolute',
            inset: isHero ? -6 : -3,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.6) 0%, rgba(168, 85, 247, 0.5) 50%, rgba(6, 182, 212, 0.4) 100%)',
            filter: isHero ? 'blur(12px)' : 'blur(7px)',
            opacity: 0.85,
            zIndex: 0,
          }}
        />

        {/* Circular Avatar Container with Cyber Border */}
        <div
          style={{
            position: 'relative',
            zIndex: 1,
            width: markSize,
            height: markSize,
            borderRadius: '50%',
            overflow: 'hidden',
            border: isHero ? '2px solid rgba(56, 189, 248, 0.7)' : '1.5px solid rgba(56, 189, 248, 0.5)',
            boxShadow: isHero
              ? '0 0 25px rgba(56, 189, 248, 0.5), inset 0 0 15px rgba(168, 85, 247, 0.3)'
              : '0 0 12px rgba(56, 189, 248, 0.35)',
            background: '#040714',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
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
        </div>
      </div>

      {/* AegisByte Wordmark */}
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
              fontSize: taglineSize,
              fontFamily: 'var(--font-mono, "JetBrains Mono", monospace)',
              color: 'var(--accent-cyan, #06b6d4)',
              letterSpacing: '0.08em',
              fontWeight: 700,
              textTransform: 'uppercase',
              opacity: 0.95,
            }}
          >
            {isHero ? 'AI-Driven Cloud Security & Automated Remediation' : 'AI Cloud Security & Defense'}
          </span>
        </div>
      )}
    </div>
  )
}

// Backward-compatibility alias so existing imports work seamlessly
export const CloudGuardLogo = AegisByteLogo

export default AegisByteLogo
