import React, { useState, useMemo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Lock,
  User as UserIcon,
  Mail,
  KeyRound,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  ShieldCheck,
  Zap,
  Globe,
  Activity,
} from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { ApiError } from '../api/client'
import { CloudGuardLogo } from '../components/brand/CloudGuardLogo'

interface LoginPageProps {
  initialMode?: 'login' | 'signup'
}

/** Animated SVG background — pure CSS, no extra dependencies */
const AnimatedBackground: React.FC = () => (
  <div
    aria-hidden="true"
    style={{ position: 'absolute', inset: 0, overflow: 'hidden', zIndex: 0 }}
  >
    {/* Base gradient */}
    <div
      style={{
        position: 'absolute',
        inset: 0,
        background:
          'radial-gradient(ellipse 80% 60% at 20% 10%, rgba(99,102,241,0.18) 0%, transparent 60%),' +
          'radial-gradient(ellipse 60% 50% at 80% 80%, rgba(6,182,212,0.14) 0%, transparent 55%),' +
          'radial-gradient(ellipse 50% 40% at 50% 50%, rgba(139,92,246,0.07) 0%, transparent 70%),' +
          '#080b14',
      }}
    />

    {/* Animated grid — subtle tech mesh */}
    <svg
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 0.06 }}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <pattern id="login-grid" width="56" height="56" patternUnits="userSpaceOnUse">
          <path d="M 56 0 L 0 0 0 56" fill="none" stroke="rgba(148,163,184,1)" strokeWidth="0.75" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#login-grid)" />
    </svg>

    {/* Floating orb 1 */}
    <div
      className="login-orb-1"
      style={{
        position: 'absolute',
        top: '15%',
        left: '10%',
        width: 480,
        height: 480,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 70%)',
        filter: 'blur(60px)',
      }}
    />

    {/* Floating orb 2 */}
    <div
      className="login-orb-2"
      style={{
        position: 'absolute',
        bottom: '10%',
        right: '5%',
        width: 560,
        height: 560,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(6,182,212,0.14) 0%, transparent 70%)',
        filter: 'blur(70px)',
      }}
    />

    {/* Floating orb 3 — violet accent */}
    <div
      className="login-orb-3"
      style={{
        position: 'absolute',
        top: '50%',
        left: '45%',
        width: 300,
        height: 300,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(139,92,246,0.12) 0%, transparent 70%)',
        filter: 'blur(50px)',
        transform: 'translate(-50%, -50%)',
      }}
    />




    {/* CSS for animations */}
    <style>{`
      @keyframes orb-float-1 {
        0%, 100% { transform: translate(0, 0) scale(1); }
        33% { transform: translate(30px, -20px) scale(1.05); }
        66% { transform: translate(-20px, 15px) scale(0.95); }
      }
      @keyframes orb-float-2 {
        0%, 100% { transform: translate(0, 0) scale(1); }
        40% { transform: translate(-25px, -30px) scale(1.08); }
        70% { transform: translate(15px, 20px) scale(0.93); }
      }
      @keyframes orb-float-3 {
        0%, 100% { transform: translate(-50%, -50%) scale(1); }
        50% { transform: translate(-50%, -60%) scale(1.1); }
      }
      @keyframes login-card-in {
        from { opacity: 0; transform: translateY(22px) scale(0.97); }
        to   { opacity: 1; transform: translateY(0)   scale(1); }
      }
      @keyframes login-border-glow {
        0%,100% { opacity: 0.6; filter: blur(1.5px); }
        50%      { opacity: 1; filter: blur(2.5px); }
      }
      @keyframes login-shimmer {
        0%   { transform: translateX(-100%) skewX(-15deg); }
        100% { transform: translateX(250%)  skewX(-15deg); }
      }
      @keyframes cute-pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.04); }
      }
      @keyframes cute-float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-5px); }
      }
      .login-orb-1 { animation: orb-float-1 12s ease-in-out infinite; }
      .login-orb-2 { animation: orb-float-2 15s ease-in-out infinite; }
      .login-orb-3 { animation: orb-float-3 10s ease-in-out infinite; }
      .login-card  { animation: login-card-in 0.55s cubic-bezier(0.16,1,0.3,1) both; }
      .login-border-glow { animation: login-border-glow 3s ease-in-out infinite; }
      .login-shimmer::after {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        background: linear-gradient(105deg, transparent 35%, rgba(255,255,255,0.06) 50%, transparent 65%);
        animation: login-shimmer 4s ease-in-out infinite 1.5s;
        pointer-events: none;
        border-radius: inherit;
        overflow: hidden;
      }
      .brand-stat-card {
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      }
      .brand-stat-card:hover {
        transform: translateY(-3px);
        background: rgba(255,255,255,0.065) !important;
        border-color: rgba(99,102,241,0.3) !important;
        box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5), 0 0 20px rgba(99,102,241,0.15) !important;
      }
      .cute-feature-tag {
        transition: all 0.2s ease;
      }
      .cute-feature-tag:hover {
        transform: translateY(-2px);
        background: rgba(255, 255, 255, 0.07) !important;
        border-color: rgba(99, 102, 241, 0.3) !important;
        color: #ffffff !important;
      }
      .cute-input-group {
        transition: all 0.22s ease;
      }
      .cute-input-group:focus-within {
        border-color: rgba(99, 102, 241, 0.75) !important;
        background: rgba(14, 20, 42, 0.95) !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.22), 0 8px 24px rgba(0, 0, 0, 0.35) !important;
      }
      .cute-btn {
        transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      }
      .cute-btn:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 12px 32px rgba(99, 102, 241, 0.45) !important;
        filter: brightness(1.07);
      }
      .cute-btn:active:not(:disabled) {
        transform: translateY(0px) scale(0.985);
      }
      @media (prefers-reduced-motion: reduce) {
        .login-orb-1, .login-orb-2, .login-orb-3, .login-card, .brand-stat-card, .cute-btn { animation: none; transition: none; }
      }
    `}</style>
  </div>
)

/** Left info panel with brand story + stats (optimized for 55% width) */
const BrandPanel: React.FC = () => {
  const stats = [
    { icon: <ShieldCheck size={18} />, value: '44', label: 'Deterministic Rules', badge: 'Active' },
    { icon: <Zap size={18} />, value: 'AI', label: 'Auto-Remediation', badge: 'Self-Healing' },
    { icon: <Globe size={18} />, value: 'Multi', label: 'Cloud Coverage', badge: 'AWS · GCP · Azure' },
    { icon: <Activity size={18} />, value: 'Live', label: 'Threat Detection', badge: 'Continuous' },
  ]

  return (
    <div
      style={{
        width: '100%',
        maxWidth: 620,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        padding: '48px 40px',
        position: 'relative',
        zIndex: 10,
      }}
    >
      {/* Top cute pill */}
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 14px',
          borderRadius: 999,
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(6, 182, 212, 0.12) 100%)',
          border: '1px solid rgba(99, 102, 241, 0.32)',
          color: '#c7d2fe',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          fontWeight: 700,
          letterSpacing: '0.06em',
          marginBottom: 26,
          width: 'fit-content',
          boxShadow: '0 0 20px rgba(99, 102, 241, 0.12)',
        }}
      >
        <span style={{ fontSize: 13 }}>✨</span>
        <span>AUTONOMOUS CLOUD DEFENSE 4.0</span>
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#38bdf8', boxShadow: '0 0 8px #38bdf8' }} />
        <span style={{ color: '#38bdf8', fontSize: 10, fontWeight: 700 }}>LIVE ENCLAVE</span>
      </div>

      {/* Logo */}
      <CloudGuardLogo variant="hero" size={62} style={{ marginBottom: 28 }} />

      {/* Headline */}
      <h1
        style={{
          fontSize: 40,
          fontWeight: 800,
          lineHeight: 1.15,
          letterSpacing: '-0.02em',
          color: '#ffffff',
          marginBottom: 16,
          maxWidth: 580,
        }}
      >
        Enterprise Cloud Security
        <br />
        <span
          style={{
            background: 'linear-gradient(135deg, #818cf8 0%, #38bdf8 50%, #c084fc 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            filter: 'drop-shadow(0 2px 14px rgba(129, 140, 248, 0.25))',
          }}
        >
          Redefined by AI
        </span>
      </h1>

      <p
        style={{
          fontSize: 14,
          color: 'rgba(226, 232, 240, 0.75)',
          lineHeight: 1.7,
          maxWidth: 540,
          marginBottom: 24,
        }}
      >
        Continuous posture assessment, autonomous threat remediation, and
        cryptographically audited governance across your entire cloud infrastructure.
      </p>

      {/* Cute Feature Chips */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 32, maxWidth: 560 }}>
        {[
          { icon: '🛡️', text: 'Zero-Trust Isolation' },
          { icon: '⚡', text: '120ms Auto-Remediation' },
          { icon: '🧠', text: 'AI Agent Enclave' },
          { icon: '🔒', text: 'Argon2id Enclave' },
        ].map((f, i) => (
          <div
            key={i}
            className="cute-feature-tag"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              borderRadius: 10,
              background: 'rgba(255,255,255,0.035)',
              border: '1px solid rgba(255,255,255,0.08)',
              fontSize: 11,
              color: '#cbd5e1',
              backdropFilter: 'blur(8px)',
            }}
          >
            <span>{f.icon}</span>
            <span style={{ fontWeight: 600 }}>{f.text}</span>
          </div>
        ))}
      </div>

      {/* Stats Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: 14,
          maxWidth: 560,
        }}
      >
        {stats.map((stat, i) => (
          <div
            key={i}
            className="brand-stat-card"
            style={{
              padding: '16px 18px',
              background: 'rgba(255,255,255,0.035)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 16,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              backdropFilter: 'blur(10px)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div
                style={{
                  width: 38,
                  height: 38,
                  borderRadius: 12,
                  background: 'linear-gradient(135deg, rgba(99,102,241,0.2) 0%, rgba(6,182,212,0.2) 100%)',
                  border: '1px solid rgba(99,102,241,0.28)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#818cf8',
                  flexShrink: 0,
                  boxShadow: '0 4px 12px rgba(99,102,241,0.15)',
                }}
              >
                {stat.icon}
              </div>
              <div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#ffffff', lineHeight: 1 }}>
                  {stat.value}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>
                  {stat.label}
                </div>
              </div>
            </div>
            <span
              style={{
                fontSize: 10,
                fontWeight: 600,
                color: '#38bdf8',
                background: 'rgba(6,182,212,0.1)',
                border: '1px solid rgba(6,182,212,0.2)',
                padding: '3px 8px',
                borderRadius: 999,
                fontFamily: 'var(--font-mono)',
              }}
            >
              {stat.badge}
            </span>
          </div>
        ))}
      </div>

      {/* Enclave Status Bar */}
      <div
        style={{
          marginTop: 32,
          display: 'inline-flex',
          alignItems: 'center',
          gap: 12,
          padding: '8px 16px',
          borderRadius: 999,
          background: 'rgba(6,182,212,0.08)',
          border: '1px solid rgba(6,182,212,0.22)',
          color: '#22d3ee',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          width: 'fit-content',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: '#06b6d4',
              boxShadow: '0 0 8px #06b6d4',
              animation: 'pulse-dot 2s ease-in-out infinite',
            }}
          />
          <span>ENCLAVE OPERATING · ISOLATED</span>
        </div>
        <span style={{ color: 'rgba(255,255,255,0.2)' }}>|</span>
        <span style={{ color: '#a5b4fc', fontSize: 10 }}>99.99% Posture Health</span>
      </div>
    </div>
  )
}

export const LoginPage: React.FC<LoginPageProps> = ({ initialMode = 'login' }) => {
  const navigate = useNavigate()
  const location = useLocation()
  const { login, signup } = useAuth()

  const [mode, setMode] = useState<'login' | 'signup'>(initialMode)

  // Login form state
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showLoginPassword, setShowLoginPassword] = useState(false)

  // Signup form state
  const [signupUsername, setSignupUsername] = useState('')
  const [signupEmail, setSignupEmail] = useState('')
  const [signupPassword, setSignupPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showSignupPassword, setShowSignupPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const signupRole = 'VIEWER'

  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/overview'

  // Password strength calculation
  const passwordStrength = useMemo(() => {
    if (!signupPassword) return { score: 0, label: '', color: '' }
    let score = 0
    if (signupPassword.length >= 8) score += 1
    if (/[A-Z]/.test(signupPassword) && /[a-z]/.test(signupPassword)) score += 1
    if (/[0-9]/.test(signupPassword) || /[^A-Za-z0-9]/.test(signupPassword)) score += 1

    if (score === 1) return { score: 1, label: 'Basic', color: '#f43f5e' }
    if (score === 2) return { score: 2, label: 'Moderate', color: '#f59e0b' }
    return { score: 3, label: 'Strong', color: '#10b981' }
  }, [signupPassword])

  const handleLoginSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('Please provide both username and password.')
      return
    }

    setIsLoading(true)
    setError(null)
    setSuccessMsg(null)

    try {
      await login(username.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || 'Authentication failed. Please verify your credentials.')
      } else {
        setError('Unable to connect to authentication service.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const handleSignupSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!signupUsername.trim() || !signupEmail.trim() || !signupPassword.trim()) {
      setError('All registration fields are required.')
      return
    }

    if (signupPassword.length < 12) {
      setError('Password must be at least 12 characters long.')
      return
    }

    if (confirmPassword && signupPassword !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setIsLoading(true)
    setError(null)
    setSuccessMsg(null)

    try {
      await signup(signupUsername.trim(), signupEmail.trim(), signupPassword, signupRole)
      setSuccessMsg('Account created successfully! Redirecting to command enclave...')
      setTimeout(() => {
        navigate(from, { replace: true })
      }, 600)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || 'Registration failed. User or email might already exist.')
      } else {
        setError('Unable to reach registration server.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const inputGroupStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '11px 14px',
    borderRadius: 12,
    background: 'rgba(10, 14, 25, 0.85)',
    border: '1px solid rgba(255, 255, 255, 0.12)',
    transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
  }

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: 11,
    fontWeight: 700,
    color: 'var(--text-secondary)',
    marginBottom: 6,
    letterSpacing: '0.05em',
  }

  const inputStyle: React.CSSProperties = {
    flex: 1,
    background: 'transparent',
    border: 'none',
    outline: 'none',
    color: '#ffffff',
    fontSize: 13,
    fontFamily: 'var(--font-mono)',
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        width: '100vw',
        display: 'flex',
        position: 'relative',
        overflow: 'auto',
        background: '#080b14',
      }}
    >
      <AnimatedBackground />

      {/* Split layout: 55% Brand panel left + 45% Auth form right */}
      <div
        style={{
          display: 'flex',
          width: '100%',
          minHeight: '100vh',
          position: 'relative',
          zIndex: 10,
        }}
      >
        {/* ═══ LEFT: Brand Information Panel (55% width) ═══ */}
        <div
          className="login-brand-panel"
          style={{
            flex: '0 0 55%',
            width: '55%',
            maxWidth: '55%',
            borderRight: '1px solid rgba(255,255,255,0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 32px',
            position: 'relative',
          }}
        >
          <BrandPanel />
        </div>

        {/* ═══ RIGHT: Auth Form Panel (45% width, centered cute card) ═══ */}
        <div
          className="login-form-panel"
          style={{
            flex: '0 0 45%',
            width: '45%',
            maxWidth: '45%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 32px',
            background: 'radial-gradient(ellipse at center, rgba(14, 18, 40, 0.45) 0%, rgba(8, 11, 22, 0.7) 100%)',
            backdropFilter: 'blur(24px)',
            WebkitBackdropFilter: 'blur(24px)',
            position: 'relative',
          }}
        >
          {/* ── Glassmorphic Card (Cute Box) ── */}
          <div
            className="login-card login-shimmer"
            style={{
              width: '100%',
              maxWidth: 420,
              position: 'relative',
              borderRadius: 24,
              padding: '36px 32px',
              background: 'linear-gradient(145deg, rgba(14,18,38,0.95) 0%, rgba(10,13,28,0.98) 100%)',
              boxShadow:
                '0 32px 64px rgba(0,0,0,0.55),' +
                '0 0 0 1px rgba(99,102,241,0.2),' +
                '0 0 80px rgba(99,102,241,0.08) inset',
              overflow: 'visible',
            }}
          >
            {/* Gradient border glow */}
            <div
              className="login-border-glow"
              style={{
                position: 'absolute',
                inset: -1,
                borderRadius: 25,
                background: 'linear-gradient(135deg, rgba(99,102,241,0.5) 0%, rgba(6,182,212,0.3) 50%, rgba(139,92,246,0.4) 100%)',
                zIndex: -1,
                filter: 'blur(1px)',
              }}
            />
            {/* Inner dark fill to make border visible */}
            <div
              style={{
                position: 'absolute',
                inset: 1,
                borderRadius: 23,
                background: 'linear-gradient(145deg, rgba(14,18,36,0.98) 0%, rgba(10,13,28,1) 100%)',
                zIndex: -1,
              }}
            />

            {/* Top accent line */}
            <div style={{
              position: 'absolute',
              top: 0, left: '15%', right: '15%',
              height: 2,
              borderRadius: '0 0 4px 4px',
              background: 'linear-gradient(90deg, transparent, rgba(99,102,241,0.8), rgba(6,182,212,0.6), transparent)',
              filter: 'blur(0.5px)',
            }} />

          {/* Form content (same as before, indented into card) */}
          <div style={{ width: '100%' }}>
            {/* Mobile-only logo (hidden on desktop via class) */}
            <div className="login-mobile-logo" style={{ marginBottom: 28, textAlign: 'center' }}>
              <CloudGuardLogo variant="full" size={38} style={{ justifyContent: 'center' }} />
            </div>

            {/* Mode switcher */}
            <div
              style={{
                display: 'flex',
                padding: 4,
                borderRadius: 12,
                background: 'rgba(10, 14, 25, 0.9)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                marginBottom: 28,
              }}
            >
              <button
                type="button"
                id="auth-tab-signin"
                onClick={() => { setMode('login'); setError(null); setSuccessMsg(null) }}
                style={{
                  flex: 1,
                  padding: '10px 0',
                  borderRadius: 9,
                  border: 'none',
                  background: mode === 'login' ? 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)' : 'transparent',
                  color: mode === 'login' ? '#ffffff' : 'var(--text-muted)',
                  fontWeight: 700,
                  fontSize: 12,
                  cursor: 'pointer',
                  letterSpacing: '0.04em',
                  boxShadow: mode === 'login' ? '0 4px 14px rgba(99, 102, 241, 0.35)' : 'none',
                  transition: 'all 0.2s ease',
                }}
              >
                Sign In
              </button>
              <button
                type="button"
                id="auth-tab-register"
                onClick={() => { setMode('signup'); setError(null); setSuccessMsg(null) }}
                style={{
                  flex: 1,
                  padding: '10px 0',
                  borderRadius: 9,
                  border: 'none',
                  background: mode === 'signup' ? 'linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)' : 'transparent',
                  color: mode === 'signup' ? '#ffffff' : 'var(--text-muted)',
                  fontWeight: 700,
                  fontSize: 12,
                  cursor: 'pointer',
                  letterSpacing: '0.04em',
                  boxShadow: mode === 'signup' ? '0 4px 14px rgba(6, 182, 212, 0.35)' : 'none',
                  transition: 'all 0.2s ease',
                }}
              >
                Create Account
              </button>
            </div>

            {/* Heading */}
            <div style={{ marginBottom: 24 }}>
              <h2
                style={{
                  fontSize: 20,
                  fontWeight: 800,
                  color: '#ffffff',
                  letterSpacing: '-0.01em',
                  margin: '0 0 4px 0',
                }}
              >
                {mode === 'login' ? 'Welcome back' : 'Create account'}
              </h2>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                {mode === 'login'
                  ? 'Authenticate to access your security enclave'
                  : 'Register for read-only posture access'}
              </p>
            </div>

            {/* Status Alerts */}
            {error && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 8,
                  padding: '10px 14px',
                  borderRadius: 10,
                  background: 'rgba(244, 63, 94, 0.12)',
                  border: '1px solid rgba(244, 63, 94, 0.32)',
                  color: '#f43f5e',
                  fontSize: 12,
                  marginBottom: 20,
                  lineHeight: 1.4,
                }}
                role="alert"
              >
                <AlertCircle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '10px 14px',
                  borderRadius: 10,
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.32)',
                  color: '#10b981',
                  fontSize: 12,
                  marginBottom: 20,
                }}
                role="status"
              >
                <CheckCircle2 size={15} style={{ flexShrink: 0 }} />
                <span>{successMsg}</span>
              </div>
            )}

            {/* ═══ SIGN IN FORM ═══ */}
            {mode === 'login' ? (
              <form id="login-form" onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div>
                  <label htmlFor="login-username" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#6366f1', marginRight: 6, verticalAlign: 'middle' }} />
                    OPERATOR USERNAME
                  </label>
                  <div className="cute-input-group" style={inputGroupStyle}>
                    <UserIcon size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="login-username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Username"
                      disabled={isLoading}
                      autoComplete="username"
                      style={inputStyle}
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="login-password" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#06b6d4', marginRight: 6, verticalAlign: 'middle' }} />
                    SECURITY PASSWORD
                  </label>
                  <div className="cute-input-group" style={inputGroupStyle}>
                    <Lock size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="login-password"
                      type={showLoginPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      disabled={isLoading}
                      autoComplete="current-password"
                      style={inputStyle}
                    />
                    <button
                      type="button"
                      onClick={() => setShowLoginPassword(!showLoginPassword)}
                      style={{ background: 'transparent', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
                      title={showLoginPassword ? 'Hide password' : 'Show password'}
                    >
                      {showLoginPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>

                <button
                  id="login-submit"
                  type="submit"
                  className="cute-btn"
                  disabled={isLoading}
                  style={{
                    marginTop: 4,
                    padding: '13px 20px',
                    borderRadius: 12,
                    border: 'none',
                    background: isLoading
                      ? 'rgba(99,102,241,0.5)'
                      : 'linear-gradient(135deg, #6366f1 0%, #4f46e5 60%, #06b6d4 100%)',
                    color: '#ffffff',
                    fontSize: 13,
                    fontWeight: 700,
                    cursor: isLoading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                    boxShadow: isLoading ? 'none' : '0 8px 28px rgba(99, 102, 241, 0.4)',
                    letterSpacing: '0.04em',
                  }}
                >
                  <KeyRound size={15} />
                  <span>{isLoading ? 'AUTHENTICATING...' : 'AUTHENTICATE SESSION'}</span>
                  {!isLoading && <ArrowRight size={14} />}
                </button>


                <div style={{ textAlign: 'center', marginTop: 4 }}>
                  <button
                    type="button"
                    onClick={() => { setMode('signup'); setError(null); setSuccessMsg(null) }}
                    style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
                  >
                    Don't have an enclave account? Register here
                  </button>
                </div>
              </form>
            ) : (
              /* ═══ SIGN UP FORM ═══ */
              <form id="signup-form" onSubmit={handleSignupSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div>
                  <label htmlFor="signup-username" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#6366f1', marginRight: 6, verticalAlign: 'middle' }} />
                    OPERATOR USERNAME
                  </label>
                  <div className="cute-input-group" style={inputGroupStyle}>
                    <UserIcon size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="signup-username"
                      type="text"
                      value={signupUsername}
                      onChange={(e) => setSignupUsername(e.target.value)}
                      placeholder="e.g. security_lead"
                      disabled={isLoading}
                      autoComplete="username"
                      style={inputStyle}
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="signup-email" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#06b6d4', marginRight: 6, verticalAlign: 'middle' }} />
                    WORK EMAIL
                  </label>
                  <div className="cute-input-group" style={inputGroupStyle}>
                    <Mail size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="signup-email"
                      type="email"
                      value={signupEmail}
                      onChange={(e) => setSignupEmail(e.target.value)}
                      placeholder="officer@defense.cloud"
                      disabled={isLoading}
                      autoComplete="email"
                      style={inputStyle}
                    />
                  </div>
                </div>

                {/* Provisioned Role Badge */}
                <div>
                  <label style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#8b5cf6', marginRight: 6, verticalAlign: 'middle' }} />
                    PROVISIONED ROLE
                  </label>
                  <div
                    style={{
                      padding: '10px 14px',
                      borderRadius: 12,
                      background: 'rgba(10, 14, 25, 0.8)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8' }}>
                      VIEWER (Security Auditor / Read-Only Posture)
                    </span>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(255,255,255,0.06)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        fontSize: 10,
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-muted)',
                      }}
                    >
                      DEFAULT
                    </span>
                  </div>
                  <p style={{ fontSize: 10, color: 'var(--text-disabled)', marginTop: 4 }}>
                    Elevated roles require administrator assignment.
                  </p>
                </div>

                <div>
                  <label htmlFor="signup-password" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#ec4899', marginRight: 6, verticalAlign: 'middle' }} />
                    SECURE PASSWORD
                  </label>
                  <div className="cute-input-group" style={inputGroupStyle}>
                    <Lock size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="signup-password"
                      type={showSignupPassword ? 'text' : 'password'}
                      value={signupPassword}
                      onChange={(e) => setSignupPassword(e.target.value)}
                      placeholder="Min 12 characters"
                      disabled={isLoading}
                      autoComplete="new-password"
                      style={inputStyle}
                    />
                    <button
                      type="button"
                      onClick={() => setShowSignupPassword(!showSignupPassword)}
                      style={{ background: 'transparent', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
                      title={showSignupPassword ? 'Hide password' : 'Show password'}
                    >
                      {showSignupPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                  {signupPassword.length > 0 && (
                    <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ display: 'flex', gap: 4, flex: 1 }}>
                        {[1, 2, 3].map((level) => (
                          <div
                            key={level}
                            style={{
                              height: 3,
                              flex: 1,
                              borderRadius: 2,
                              backgroundColor: passwordStrength.score >= level ? passwordStrength.color : 'rgba(255, 255, 255, 0.1)',
                              transition: 'background-color 0.25s ease',
                            }}
                          />
                        ))}
                      </div>
                      <span style={{ fontSize: 10, color: passwordStrength.color, fontWeight: 700, minWidth: 48 }}>
                        {passwordStrength.label}
                      </span>
                    </div>
                  )}
                </div>

                <div>
                  <label htmlFor="signup-confirm" style={labelStyle}>
                    <span style={{ display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#10b981', marginRight: 6, verticalAlign: 'middle' }} />
                    CONFIRM PASSWORD
                  </label>
                  <div
                    className="cute-input-group"
                    style={{
                      ...inputGroupStyle,
                      borderColor: confirmPassword && confirmPassword !== signupPassword
                        ? 'rgba(244, 63, 94, 0.45)'
                        : 'rgba(255, 255, 255, 0.12)',
                    }}
                  >
                    <Lock size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      id="signup-confirm"
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Confirm password"
                      disabled={isLoading}
                      autoComplete="new-password"
                      style={inputStyle}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      style={{ background: 'transparent', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
                      title={showConfirmPassword ? 'Hide password' : 'Show password'}
                    >
                      {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>

                <button
                  id="signup-submit"
                  type="submit"
                  className="cute-btn"
                  disabled={isLoading}
                  style={{
                    marginTop: 4,
                    padding: '13px 20px',
                    borderRadius: 12,
                    border: 'none',
                    background: isLoading
                      ? 'rgba(6,182,212,0.4)'
                      : 'linear-gradient(135deg, #06b6d4 0%, #0891b2 60%, #10b981 100%)',
                    color: '#ffffff',
                    fontSize: 13,
                    fontWeight: 700,
                    cursor: isLoading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                    boxShadow: isLoading ? 'none' : '0 8px 28px rgba(6, 182, 212, 0.35)',
                    letterSpacing: '0.04em',
                  }}
                >
                  <CheckCircle2 size={16} />
                  <span>{isLoading ? 'CREATING ACCOUNT...' : 'REGISTER VERIFIED ACCOUNT'}</span>
                </button>

                <div style={{ textAlign: 'center' }}>
                  <button
                    type="button"
                    onClick={() => { setMode('login'); setError(null); setSuccessMsg(null) }}
                    style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
                  >
                    Already have credentials? Sign In
                  </button>
                </div>
              </form>
            )}

            {/* Security Footer */}
            <div
              style={{
                marginTop: 26,
                paddingTop: 16,
                borderTop: '1px solid rgba(255, 255, 255, 0.07)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: 10,
                color: 'var(--text-disabled)',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '0.03em',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ color: '#10b981' }}>🛡️</span>
                <span>Argon2id Protected</span>
              </div>
              <span style={{ color: '#06b6d4', fontWeight: 600 }}>SESSION ISOLATED</span>
            </div>
            </div>
          </div>{/* end glassmorphic card */}
        </div>{/* end form panel */}
      </div>{/* end split layout */}

      {/* Responsive CSS */}
      <style>{`
        .login-mobile-logo { display: none; }
        @media (max-width: 1024px) {
          .login-brand-panel { display: none !important; }
          .login-form-panel {
            flex: 1 1 100% !important;
            width: 100% !important;
            max-width: 100% !important;
            padding: 32px 20px !important;
          }
          .login-mobile-logo { display: block; }
        }
      `}</style>
    </div>
  )
}
