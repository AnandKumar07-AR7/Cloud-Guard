/**
 * PageBackground — Live 3D animated background for each CloudGuard module.
 * Uses pure CSS transforms with perspective for authentic 3D depth.
 * All animations respect prefers-reduced-motion.
 */
import React, { useMemo } from 'react'
import { useLocation } from 'react-router-dom'

/* ─── Module → variant mapping ───────────────────────────── */
type BgVariant =
  | 'overview'       // Indigo + Blue  — command center hex grid
  | 'posture'        // Teal + Cyan    — concentric rings
  | 'activity'       // Electric blue  — radar pulses
  | 'discover'       // Azure + Violet — cloud constellation
  | 'security'       // Crimson + Org  — threat matrix
  | 'intelligence'   // Magenta + Viol — neural nodes
  | 'remediation'    // Emerald + Green— healing lattice
  | 'compliance'     // Amber + Gold   — shield grid
  | 'operations'     // Orange + Amber — scanner rings
  | 'system'         // Slate + Pink   — circuit board

function getVariant(pathname: string): BgVariant {
  const p = pathname.toLowerCase().replace(/^\//, '')
  if (!p || p === 'overview') return 'overview'
  if (p === 'posture') return 'posture'
  if (p === 'activity') return 'activity'
  if (p.startsWith('asset') || p.startsWith('account') || p.startsWith('resource')) return 'discover'
  if (p.startsWith('finding') || p.startsWith('rules') || p.startsWith('risk') || p.startsWith('attack')) return 'security'
  if (p.startsWith('ai') || p.startsWith('orchestrat') || p.startsWith('agent') || p.startsWith('runs')) return 'intelligence'
  if (p.startsWith('remedi') || p.startsWith('approv') || p.startsWith('execut') || p.startsWith('verif')) return 'remediation'
  if (p.startsWith('compliance')) return 'compliance'
  if (p.startsWith('scan') || p.startsWith('audit') || p.startsWith('report')) return 'operations'
  if (p.startsWith('mcp') || p.startsWith('polic') || p.startsWith('automat') || p.startsWith('setting')) return 'system'
  return 'overview'
}

/* ─── Theme palette for each variant ─────────────────────── */
interface Theme {
  base: string       // radial gradient base (rich + deep, NOT transparent)
  orb1: string
  orb2: string
  orb3: string
  shape: string      // primary 3D shape color
  shapeAlt: string   // secondary shape color
  gridColor: string  // grid line color
  accent: string     // bright accent for animations
}

const THEMES: Record<BgVariant, Theme> = {
  overview: {
    base: 'radial-gradient(ellipse 80% 55% at 20% 0%, rgba(99,102,241,0.28) 0%, transparent 65%),' +
          'radial-gradient(ellipse 60% 40% at 80% 85%, rgba(6,182,212,0.2) 0%, transparent 55%),' +
          'linear-gradient(180deg, #060a18 0%, #080d22 100%)',
    orb1: 'rgba(99,102,241,0.35)', orb2: 'rgba(6,182,212,0.22)', orb3: 'rgba(139,92,246,0.18)',
    shape: 'rgba(99,102,241,0.55)', shapeAlt: 'rgba(6,182,212,0.4)',
    gridColor: 'rgba(99,102,241,0.12)', accent: '#818cf8',
  },
  posture: {
    base: 'radial-gradient(ellipse 70% 60% at 15% 10%, rgba(6,182,212,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 45% at 85% 80%, rgba(20,184,166,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #041614 0%, #061a1a 100%)',
    orb1: 'rgba(6,182,212,0.35)', orb2: 'rgba(20,184,166,0.28)', orb3: 'rgba(34,211,238,0.18)',
    shape: 'rgba(6,182,212,0.55)', shapeAlt: 'rgba(20,184,166,0.45)',
    gridColor: 'rgba(6,182,212,0.12)', accent: '#22d3ee',
  },
  activity: {
    base: 'radial-gradient(ellipse 75% 60% at 50% 50%, rgba(59,130,246,0.3) 0%, transparent 65%),' +
          'radial-gradient(ellipse 50% 40% at 10% 80%, rgba(139,92,246,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #050a1e 0%, #080f28 100%)',
    orb1: 'rgba(59,130,246,0.38)', orb2: 'rgba(139,92,246,0.28)', orb3: 'rgba(96,165,250,0.2)',
    shape: 'rgba(96,165,250,0.55)', shapeAlt: 'rgba(139,92,246,0.45)',
    gridColor: 'rgba(59,130,246,0.14)', accent: '#60a5fa',
  },
  discover: {
    base: 'radial-gradient(ellipse 75% 55% at 25% 15%, rgba(167,139,250,0.26) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 45% at 75% 80%, rgba(96,165,250,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #07060f 0%, #0b0d1e 100%)',
    orb1: 'rgba(167,139,250,0.35)', orb2: 'rgba(96,165,250,0.28)', orb3: 'rgba(192,132,252,0.2)',
    shape: 'rgba(167,139,250,0.55)', shapeAlt: 'rgba(96,165,250,0.45)',
    gridColor: 'rgba(167,139,250,0.12)', accent: '#a78bfa',
  },
  security: {
    base: 'radial-gradient(ellipse 70% 55% at 20% 10%, rgba(239,68,68,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 45% at 80% 80%, rgba(249,115,22,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #120408 0%, #180608 100%)',
    orb1: 'rgba(239,68,68,0.38)', orb2: 'rgba(249,115,22,0.28)', orb3: 'rgba(251,146,60,0.2)',
    shape: 'rgba(239,68,68,0.55)', shapeAlt: 'rgba(249,115,22,0.45)',
    gridColor: 'rgba(239,68,68,0.12)', accent: '#fb7185',
  },
  intelligence: {
    base: 'radial-gradient(ellipse 72% 56% at 30% 10%, rgba(192,132,252,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 42% at 75% 85%, rgba(244,114,182,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #0d0614 0%, #120a1e 100%)',
    orb1: 'rgba(192,132,252,0.38)', orb2: 'rgba(244,114,182,0.28)', orb3: 'rgba(167,139,250,0.22)',
    shape: 'rgba(192,132,252,0.55)', shapeAlt: 'rgba(244,114,182,0.45)',
    gridColor: 'rgba(192,132,252,0.12)', accent: '#c084fc',
  },
  remediation: {
    base: 'radial-gradient(ellipse 70% 55% at 20% 15%, rgba(16,185,129,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 42% at 80% 80%, rgba(52,211,153,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #030f08 0%, #051410 100%)',
    orb1: 'rgba(16,185,129,0.38)', orb2: 'rgba(52,211,153,0.28)', orb3: 'rgba(110,231,183,0.2)',
    shape: 'rgba(16,185,129,0.55)', shapeAlt: 'rgba(52,211,153,0.45)',
    gridColor: 'rgba(16,185,129,0.12)', accent: '#34d399',
  },
  compliance: {
    base: 'radial-gradient(ellipse 70% 55% at 25% 10%, rgba(245,158,11,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 42% at 78% 82%, rgba(251,191,36,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #110b02 0%, #160f03 100%)',
    orb1: 'rgba(245,158,11,0.38)', orb2: 'rgba(251,191,36,0.28)', orb3: 'rgba(253,224,71,0.2)',
    shape: 'rgba(245,158,11,0.55)', shapeAlt: 'rgba(251,191,36,0.45)',
    gridColor: 'rgba(245,158,11,0.12)', accent: '#fbbf24',
  },
  operations: {
    base: 'radial-gradient(ellipse 70% 55% at 20% 15%, rgba(249,115,22,0.28) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 42% at 80% 80%, rgba(245,158,11,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #0f0700 0%, #150a02 100%)',
    orb1: 'rgba(249,115,22,0.38)', orb2: 'rgba(245,158,11,0.28)', orb3: 'rgba(251,146,60,0.22)',
    shape: 'rgba(249,115,22,0.55)', shapeAlt: 'rgba(245,158,11,0.45)',
    gridColor: 'rgba(249,115,22,0.12)', accent: '#fb923c',
  },
  system: {
    base: 'radial-gradient(ellipse 70% 55% at 20% 10%, rgba(244,114,182,0.24) 0%, transparent 60%),' +
          'radial-gradient(ellipse 55% 42% at 80% 80%, rgba(99,102,241,0.22) 0%, transparent 55%),' +
          'linear-gradient(180deg, #0a0510 0%, #0c071a 100%)',
    orb1: 'rgba(244,114,182,0.35)', orb2: 'rgba(99,102,241,0.28)', orb3: 'rgba(216,180,254,0.2)',
    shape: 'rgba(244,114,182,0.52)', shapeAlt: 'rgba(99,102,241,0.45)',
    gridColor: 'rgba(244,114,182,0.12)', accent: '#f472b6',
  },
}

/* ─── Global keyframe styles (injected once) ─────────────── */
const BG_KEYFRAMES = `
  @keyframes bg-orb-a { 0%,100%{transform:translate(0,0) scale(1)} 33%{transform:translate(40px,-28px) scale(1.07)} 66%{transform:translate(-25px,18px) scale(0.94)} }
  @keyframes bg-orb-b { 0%,100%{transform:translate(0,0) scale(1)} 40%{transform:translate(-35px,-25px) scale(1.09)} 72%{transform:translate(20px,22px) scale(0.92)} }
  @keyframes bg-orb-c { 0%,100%{transform:translate(-50%,-50%) scale(1)} 50%{transform:translate(-50%,-58%) scale(1.12)} }

  @keyframes bg-cube-spin  { from{transform:rotateX(0deg) rotateY(0deg) rotateZ(0deg)} to{transform:rotateX(360deg) rotateY(240deg) rotateZ(120deg)} }
  @keyframes bg-cube-spin2 { from{transform:rotateX(45deg) rotateY(180deg) rotateZ(0deg)} to{transform:rotateX(405deg) rotateY(540deg) rotateZ(360deg)} }
  @keyframes bg-cube-spin3 { from{transform:rotateX(20deg) rotateY(60deg) rotateZ(30deg)} to{transform:rotateX(380deg) rotateY(300deg) rotateZ(390deg)} }

  @keyframes bg-ring-rot  { from{transform:rotateX(70deg) rotateZ(0deg)} to{transform:rotateX(70deg) rotateZ(360deg)} }
  @keyframes bg-ring-rot2 { from{transform:rotateX(50deg) rotateZ(180deg)} to{transform:rotateX(50deg) rotateZ(540deg)} }
  @keyframes bg-ring-rot3 { from{transform:rotateX(80deg) rotateZ(30deg)} to{transform:rotateX(80deg) rotateZ(390deg)} }

  @keyframes bg-hex-drift { 0%,100%{transform:translateY(0px) rotate(0deg)} 50%{transform:translateY(-20px) rotate(180deg)} }
  @keyframes bg-hex-drift2{ 0%,100%{transform:translateY(0px) rotate(30deg)} 50%{transform:translateY(-28px) rotate(210deg)} }
  @keyframes bg-hex-drift3{ 0%,100%{transform:translateY(0px) rotate(60deg)} 50%{transform:translateY(-15px) rotate(250deg)} }

  @keyframes bg-pulse-ring { 0%,100%{transform:scale(1);opacity:0.7} 50%{transform:scale(1.18);opacity:0.35} }
  @keyframes bg-pulse-ring2{ 0%,100%{transform:scale(1);opacity:0.5} 50%{transform:scale(1.25);opacity:0.2} }

  @keyframes bg-node-pulse { 0%,100%{opacity:0.5;transform:scale(1)} 50%{opacity:1;transform:scale(1.5)} }
  @keyframes bg-circuit-flow { 0%{stroke-dashoffset:200} 100%{stroke-dashoffset:0} }
  @keyframes bg-scanline { 0%{top:-2px;opacity:0} 5%{opacity:1} 95%{opacity:1} 100%{top:100%;opacity:0} }
  @keyframes bg-radar-sweep { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
  @keyframes bg-float-y { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-24px)} }

  @media (prefers-reduced-motion: reduce) {
    [class^="cg-bg-"] { animation: none !important; }
  }
`

/* ─── 3D Floating Cubes ───────────────────────────────────── */
const FloatingCubes: React.FC<{ color: string; altColor: string }> = ({ color, altColor }) => {
  const cubes = [
    { size: 60, top: '12%', left: '8%',  duration: '18s', delay: '0s',   anim: 'bg-cube-spin'  },
    { size: 40, top: '65%', left: '82%', duration: '24s', delay: '-6s',  anim: 'bg-cube-spin2' },
    { size: 50, top: '40%', left: '88%', duration: '20s', delay: '-12s', anim: 'bg-cube-spin3' },
    { size: 30, top: '80%', left: '20%', duration: '16s', delay: '-4s',  anim: 'bg-cube-spin'  },
    { size: 45, top: '20%', left: '70%', duration: '22s', delay: '-8s',  anim: 'bg-cube-spin2' },
  ]
  return (
    <>
      {cubes.map((c, i) => (
        <div
          key={i}
          style={{
            position: 'absolute',
            top: c.top,
            left: c.left,
            width: c.size,
            height: c.size,
            transformStyle: 'preserve-3d',
            animation: `${c.anim} ${c.duration} linear infinite ${c.delay}`,
            perspective: 400,
          }}
        >
          {/* 6 faces of a cube */}
          {[
            { transform: `translateZ(${c.size / 2}px)`, bg: i % 2 === 0 ? color : altColor },
            { transform: `translateZ(-${c.size / 2}px)`, bg: altColor },
            { transform: `rotateY(90deg) translateZ(${c.size / 2}px)`, bg: color },
            { transform: `rotateY(-90deg) translateZ(${c.size / 2}px)`, bg: altColor },
            { transform: `rotateX(90deg) translateZ(${c.size / 2}px)`, bg: color },
            { transform: `rotateX(-90deg) translateZ(${c.size / 2}px)`, bg: altColor },
          ].map((face, fi) => (
            <div
              key={fi}
              style={{
                position: 'absolute',
                width: c.size,
                height: c.size,
                background: face.bg,
                border: `1px solid ${color.replace('0.55', '0.8')}`,
                transform: face.transform,
                backdropFilter: 'blur(1px)',
              }}
            />
          ))}
        </div>
      ))}
    </>
  )
}

/* ─── Concentric 3D Rings ─────────────────────────────────── */
const ConcentricRings: React.FC<{ color: string; altColor: string; cx: string; cy: string }> = ({ color, altColor, cx, cy }) => {
  const rings = [
    { size: 180, duration: '12s', delay: '0s',   anim: 'bg-ring-rot',  c: color    },
    { size: 280, duration: '18s', delay: '-4s',  anim: 'bg-ring-rot2', c: altColor },
    { size: 380, duration: '24s', delay: '-8s',  anim: 'bg-ring-rot',  c: color    },
    { size: 480, duration: '30s', delay: '-12s', anim: 'bg-ring-rot2', c: altColor },
  ]
  return (
    <>
      {rings.map((r, i) => (
        <div
          key={i}
          style={{
            position: 'absolute',
            top: cy,
            left: cx,
            width: r.size,
            height: r.size,
            marginLeft: -r.size / 2,
            marginTop: -r.size / 2,
            borderRadius: '50%',
            border: `1.5px solid ${r.c}`,
            animation: `${r.anim} ${r.duration} linear infinite ${r.delay}`,
            transformStyle: 'preserve-3d',
          }}
        />
      ))}
    </>
  )
}

/* ─── Hexagon Field ───────────────────────────────────────── */
const HexField: React.FC<{ color: string; altColor: string }> = ({ color, altColor }) => {
  const hexes = [
    { size: 80, top: '10%', left: '5%',  duration: '14s', delay: '0s',   anim: 'bg-hex-drift'  },
    { size: 55, top: '70%', left: '85%', duration: '18s', delay: '-5s',  anim: 'bg-hex-drift2' },
    { size: 65, top: '45%', left: '90%', duration: '16s', delay: '-10s', anim: 'bg-hex-drift3' },
    { size: 45, top: '85%', left: '15%', duration: '12s', delay: '-3s',  anim: 'bg-hex-drift'  },
    { size: 70, top: '25%', left: '75%', duration: '20s', delay: '-7s',  anim: 'bg-hex-drift2' },
  ]
  const HEX = (sz: number, c: string) => {
    const w = sz, h = sz * 0.866
    const pts = [
      [w * 0.5, 0], [w, h * 0.25], [w, h * 0.75],
      [w * 0.5, h], [0, h * 0.75], [0, h * 0.25]
    ].map(([x, y]) => `${x},${y}`).join(' ')
    return (
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
        <polygon points={pts} fill="none" stroke={c} strokeWidth="1.5" />
      </svg>
    )
  }
  return (
    <>
      {hexes.map((h, i) => (
        <div
          key={i}
          style={{
            position: 'absolute',
            top: h.top,
            left: h.left,
            animation: `${h.anim} ${h.duration} ease-in-out infinite ${h.delay}`,
            opacity: 0.7,
          }}
        >
          {HEX(h.size, i % 2 === 0 ? color : altColor)}
        </div>
      ))}
    </>
  )
}

/* ─── Neural Nodes (Intelligence) ────────────────────────── */
const NeuralNodes: React.FC<{ color: string }> = ({ color }) => {
  const nodes = [
    { x: '15%', y: '20%' }, { x: '40%', y: '35%' }, { x: '70%', y: '15%' },
    { x: '85%', y: '50%' }, { x: '60%', y: '70%' }, { x: '25%', y: '75%' },
    { x: '50%', y: '55%' }, { x: '80%', y: '80%' },
  ]
  const connections = [
    [0,1],[1,2],[1,6],[2,3],[3,4],[4,5],[4,6],[6,7],[5,6],[3,7]
  ]
  return (
    <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', overflow: 'visible' }}>
      {connections.map(([a, b], i) => (
        <line key={i}
          x1={nodes[a].x} y1={nodes[a].y}
          x2={nodes[b].x} y2={nodes[b].y}
          stroke={color.replace('0.55', '0.25')} strokeWidth="1"
          strokeDasharray="6 4"
        >
          <animate attributeName="stroke-opacity" values="0.15;0.5;0.15" dur={`${3 + i * 0.5}s`} repeatCount="indefinite" />
        </line>
      ))}
      {nodes.map((n, i) => (
        <circle key={i} cx={n.x} cy={n.y} r="5" fill={color.replace('0.55', '0.6')}>
          <animate attributeName="r" values="4;7;4" dur={`${2 + (i % 4) * 0.7}s`} begin={`${i * 0.4}s`} repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.5;1;0.5" dur={`${2 + (i % 4) * 0.7}s`} begin={`${i * 0.4}s`} repeatCount="indefinite" />
        </circle>
      ))}
    </svg>
  )
}

/* ─── Radar Sweep (Operations) ───────────────────────────── */
const RadarSweep: React.FC<{ color: string }> = ({ color }) => {
  const c = color.replace('0.55', '0.6')
  return (
    <div style={{ position: 'absolute', top: '50%', left: '60%', transform: 'translate(-50%,-50%)' }}>
      {[120, 200, 280, 360].map((sz, i) => (
        <div key={i} style={{
          position: 'absolute', top: '50%', left: '50%',
          width: sz, height: sz,
          marginLeft: -sz / 2, marginTop: -sz / 2,
          borderRadius: '50%',
          border: `1px solid ${color.replace('0.55', '0.2')}`,
          animation: `bg-pulse-ring ${4 + i}s ease-in-out infinite ${i * 0.8}s`,
        }} />
      ))}
      <div style={{
        position: 'absolute', top: '50%', left: '50%',
        width: 360, height: 360,
        marginLeft: -180, marginTop: -180,
        animation: 'bg-radar-sweep 6s linear infinite',
        transformOrigin: '180px 180px',
        overflow: 'hidden', borderRadius: '50%',
      }}>
        <div style={{
          position: 'absolute', top: 0, left: '50%',
          width: 180, height: 180,
          background: `conic-gradient(from 0deg, transparent 0deg, ${color.replace('0.55', '0.15')} 45deg, transparent 46deg)`,
          transformOrigin: '0 100%',
        }} />
      </div>
    </div>
  )
}

/* ─── Circuit Traces (System) ────────────────────────────── */
const CircuitTraces: React.FC<{ color: string }> = ({ color }) => {
  const stroke = color.replace('0.52', '0.35')
  const paths = [
    'M 50 100 L 200 100 L 200 180 L 350 180',
    'M 100 50 L 100 200 L 250 200 L 250 300',
    'M 400 80 L 550 80 L 550 200 L 700 200',
    'M 600 50 L 600 150 L 750 150 L 750 250',
    'M 150 350 L 300 350 L 300 450 L 500 450',
    'M 50 280 L 180 280 L 180 400',
  ]
  return (
    <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '80%', opacity: 0.55 }}>
      {paths.map((d, i) => (
        <g key={i}>
          <path d={d} fill="none" stroke={stroke} strokeWidth="1.5" />
          <circle cx={d.match(/L (\d+) (\d+)$/)![1]} cy={d.match(/L (\d+) (\d+)$/)![2]} r="3" fill={stroke}>
            <animate attributeName="opacity" values="0.3;1;0.3" dur={`${2 + i * 0.6}s`} begin={`${i * 0.3}s`} repeatCount="indefinite" />
          </circle>
        </g>
      ))}
    </svg>
  )
}



/* ─── Main PageBackground Component ─────────────────────── */
export const PageBackground: React.FC = () => {
  const { pathname } = useLocation()
  const variant = useMemo(() => getVariant(pathname), [pathname])
  const t = THEMES[variant]

  return (
    <>
      {/* Inject keyframes once */}
      <style>{BG_KEYFRAMES}</style>

      {/* Fixed background layer — sits behind everything */}
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 0,
          overflow: 'hidden',
          pointerEvents: 'none',
        }}
      >
        {/* ── Base gradient ── */}
        <div style={{ position: 'absolute', inset: 0, background: t.base }} />

        {/* ── Subtle grid mesh ── */}
        <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 1 }} xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id={`grid-${variant}`} width="52" height="52" patternUnits="userSpaceOnUse">
              <path d="M 52 0 L 0 0 0 52" fill="none" stroke={t.gridColor} strokeWidth="0.75" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill={`url(#grid-${variant})`} />
        </svg>

        {/* ── Orb 1 — top-left ── */}
        <div style={{
          position: 'absolute', top: '5%', left: '3%',
          width: 520, height: 520, borderRadius: '50%',
          background: `radial-gradient(circle, ${t.orb1} 0%, transparent 70%)`,
          filter: 'blur(70px)',
          animation: 'bg-orb-a 14s ease-in-out infinite',
        }} />

        {/* ── Orb 2 — bottom-right ── */}
        <div style={{
          position: 'absolute', bottom: '5%', right: '3%',
          width: 600, height: 600, borderRadius: '50%',
          background: `radial-gradient(circle, ${t.orb2} 0%, transparent 70%)`,
          filter: 'blur(80px)',
          animation: 'bg-orb-b 18s ease-in-out infinite',
        }} />

        {/* ── Orb 3 — center accent ── */}
        <div style={{
          position: 'absolute', top: '50%', left: '50%',
          width: 350, height: 350,
          transform: 'translate(-50%,-50%)',
          borderRadius: '50%',
          background: `radial-gradient(circle, ${t.orb3} 0%, transparent 70%)`,
          filter: 'blur(55px)',
          animation: 'bg-orb-c 11s ease-in-out infinite',
        }} />

        {/* ── Module-specific 3D elements ── */}
        <div style={{ position: 'absolute', inset: 0, perspective: '800px', perspectiveOrigin: '50% 50%', transformStyle: 'preserve-3d' }}>
          {(variant === 'overview' || variant === 'discover' || variant === 'compliance') && (
            <FloatingCubes color={t.shape} altColor={t.shapeAlt} />
          )}
          {(variant === 'posture' || variant === 'activity' || variant === 'security') && (
            <>
              <ConcentricRings color={t.shape} altColor={t.shapeAlt} cx="70%" cy="45%" />
              <ConcentricRings color={t.shapeAlt} altColor={t.shape} cx="20%" cy="70%" />
            </>
          )}
          {(variant === 'remediation') && (
            <>
              <HexField color={t.shape} altColor={t.shapeAlt} />
              <ConcentricRings color={t.shape} altColor={t.shapeAlt} cx="75%" cy="35%" />
            </>
          )}
          {variant === 'intelligence' && (
            <NeuralNodes color={t.shape} />
          )}
          {variant === 'operations' && (
            <RadarSweep color={t.shape} />
          )}
          {variant === 'system' && (
            <>
              <CircuitTraces color={t.shape} />
              <HexField color={t.shape} altColor={t.shapeAlt} />
            </>
          )}
        </div>

        {/* ── Hex field for activity/posture depth ── */}
        {(variant === 'activity' || variant === 'posture') && (
          <HexField color={t.shape} altColor={t.shapeAlt} />
        )}

        {/* ── Top vignette — keeps header readable ── */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 120,
          background: 'linear-gradient(180deg, rgba(0,0,0,0.45) 0%, transparent 100%)',
          pointerEvents: 'none',
        }} />

        {/* ── Bottom vignette ── */}
        <div style={{
          position: 'absolute', bottom: 0, left: 0, right: 0, height: 80,
          background: 'linear-gradient(0deg, rgba(0,0,0,0.45) 0%, transparent 100%)',
          pointerEvents: 'none',
        }} />
      </div>
    </>
  )
}
