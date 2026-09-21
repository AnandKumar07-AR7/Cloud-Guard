import React, { useMemo, useState } from 'react'

interface DiffViewerProps {
  before: unknown
  after: unknown
  beforeLabel?: string
  afterLabel?: string
  beforeTitle?: string
  afterTitle?: string
}

interface DiffEntry {
  key: string
  status: 'REMOVED' | 'ADDED' | 'MODIFIED' | 'UNCHANGED'
  beforeValue?: unknown
  afterValue?: unknown
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  before,
  after,
  beforeLabel,
  afterLabel,
  beforeTitle,
  afterTitle,
}) => {
  const [viewMode, setViewMode] = useState<'structured' | 'side-by-side'>('structured')

  const labelB = beforeTitle || beforeLabel || 'CURRENT / BEFORE STATE'
  const labelA = afterTitle || afterLabel || 'PROPOSED / AFTER REMEDIATION'

  const formatVal = (val: unknown) => {
    if (val === undefined) return '<undefined>'
    if (typeof val === 'string') return val
    return JSON.stringify(val, null, 2)
  }

  const beforeStr = formatVal(before)
  const afterStr = formatVal(after)

  // Compute structured diff entries if both are objects
  const diffEntries: DiffEntry[] = useMemo(() => {
    if (
      before &&
      after &&
      typeof before === 'object' &&
      typeof after === 'object' &&
      !Array.isArray(before) &&
      !Array.isArray(after)
    ) {
      const bObj = before as Record<string, unknown>
      const aObj = after as Record<string, unknown>
      const allKeys = Array.from(new Set([...Object.keys(bObj), ...Object.keys(aObj)]))

      return allKeys.map((key) => {
        const hasBefore = key in bObj
        const hasAfter = key in aObj
        const bVal = bObj[key]
        const aVal = aObj[key]

        if (hasBefore && !hasAfter) {
          return { key, status: 'REMOVED', beforeValue: bVal }
        }
        if (!hasBefore && hasAfter) {
          return { key, status: 'ADDED', afterValue: aVal }
        }
        if (JSON.stringify(bVal) !== JSON.stringify(aVal)) {
          return { key, status: 'MODIFIED', beforeValue: bVal, afterValue: aVal }
        }
        return { key, status: 'UNCHANGED', beforeValue: bVal, afterValue: aVal }
      })
    }

    // Line-by-line fallback for strings or non-objects
    const bLines = beforeStr.split('\n')
    const aLines = afterStr.split('\n')
    const maxLines = Math.max(bLines.length, aLines.length)
    const entries: DiffEntry[] = []

    for (let i = 0; i < maxLines; i++) {
      const bL = bLines[i]
      const aL = aLines[i]
      if (bL === undefined && aL !== undefined) {
        entries.push({ key: `L${i + 1}`, status: 'ADDED', afterValue: aL })
      } else if (bL !== undefined && aL === undefined) {
        entries.push({ key: `L${i + 1}`, status: 'REMOVED', beforeValue: bL })
      } else if (bL !== aL) {
        entries.push({ key: `L${i + 1}`, status: 'MODIFIED', beforeValue: bL, afterValue: aL })
      } else {
        entries.push({ key: `L${i + 1}`, status: 'UNCHANGED', beforeValue: bL, afterValue: aL })
      }
    }
    return entries
  }, [before, after, beforeStr, afterStr])

  const removedCount = diffEntries.filter((e) => e.status === 'REMOVED' || e.status === 'MODIFIED').length
  const addedCount = diffEntries.filter((e) => e.status === 'ADDED' || e.status === 'MODIFIED').length
  const unchangedCount = diffEntries.filter((e) => e.status === 'UNCHANGED').length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Diff Metrics & View Mode Toolbar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 10,
          padding: '8px 12px',
          background: 'var(--surface-overlay)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 6,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            OPERATOR AUDIT DIFF:
          </span>
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'var(--font-mono)',
              background: 'rgba(239, 68, 68, 0.15)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.3)',
            }}
          >
            {removedCount} REMOVED
          </span>
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'var(--font-mono)',
              background: 'rgba(16, 185, 129, 0.15)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}
          >
            {addedCount} ADDED
          </span>
          <span
            style={{
              padding: '2px 8px',
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'var(--font-mono)',
              background: 'rgba(148, 163, 184, 0.12)',
              color: 'var(--text-muted)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {unchangedCount} UNCHANGED
          </span>
        </div>

        <div style={{ display: 'flex', gap: 6 }}>
          <button
            type="button"
            onClick={() => setViewMode('structured')}
            style={{
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 600,
              borderRadius: 4,
              border: '1px solid',
              borderColor: viewMode === 'structured' ? 'var(--accent-cyan)' : 'var(--border-subtle)',
              background: viewMode === 'structured' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
              color: viewMode === 'structured' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            Structured Matrix
          </button>
          <button
            type="button"
            onClick={() => setViewMode('side-by-side')}
            style={{
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 600,
              borderRadius: 4,
              border: '1px solid',
              borderColor: viewMode === 'side-by-side' ? 'var(--accent-cyan)' : 'var(--border-subtle)',
              background: viewMode === 'side-by-side' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
              color: viewMode === 'side-by-side' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            Split Code View
          </button>
        </div>
      </div>

      {/* Structured Matrix Table View */}
      {viewMode === 'structured' && (
        <div
          style={{
            border: '1px solid var(--border-subtle)',
            borderRadius: 6,
            overflow: 'hidden',
            background: 'var(--surface-base)',
          }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '140px 1fr 1fr',
              padding: '8px 12px',
              background: 'var(--surface-elevated)',
              borderBottom: '1px solid var(--border-subtle)',
              fontSize: 11,
              fontWeight: 600,
              color: 'var(--text-secondary)',
              letterSpacing: '0.04em',
            }}
          >
            <span>STATUS & PARAMETER</span>
            <span style={{ color: '#f87171' }}>{labelB} (VULNERABLE)</span>
            <span style={{ color: '#34d399' }}>{labelA} (REMEDIATED)</span>
          </div>

          <div style={{ maxHeight: 380, overflowY: 'auto' }}>
            {diffEntries.map((entry, idx) => {
              const isRem = entry.status === 'REMOVED'
              const isAdd = entry.status === 'ADDED'
              const isMod = entry.status === 'MODIFIED'
              const rowBg = isRem
                ? 'rgba(239, 68, 68, 0.04)'
                : isAdd
                ? 'rgba(16, 185, 129, 0.04)'
                : isMod
                ? 'rgba(234, 179, 8, 0.04)'
                : 'transparent'

              return (
                <div
                  key={`${entry.key}-${idx}`}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '140px 1fr 1fr',
                    padding: '8px 12px',
                    borderBottom: '1px solid var(--border-subtle)',
                    background: rowBg,
                    fontSize: 12,
                    fontFamily: 'var(--font-mono)',
                    alignItems: 'center',
                    gap: 10,
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span
                      style={{
                        display: 'inline-block',
                        padding: '1px 6px',
                        borderRadius: 3,
                        fontSize: 10,
                        fontWeight: 700,
                        width: 'fit-content',
                        background: isRem
                          ? 'rgba(239, 68, 68, 0.2)'
                          : isAdd
                          ? 'rgba(16, 185, 129, 0.2)'
                          : isMod
                          ? 'rgba(234, 179, 8, 0.2)'
                          : 'rgba(148, 163, 184, 0.1)',
                        color: isRem
                          ? '#f87171'
                          : isAdd
                          ? '#34d399'
                          : isMod
                          ? '#facc15'
                          : 'var(--text-muted)',
                      }}
                    >
                      {entry.status}
                    </span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {entry.key}
                    </span>
                  </div>

                  {/* Before Cell */}
                  <div
                    style={{
                      color: isRem || isMod ? '#f87171' : 'var(--text-muted)',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      background: isRem || isMod ? 'rgba(239, 68, 68, 0.08)' : 'transparent',
                      padding: '4px 8px',
                      borderRadius: 4,
                    }}
                  >
                    {entry.beforeValue !== undefined ? formatVal(entry.beforeValue) : '<none>'}
                  </div>

                  {/* After Cell */}
                  <div
                    style={{
                      color: isAdd || isMod ? '#34d399' : 'var(--text-muted)',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      background: isAdd || isMod ? 'rgba(16, 185, 129, 0.08)' : 'transparent',
                      padding: '4px 8px',
                      borderRadius: 4,
                    }}
                  >
                    {entry.afterValue !== undefined ? formatVal(entry.afterValue) : '<none>'}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Side-by-side Code Diff View */}
      <div
        style={{
          display: viewMode === 'side-by-side' ? 'grid' : 'none',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 12,
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
        }}
      >
        {/* Before */}
        <div
          style={{
            backgroundColor: 'var(--bg-app)',
            border: '1px solid var(--sev-critical-border)',
            borderRadius: 6,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: 'var(--sev-critical-bg)',
              color: 'var(--sev-critical)',
              fontSize: 11,
              fontWeight: 600,
              borderBottom: '1px solid var(--sev-critical-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>{labelB}</span>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: '0.05em',
                padding: '2px 6px',
                borderRadius: 3,
                background: 'rgba(239, 68, 68, 0.25)',
              }}
            >
              VULNERABLE
            </span>
          </div>
          <pre
            style={{
              padding: 12,
              margin: 0,
              color: '#f87171',
              whiteSpace: 'pre-wrap',
              overflowX: 'auto',
              maxHeight: 320,
            }}
          >
            {beforeStr}
          </pre>
        </div>

        {/* After */}
        <div
          style={{
            backgroundColor: 'var(--bg-app)',
            border: '1px solid var(--sev-low-border)',
            borderRadius: 6,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: 'var(--sev-low-bg)',
              color: 'var(--sev-low)',
              fontSize: 11,
              fontWeight: 600,
              borderBottom: '1px solid var(--sev-low-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>{labelA}</span>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: '0.05em',
                padding: '2px 6px',
                borderRadius: 3,
                background: 'rgba(16, 185, 129, 0.25)',
              }}
            >
              REMEDIATED
            </span>
          </div>
          <pre
            style={{
              padding: 12,
              margin: 0,
              color: '#34d399',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              maxHeight: 320,
              overflowY: 'auto',
            }}
          >
            {afterStr || '<empty / removed>'}
          </pre>
        </div>
      </div>
    </div>
  )
}
