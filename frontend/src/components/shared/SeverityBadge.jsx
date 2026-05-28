import React from 'react'

const severityConfig = {
  critical: { color: 'var(--critical)', bg: 'rgba(239, 68, 68, 0.15)' },
  high: { color: 'var(--high)', bg: 'rgba(249, 115, 22, 0.15)' },
  medium: { color: 'var(--medium)', bg: 'rgba(234, 179, 8, 0.15)' },
  low: { color: 'var(--low)', bg: 'rgba(34, 197, 94, 0.15)' },
  clean: { color: 'var(--clean)', bg: 'rgba(16, 185, 129, 0.15)' },
  info: { color: 'var(--info)', bg: 'rgba(59, 130, 246, 0.15)' },
}

export default function SeverityBadge({ severity }) {
  if (!severity) return null
  const key = severity.toLowerCase()
  const config = severityConfig[key] || {
    color: 'var(--text-secondary)',
    bg: 'rgba(148, 163, 184, 0.15)',
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 10px',
        borderRadius: '9999px',
        fontSize: '12px',
        fontWeight: '600',
        color: config.color,
        background: config.bg,
        textTransform: 'capitalize',
        letterSpacing: '0.3px',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  )
}
