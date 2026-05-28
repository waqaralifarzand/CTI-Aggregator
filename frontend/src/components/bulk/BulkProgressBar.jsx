import React from 'react'

export default function BulkProgressBar({ completed, total, status }) {
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0

  const statusColor = status === 'done' ? 'var(--clean)' : status === 'error' ? 'var(--critical)' : 'var(--accent)'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '10px',
      padding: '20px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
        <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>
          {status === 'done' ? 'Scan Complete' : 'Scanning...'}
        </span>
        <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          {completed} of {total} scanned
        </span>
      </div>
      <div style={{ height: '8px', background: 'var(--border)', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: statusColor,
          borderRadius: '4px',
          transition: 'width 0.3s ease',
        }} />
      </div>
      <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text-muted)', textAlign: 'right' }}>
        {pct}%
      </div>
    </div>
  )
}
