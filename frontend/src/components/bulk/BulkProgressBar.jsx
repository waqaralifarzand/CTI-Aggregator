import React from 'react'

export default function BulkProgressBar({ completed, total, status, failed }) {
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0
  const isDone = status === 'completed'
  const isFailed = status === 'failed'

  const barColor = isFailed ? 'var(--critical)' : isDone ? 'var(--clean)' : 'var(--accent)'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '10px',
      padding: '20px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>
          {isFailed ? 'Scan Failed' : isDone ? 'Scan Complete' : 'Scanning…'}
        </span>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          {failed > 0 && (
            <span style={{ fontSize: '12px', color: 'var(--critical)' }}>
              {failed} failed
            </span>
          )}
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            {completed} of {total} scanned
          </span>
        </div>
      </div>
      <div style={{ height: '8px', background: 'var(--border)', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: barColor,
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
