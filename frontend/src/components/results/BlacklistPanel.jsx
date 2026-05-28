import React from 'react'

export default function BlacklistPanel({ blacklistStatus }) {
  if (!blacklistStatus) return null
  const entries = Object.entries(blacklistStatus)
  if (entries.length === 0) return null

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 14px' }}>Blacklist Status</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px' }}>
        {entries.map(([source, status]) => {
          const isFlagged = status === 'flagged'
          return (
            <div key={source} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 14px',
              background: 'var(--bg-primary)',
              borderRadius: '6px',
              border: `1px solid ${isFlagged ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
            }}>
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                {source.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
              </span>
              <span style={{
                fontSize: '11px', fontWeight: '700',
                color: isFlagged ? 'var(--critical)' : 'var(--clean)',
              }}>
                {isFlagged ? '● FLAGGED' : '✓ CLEAN'}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
