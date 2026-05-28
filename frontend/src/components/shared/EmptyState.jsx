import React from 'react'

export default function EmptyState({ message = 'No data yet', subtext = '' }) {
  return (
    <div style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-secondary)' }}>
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ margin: '0 auto 16px', display: 'block', color: 'var(--text-muted)' }}>
        <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
      </svg>
      <p style={{ fontSize: '15px', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: subtext ? '6px' : 0 }}>{message}</p>
      {subtext && <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{subtext}</p>}
    </div>
  )
}
