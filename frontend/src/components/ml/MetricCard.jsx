import React from 'react'

export default function MetricCard({ label, value }) {
  const pct = value != null ? (value * 100).toFixed(1) + '%' : '—'
  const valueColor = value >= 0.85 ? 'var(--clean)' : value >= 0.70 ? 'var(--medium)' : 'var(--critical)'
  const topBorderColor = value >= 0.85 ? 'var(--clean)' : value >= 0.70 ? 'var(--medium)' : 'var(--critical)'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderTop: `3px solid ${topBorderColor}`,
      borderRadius: '10px',
      padding: '20px',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '10px', fontWeight: '500' }}>{label}</div>
      <div style={{ fontSize: '36px', fontWeight: '800', color: valueColor, lineHeight: 1 }}>{pct}</div>
    </div>
  )
}
