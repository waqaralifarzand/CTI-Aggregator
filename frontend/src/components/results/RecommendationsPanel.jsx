import React from 'react'

export default function RecommendationsPanel({ recommendations }) {
  if (!recommendations?.length) return null

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 14px' }}>
        Analyst Recommendations
      </h3>
      <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {recommendations.map((rec, i) => (
          <li key={i} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <span style={{
              flexShrink: 0,
              width: '22px', height: '22px',
              borderRadius: '50%',
              background: 'rgba(6,182,212,0.15)',
              border: '1px solid rgba(6,182,212,0.3)',
              color: 'var(--accent)',
              fontSize: '11px',
              fontWeight: '700',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              marginTop: '1px',
            }}>
              {i + 1}
            </span>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>{rec}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}
