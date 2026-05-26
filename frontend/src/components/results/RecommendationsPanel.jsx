export default function RecommendationsPanel({ recommendations, animStyle }) {
  if (!recommendations?.length) return null

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
      ...animStyle,
    }}>
      <p style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', margin: '0 0 16px' }}>
        Analyst Recommendations
      </p>
      <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {recommendations.map((rec, i) => (
          <li key={i} style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
            <span style={{
              flexShrink: 0,
              width: 24, height: 24,
              borderRadius: '50%',
              background: 'rgba(6,182,212,0.15)',
              border: '1px solid rgba(6,182,212,0.35)',
              color: 'var(--accent)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              {i + 1}
            </span>
            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.6, margin: 0 }}>
              {rec}
            </p>
          </li>
        ))}
      </ol>
    </div>
  )
}
