export default function StatCard({ icon, label, value, subtitle, accentColor }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderLeft: `3px solid ${accentColor || 'var(--accent)'}`,
      borderRadius: '8px',
      padding: '20px 20px 20px 18px',
      display: 'flex',
      alignItems: 'flex-start',
      gap: '16px',
      flex: 1,
      minWidth: 0,
    }}>
      {icon && (
        <div style={{
          width: 38, height: 38, borderRadius: '8px',
          background: `${accentColor || 'var(--accent)'}1a`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: accentColor || 'var(--accent)',
          flexShrink: 0,
        }}>
          {icon}
        </div>
      )}
      <div style={{ minWidth: 0 }}>
        <p style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', margin: '0 0 4px' }}>
          {label}
        </p>
        <p style={{ color: 'var(--text-primary)', fontSize: '28px', fontWeight: 700, lineHeight: 1, margin: '0 0 4px' }}>
          {value ?? '—'}
        </p>
        {subtitle && (
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', margin: 0 }}>{subtitle}</p>
        )}
      </div>
    </div>
  )
}
