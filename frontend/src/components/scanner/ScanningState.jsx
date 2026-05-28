export default function ScanningState({ value }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '16px',
      padding: '32px',
      color: 'var(--text-secondary)',
    }}>
      <div style={{ position: 'relative', width: 48, height: 48 }}>
        <div style={{
          width: 48,
          height: 48,
          borderRadius: '50%',
          border: '3px solid var(--border)',
          borderTopColor: 'var(--accent)',
          animation: 'spin 0.8s linear infinite',
        }} />
      </div>
      <div style={{ textAlign: 'center' }}>
        <p style={{ color: 'var(--text-primary)', fontWeight: 600, margin: '0 0 4px' }}>
          Scanning…
        </p>
        {value && (
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'JetBrains Mono, monospace', margin: 0 }}>
            {value}
          </p>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
