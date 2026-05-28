const DISPLAY_NAMES = {
  otx_blacklist: 'AlienVault OTX',
  urlhaus: 'Abuse.ch URLhaus',
  malwarebazaar: 'Abuse.ch MalwareBazaar',
  virustotal: 'VirusTotal',
}

function StatusChip({ status }) {
  const flagged = status === 'flagged'
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '5px',
      padding: '3px 10px',
      borderRadius: '999px',
      fontSize: '11px',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.04em',
      background: flagged ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)',
      color: flagged ? 'var(--critical)' : 'var(--clean)',
      border: `1px solid ${flagged ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`,
    }}>
      {flagged ? '✕ Flagged' : '✓ Clean'}
    </span>
  )
}

export default function BlacklistPanel({ blacklistStatus, animStyle }) {
  if (!blacklistStatus) return null

  const entries = Object.entries(blacklistStatus)

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
      ...animStyle,
    }}>
      <p style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', margin: '0 0 14px' }}>
        Blacklist Status
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '10px' }}>
        {entries.map(([key, status]) => (
          <div key={key} style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '10px 12px',
            background: 'var(--bg-card-hover)',
            borderRadius: '6px',
            border: '1px solid var(--border)',
          }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
              {DISPLAY_NAMES[key] || key}
            </span>
            <StatusChip status={status} />
          </div>
        ))}
      </div>
    </div>
  )
}
