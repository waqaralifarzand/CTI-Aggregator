function WhoisRow({ label, value }) {
  if (!value) return null
  const displayValue = Array.isArray(value) ? value.join(', ') : String(value)
  return (
    <div style={{ display: 'flex', gap: '12px', padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: '13px' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 120, flexShrink: 0 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', wordBreak: 'break-all' }}>
        {displayValue}
      </span>
    </div>
  )
}

export default function WhoisPanel({ whois, animStyle }) {
  if (!whois) return null

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
      ...animStyle,
    }}>
      <p style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', margin: '0 0 14px' }}>
        WHOIS Data
      </p>
      <WhoisRow label="Registrar" value={whois.registrar} />
      <WhoisRow label="Created" value={whois.creation_date} />
      <WhoisRow label="Expires" value={whois.expiration_date} />
      <WhoisRow label="Name Servers" value={whois.name_servers} />
      <WhoisRow label="Status" value={whois.status} />
    </div>
  )
}
