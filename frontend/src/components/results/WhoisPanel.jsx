import React from 'react'

export default function WhoisPanel({ whois }) {
  if (!whois) return null

  const fmt = (val) => {
    if (!val) return '—'
    if (Array.isArray(val)) return val[0] ? new Date(val[0]).toLocaleDateString() : '—'
    if (val instanceof Date) return val.toLocaleDateString()
    return String(val)
  }

  const rows = [
    { label: 'Registrar', value: whois.registrar },
    { label: 'Created', value: fmt(whois.creation_date) },
    { label: 'Expires', value: fmt(whois.expiration_date) },
    { label: 'Status', value: Array.isArray(whois.status) ? whois.status[0] : whois.status },
  ].filter(r => r.value && r.value !== '—')

  if (rows.length === 0) return null

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 14px' }}>
        WHOIS Information
      </h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '12px' }}>
        {rows.map(r => (
          <div key={r.label}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '3px', textTransform: 'uppercase' }}>{r.label}</div>
            <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: '500', wordBreak: 'break-word' }}>{r.value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
