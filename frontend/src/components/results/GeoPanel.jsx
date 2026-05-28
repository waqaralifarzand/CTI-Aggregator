import React from 'react'

export default function GeoPanel({ geo }) {
  if (!geo) return null

  const rows = [
    { label: 'Country', value: geo.country },
    { label: 'Region', value: geo.region },
    { label: 'City', value: geo.city },
    { label: 'ISP', value: geo.isp },
    { label: 'ASN', value: geo.asn },
  ].filter(r => r.value)

  if (rows.length === 0) return null

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 14px' }}>
        Geolocation
      </h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '12px' }}>
        {rows.map(r => (
          <div key={r.label}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '3px', textTransform: 'uppercase' }}>{r.label}</div>
            <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: '500' }}>{r.value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
