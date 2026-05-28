import React, { useState } from 'react'

function SubPanel({ title, data, fields }) {
  if (!data) return null
  return (
    <div style={{ padding: '14px', background: 'var(--bg-primary)', borderRadius: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <span style={{
          background: data.found ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
          color: data.found ? 'var(--critical)' : 'var(--clean)',
          borderRadius: '4px', padding: '1px 6px', fontSize: '10px', fontWeight: '700',
        }}>
          {data.found ? 'FOUND' : 'CLEAN'}
        </span>
        <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>{title}</span>
      </div>
      {data.found && fields.map(f => data[f.key] != null && (
        <div key={f.key} style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
          <span style={{ color: 'var(--text-muted)' }}>{f.label}: </span>{data[f.key]}
        </div>
      ))}
      {data.found && data.tags?.length > 0 && (
        <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
          {data.tags.map(t => (
            <span key={t} style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--critical)', borderRadius: '3px', padding: '1px 6px', fontSize: '11px' }}>{t}</span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AbuseChPanel({ urlhaus, malwarebazaar }) {
  const [open, setOpen] = useState(true)
  const anyFound = urlhaus?.found || malwarebazaar?.found

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', overflow: 'hidden' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '16px 20px', background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-primary)', fontFamily: 'inherit',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            background: anyFound ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
            color: anyFound ? 'var(--critical)' : 'var(--clean)',
            borderRadius: '4px', padding: '2px 8px', fontSize: '11px', fontWeight: '600',
          }}>
            {anyFound ? 'FOUND' : 'CLEAN'}
          </span>
          <span style={{ fontWeight: '600', fontSize: '14px' }}>Abuse.ch Feeds</span>
        </div>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s', color: 'var(--text-muted)' }}>
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && (
        <div style={{ padding: '0 20px 20px', borderTop: '1px solid var(--border)' }}>
          <div style={{ paddingTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <SubPanel title="URLhaus" data={urlhaus} fields={[
              { key: 'url_count', label: 'URLs' },
            ]} />
            <SubPanel title="MalwareBazaar" data={malwarebazaar} fields={[
              { key: 'file_type', label: 'File Type' },
              { key: 'signature', label: 'Signature' },
            ]} />
          </div>
        </div>
      )}
    </div>
  )
}
