import React, { useState } from 'react'

export default function OTXPanel({ otx }) {
  const [open, setOpen] = useState(true)
  if (!otx) return null

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
            background: otx.found ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
            color: otx.found ? 'var(--critical)' : 'var(--clean)',
            borderRadius: '4px', padding: '2px 8px', fontSize: '11px', fontWeight: '600',
          }}>
            {otx.found ? 'FOUND' : 'CLEAN'}
          </span>
          <span style={{ fontWeight: '600', fontSize: '14px' }}>AlienVault OTX</span>
        </div>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s', color: 'var(--text-muted)' }}>
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {open && (
        <div style={{ padding: '0 20px 20px', borderTop: '1px solid var(--border)' }}>
          <div style={{ paddingTop: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>PULSE COUNT</div>
              <div style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)' }}>{otx.pulse_count ?? 0}</div>
            </div>
            {otx.country && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>COUNTRY</div>
                <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)' }}>{otx.country}</div>
              </div>
            )}
          </div>

          {otx.threat_tags?.length > 0 && (
            <div style={{ marginTop: '14px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>THREAT TAGS</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {otx.threat_tags.map(tag => (
                  <span key={tag} style={{
                    background: 'rgba(249,115,22,0.1)', color: 'var(--high)',
                    border: '1px solid rgba(249,115,22,0.2)',
                    borderRadius: '4px', padding: '2px 8px', fontSize: '12px',
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {otx.categories?.length > 0 && (
            <div style={{ marginTop: '14px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>CATEGORIES</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {otx.categories.map(cat => (
                  <span key={cat} style={{
                    background: 'rgba(6,182,212,0.08)', color: 'var(--accent)',
                    borderRadius: '4px', padding: '2px 8px', fontSize: '12px',
                  }}>
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          )}

          {!otx.found && (
            <p style={{ marginTop: '12px', fontSize: '13px', color: 'var(--text-muted)' }}>
              Not found in any OTX pulses.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
