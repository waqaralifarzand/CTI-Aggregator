import { useState } from 'react'

function TagPill({ tag }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: '999px',
      fontSize: '11px',
      fontWeight: 500,
      background: 'rgba(6,182,212,0.1)',
      color: 'var(--accent)',
      border: '1px solid rgba(6,182,212,0.25)',
    }}>
      {tag}
    </span>
  )
}

export default function OTXPanel({ otx, animStyle }) {
  const [expanded, setExpanded] = useState(!!(otx?.found))
  const found = otx?.found

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${found ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
      borderRadius: '8px',
      overflow: 'hidden',
      opacity: found ? 1 : 0.75,
      ...animStyle,
    }}>
      <button
        onClick={() => setExpanded(e => !e)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 20px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          color: 'inherit',
          fontFamily: 'inherit',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
            padding: '2px 6px', borderRadius: '3px',
            background: 'rgba(239,68,68,0.15)', color: '#f87171',
          }}>OTX</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '14px' }}>
            AlienVault OTX
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {found ? (
            <span style={{ color: 'var(--critical)', fontSize: '12px', fontWeight: 600 }}>
              ⚠ {otx.pulse_count} pulse{otx.pulse_count !== 1 ? 's' : ''} found
            </span>
          ) : (
            <span style={{ color: 'var(--clean)', fontSize: '12px' }}>✓ No threats detected</span>
          )}
          <ChevronIcon expanded={expanded} />
        </div>
      </button>

      {expanded && (
        <div style={{ padding: '0 20px 20px', borderTop: '1px solid var(--border)' }}>
          {found ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '16px' }}>
              <Row label="Pulse Count" value={otx.pulse_count} />
              {otx.country && <Row label="Country" value={otx.country} />}
              {otx.threat_tags?.length > 0 && (
                <div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'block', marginBottom: '6px' }}>Threat Tags</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
                    {otx.threat_tags.map(tag => <TagPill key={tag} tag={tag} />)}
                  </div>
                </div>
              )}
              {otx.categories?.length > 0 && (
                <div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'block', marginBottom: '6px' }}>Categories</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
                    {otx.categories.map(cat => <TagPill key={cat} tag={cat} />)}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', paddingTop: '14px', margin: 0 }}>
              This IoC has no recorded threat activity in AlienVault OTX.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 110 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)' }}>{value ?? '—'}</span>
    </div>
  )
}

function ChevronIcon({ expanded }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
      <polyline points="6 9 12 15 18 9"/>
    </svg>
  )
}
