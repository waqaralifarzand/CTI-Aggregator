import React, { useState } from 'react'
import IocTypeBadge from './IocTypeBadge'

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/

function detectTypeClient(value) {
  const v = value.trim()
  if (!v) return null
  if (IPV4_RE.test(v)) return 'ip'
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'hash_sha256'
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'hash_sha1'
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'hash_md5'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(v)) return 'domain'
  return null
}

export default function ScanBar({ onScan, loading }) {
  const [value, setValue] = useState('')
  const detectedType = detectTypeClient(value)

  const handleSubmit = (e) => {
    e.preventDefault()
    const trimmed = value.trim()
    if (trimmed && !loading) onScan(trimmed)
  }

  return (
    <form onSubmit={handleSubmit}>
      <div style={{ position: 'relative', display: 'flex', gap: '12px' }}>
        <input
          type="text"
          value={value}
          onChange={e => setValue(e.target.value)}
          disabled={loading}
          placeholder="Enter IP address, domain, or file hash..."
          autoComplete="off"
          spellCheck={false}
          style={{
            flex: 1,
            padding: '14px 18px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            color: 'var(--text-primary)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '14px',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={e => { e.target.style.borderColor = 'var(--accent)' }}
          onBlur={e => { e.target.style.borderColor = 'var(--border)' }}
        />
        <button
          type="submit"
          disabled={loading || !value.trim()}
          style={{
            padding: '14px 28px',
            background: loading || !value.trim() ? 'var(--border)' : 'var(--accent)',
            color: loading || !value.trim() ? 'var(--text-muted)' : '#fff',
            border: 'none',
            borderRadius: '8px',
            cursor: loading || !value.trim() ? 'not-allowed' : 'pointer',
            fontSize: '14px',
            fontWeight: '600',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'background 0.15s',
            whiteSpace: 'nowrap',
          }}
        >
          {loading ? (
            <>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ animation: 'spin 1s linear infinite' }}>
                <path d="M21 12a9 9 0 1 1-6.219-8.56" />
              </svg>
              Scanning...
            </>
          ) : 'Scan'}
        </button>
      </div>
      {detectedType && (
        <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Detected:</span>
          <IocTypeBadge type={detectedType} />
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </form>
  )
}
