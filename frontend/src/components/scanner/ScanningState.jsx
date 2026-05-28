import React from 'react'

export default function ScanningState() {
  return (
    <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" style={{ animation: 'spin 1s linear infinite' }}>
          <path d="M21 12a9 9 0 1 1-6.219-8.56" />
        </svg>
      </div>
      <p style={{ fontSize: '15px' }}>Scanning threat intelligence feeds...</p>
      <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '6px' }}>Querying OTX, URLhaus, MalwareBazaar</p>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
