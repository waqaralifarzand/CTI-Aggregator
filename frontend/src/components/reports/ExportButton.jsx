import React from 'react'

export default function ExportButton({ onExport, exporting }) {
  return (
    <button
      onClick={onExport}
      disabled={exporting}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        background: 'var(--accent)',
        color: '#0a0e1a',
        border: 'none',
        borderRadius: '6px',
        padding: '8px 16px',
        fontSize: '13px',
        fontWeight: '600',
        cursor: exporting ? 'not-allowed' : 'pointer',
        opacity: exporting ? 0.7 : 1,
        fontFamily: 'inherit',
        transition: 'background 0.15s',
        whiteSpace: 'nowrap',
      }}
      onMouseEnter={(e) => { if (!exporting) e.currentTarget.style.background = 'var(--accent-hover)' }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--accent)' }}
    >
      {exporting ? (
        <>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
            style={{ animation: 'spin 1s linear infinite' }}>
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          Exporting...
        </>
      ) : (
        <>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Export CSV
        </>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </button>
  )
}
