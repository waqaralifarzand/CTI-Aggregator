import React from 'react'

export default function TopBar({ title, children }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingBottom: '24px',
        marginBottom: '24px',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <h1
        style={{
          fontSize: '24px',
          fontWeight: '700',
          color: 'var(--text-primary)',
          fontFamily: "'DM Sans', sans-serif",
          letterSpacing: '-0.3px',
        }}
      >
        {title}
      </h1>
      {children && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {children}
        </div>
      )}
    </div>
  )
}
