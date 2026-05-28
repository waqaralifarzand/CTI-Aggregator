import React from 'react'

export default function StatCard({ label, value, icon, subtitle }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '10px',
      padding: '20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
        <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: '500' }}>{label}</span>
        {icon && <span style={{ color: 'var(--accent)', opacity: 0.7 }}>{icon}</span>}
      </div>
      <div style={{ fontSize: '32px', fontWeight: '800', color: 'var(--text-primary)', lineHeight: 1 }}>
        {value ?? '—'}
      </div>
      {subtitle && (
        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>{subtitle}</div>
      )}
    </div>
  )
}
