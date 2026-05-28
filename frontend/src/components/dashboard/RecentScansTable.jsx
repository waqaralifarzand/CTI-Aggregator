import React from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../shared/SeverityBadge'

function relativeTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function RecentScansTable({ scans }) {
  if (!scans?.length) return (
    <div style={{ padding: '24px', fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center' }}>
      No scans yet
    </div>
  )

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {['IoC Value', 'Type', 'Severity', 'Score', 'Time', ''].map(h => (
              <th key={h} style={{
                padding: '10px 12px', textAlign: 'left', fontSize: '11px', fontWeight: '600',
                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px',
                borderBottom: '1px solid var(--border)',
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {scans.map(s => (
            <tr key={s.scan_id}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-card-hover)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                <span className="mono" style={{ fontSize: '12px', color: 'var(--text-primary)' }}
                  title={s.ioc_value}>
                  {s.ioc_value?.length > 25 ? s.ioc_value.slice(0, 25) + '…' : s.ioc_value}
                </span>
              </td>
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
                {s.ioc_type?.replace('hash_', '').toUpperCase()}
              </td>
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                <SeverityBadge severity={s.overall_severity} />
              </td>
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontSize: '13px', fontWeight: '700', color: 'var(--text-secondary)' }}>
                {s.threat_score}
              </td>
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}
                title={s.scanned_at ? new Date(s.scanned_at).toLocaleString() : ''}>
                {relativeTime(s.scanned_at)}
              </td>
              <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                <Link to={`/results/${s.scan_id}`} style={{ color: 'var(--accent)', display: 'inline-flex' }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                    <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
                  </svg>
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
