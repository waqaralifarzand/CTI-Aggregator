import React from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../shared/SeverityBadge'

export default function BulkResultsTable({ results }) {
  if (!results?.length) return null

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', overflow: 'hidden' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
        <h3 style={{ margin: 0, fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)' }}>
          Results ({results.length})
        </h3>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['IoC Value', 'Type', 'Severity', 'Score', ''].map(h => (
                <th key={h} style={{
                  padding: '10px 12px', textAlign: 'left', fontSize: '11px',
                  fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.5px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card)',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={i}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-card-hover)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
              >
                <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                  <span className="mono" style={{ fontSize: '12px', color: 'var(--text-primary)' }}
                    title={r.ioc_value}>
                    {r.ioc_value?.length > 30 ? r.ioc_value.slice(0, 30) + '…' : r.ioc_value}
                  </span>
                </td>
                <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
                  {r.ioc_type?.replace('hash_', '').toUpperCase()}
                </td>
                <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                  <SeverityBadge severity={r.overall_severity} />
                </td>
                <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)', fontSize: '13px', fontWeight: '700', color: 'var(--text-secondary)' }}>
                  {r.threat_score}
                </td>
                <td style={{ padding: '9px 12px', borderBottom: '1px solid var(--border)' }}>
                  {r.scan_id && (
                    <Link to={`/results/${r.scan_id}`} style={{ color: 'var(--accent)', display: 'inline-flex' }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                        <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                      </svg>
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
