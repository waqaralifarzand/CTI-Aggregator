import React from 'react'
import { Link } from 'react-router-dom'
import SeverityBadge from '../shared/SeverityBadge'
import CopyButton from '../shared/CopyButton'
import LoadingSkeleton from '../shared/LoadingSkeleton'
import EmptyState from '../shared/EmptyState'

function relativeTime(isoString) {
  if (!isoString) return '—'
  const diff = Date.now() - new Date(isoString).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function scoreColor(score) {
  if (score >= 76) return 'var(--critical)'
  if (score >= 51) return 'var(--high)'
  if (score >= 26) return 'var(--medium)'
  if (score >= 1) return 'var(--low)'
  return 'var(--clean)'
}

const thStyle = {
  padding: '10px 12px',
  textAlign: 'left',
  fontSize: '11px',
  fontWeight: '600',
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  whiteSpace: 'nowrap',
  background: 'var(--bg-card)',
  borderBottom: '1px solid var(--border)',
  position: 'sticky',
  top: 0,
  zIndex: 1,
}

const tdStyle = {
  padding: '10px 12px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  borderBottom: '1px solid var(--border)',
  verticalAlign: 'middle',
}

export default function ReportsTable({ results, loading, total, page, limit, onPageChange }) {
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
      <div style={{ overflowX: 'auto', flex: 1 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={thStyle}>IoC Value</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Severity</th>
              <th style={thStyle}>Score</th>
              <th style={thStyle}>ML Severity</th>
              <th style={thStyle}>Scanned At</th>
              <th style={thStyle}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  {Array.from({ length: 7 }).map((__, j) => (
                    <td key={j} style={tdStyle}>
                      <LoadingSkeleton height="16px" />
                    </td>
                  ))}
                </tr>
              ))
            ) : results.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '48px 12px' }}>
                  <EmptyState message="No scans match these filters." subtext="Try adjusting your filters or clearing them to see all results." />
                </td>
              </tr>
            ) : (
              results.map((row) => {
                const truncated = row.ioc_value?.length > 30
                  ? row.ioc_value.slice(0, 30) + '…'
                  : row.ioc_value

                return (
                  <tr
                    key={row.scan_id}
                    style={{ transition: 'background 0.1s' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-card-hover)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={tdStyle}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span
                          className="mono"
                          style={{ fontSize: '12px', color: 'var(--text-primary)' }}
                          title={row.ioc_value}
                        >
                          {truncated}
                        </span>
                        <CopyButton text={row.ioc_value} />
                      </div>
                    </td>
                    <td style={tdStyle}>
                      <span style={{
                        fontSize: '11px',
                        color: 'var(--text-secondary)',
                        background: 'rgba(148,163,184,0.1)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontWeight: '500',
                      }}>
                        {row.ioc_type?.replace('hash_', '').toUpperCase() || '—'}
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <SeverityBadge severity={row.overall_severity} />
                    </td>
                    <td style={{ ...tdStyle, fontWeight: '700', color: scoreColor(row.threat_score) }}>
                      {row.threat_score ?? '—'}
                    </td>
                    <td style={tdStyle}>
                      {row.ml_severity ? <SeverityBadge severity={row.ml_severity} /> : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td
                      style={{ ...tdStyle, color: 'var(--text-secondary)', fontSize: '12px' }}
                      title={row.scanned_at ? new Date(row.scanned_at).toLocaleString() : ''}
                    >
                      {relativeTime(row.scanned_at)}
                    </td>
                    <td style={tdStyle}>
                      <Link
                        to={`/results/${row.scan_id}`}
                        title="View full result"
                        style={{ color: 'var(--accent)', display: 'inline-flex', alignItems: 'center' }}
                      >
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                          <polyline points="15 3 21 3 21 9" />
                          <line x1="10" y1="14" x2="21" y2="3" />
                        </svg>
                      </Link>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-card)',
        fontSize: '13px',
        color: 'var(--text-secondary)',
      }}>
        <span>
          Showing {results.length} of {total} results
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            style={{
              background: 'transparent',
              border: '1px solid var(--border)',
              color: page <= 1 ? 'var(--text-muted)' : 'var(--text-primary)',
              borderRadius: '5px',
              padding: '5px 12px',
              cursor: page <= 1 ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              fontFamily: 'inherit',
            }}
          >
            ← Previous
          </button>
          <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            style={{
              background: 'transparent',
              border: '1px solid var(--border)',
              color: page >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
              borderRadius: '5px',
              padding: '5px 12px',
              cursor: page >= totalPages ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              fontFamily: 'inherit',
            }}
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  )
}
