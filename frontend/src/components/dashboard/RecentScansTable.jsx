import { Link } from 'react-router-dom'
import SeverityBadge from '../shared/SeverityBadge'
import LoadingSkeleton from '../shared/LoadingSkeleton'
import EmptyState from '../shared/EmptyState'

const TYPE_LABEL = {
  ip: 'IP', domain: 'Domain',
  hash_md5: 'MD5', hash_sha256: 'SHA256', hash_sha1: 'SHA1',
}

function relativeTime(dateStr) {
  if (!dateStr) return '—'
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(mins / 60)
  const days  = Math.floor(hours / 24)
  if (days > 0) return `${days}d ago`
  if (hours > 0) return `${hours}h ago`
  if (mins > 0) return `${mins}m ago`
  return 'Just now'
}

function SkeletonRow() {
  return (
    <tr>
      {[200, 60, 80, 40, 60, 30].map((w, i) => (
        <td key={i} style={{ padding: '10px 12px' }}>
          <LoadingSkeleton height={12} width={w} />
        </td>
      ))}
    </tr>
  )
}

export default function RecentScansTable({ data, loading }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['IoC Value', 'Type', 'Severity', 'Score', 'When', ''].map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left', fontWeight: 600,
                fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: '0.06em', whiteSpace: 'nowrap',
              }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading && [...Array(5)].map((_, i) => <SkeletonRow key={i} />)}

          {!loading && (!data || data.length === 0) && (
            <tr>
              <td colSpan={6}>
                <EmptyState
                  title="No scans yet"
                  description="Go to the Scanner page to run your first IoC scan"
                />
              </td>
            </tr>
          )}

          {!loading && data?.map(scan => (
            <tr
              key={scan.scan_id}
              style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <td style={{ padding: '10px 12px', maxWidth: '180px' }}>
                <span style={{
                  fontFamily: 'JetBrains Mono, monospace', fontSize: '12px',
                  color: 'var(--text-primary)', display: 'block',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {scan.ioc_value}
                </span>
              </td>
              <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>
                  {TYPE_LABEL[scan.ioc_type] || scan.ioc_type}
                </span>
              </td>
              <td style={{ padding: '10px 12px' }}>
                <SeverityBadge severity={scan.overall_severity} size="sm" />
              </td>
              <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}>
                {scan.threat_score}
              </td>
              <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: '12px', whiteSpace: 'nowrap' }}>
                {relativeTime(scan.scanned_at)}
              </td>
              <td style={{ padding: '10px 12px' }}>
                <Link
                  to={`/results/${scan.scan_id}`}
                  style={{ color: 'var(--accent)', display: 'flex', alignItems: 'center' }}
                  title="View results"
                >
                  <LinkIcon />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function LinkIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      <polyline points="15 3 21 3 21 9"/>
      <line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  )
}
