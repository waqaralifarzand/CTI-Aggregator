import React from 'react'

const statusConfig = {
  active: { color: 'var(--clean)', bg: 'rgba(16,185,129,0.15)', label: 'Active' },
  error: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.15)', label: 'Error' },
  syncing: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.15)', label: 'Syncing' },
  unknown: { color: 'var(--text-muted)', bg: 'rgba(71,85,105,0.15)', label: 'Unknown' },
}

const feedNames = {
  otx: 'AlienVault OTX',
  urlhaus: 'Abuse.ch URLhaus',
  malwarebazaar: 'Abuse.ch MalwareBazaar',
}

function relativeTime(iso) {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function FeedHealthWidget({ feed }) {
  if (!feed) return null
  const cfg = statusConfig[feed.status] || statusConfig.unknown

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '14px 16px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '12px',
    }}>
      <div>
        <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '3px' }}>
          {feedNames[feed.feed_name] || feed.feed_name}
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          Last sync: {relativeTime(feed.last_synced)}
          {feed.record_count > 0 && ` · ${feed.record_count.toLocaleString()} records`}
        </div>
      </div>
      <span style={{
        background: cfg.bg, color: cfg.color,
        borderRadius: '4px', padding: '3px 8px',
        fontSize: '11px', fontWeight: '700',
        whiteSpace: 'nowrap',
      }}>
        {cfg.label}
      </span>
    </div>
  )
}
