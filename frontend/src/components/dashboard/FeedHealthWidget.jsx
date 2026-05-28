import { useState } from 'react'
import { refreshFeed } from '../../api/client'

const STATUS_STYLES = {
  active:  { color: 'var(--clean)',  bg: 'rgba(16,185,129,0.12)',  label: 'Active'  },
  error:   { color: 'var(--critical)', bg: 'rgba(239,68,68,0.12)', label: 'Error'   },
  syncing: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.12)',   label: 'Syncing' },
  unknown: { color: 'var(--text-muted)', bg: 'rgba(71,85,105,0.12)', label: 'Unknown' },
}

function relativeTime(dateStr) {
  if (!dateStr) return 'Never'
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(mins / 60)
  const days  = Math.floor(hours / 24)
  if (days > 0) return `${days}d ago`
  if (hours > 0) return `${hours}h ago`
  if (mins > 0) return `${mins}m ago`
  return 'Just now'
}

export default function FeedHealthWidget({ feed, onRefreshed }) {
  const [refreshing, setRefreshing] = useState(false)
  const [localFeed, setLocalFeed] = useState(feed)

  const status = localFeed?.status || 'unknown'
  const style = STATUS_STYLES[status] || STATUS_STYLES.unknown

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      const res = await refreshFeed(localFeed.feed_name)
      if (res.data?.success) {
        setLocalFeed(f => ({ ...f, status: res.data.data.status }))
        onRefreshed?.()
      }
    } catch {
      // keep existing status
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '14px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '13px' }}>
          {localFeed?.display_name || localFeed?.feed_name}
        </span>
        <span style={{
          fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
          padding: '2px 8px', borderRadius: '999px',
          color: style.color, background: style.bg, border: `1px solid ${style.color}44`,
        }}>
          {style.label}
        </span>
      </div>

      <div style={{ display: 'flex', gap: '14px', fontSize: '11px', color: 'var(--text-muted)' }}>
        <span>Last synced: <span style={{ color: 'var(--text-secondary)' }}>{relativeTime(localFeed?.last_synced)}</span></span>
        {localFeed?.record_count > 0 && (
          <span>Records: <span style={{ color: 'var(--text-secondary)' }}>{localFeed.record_count}</span></span>
        )}
      </div>

      {localFeed?.error_message && (
        <p style={{ color: 'var(--critical)', fontSize: '11px', margin: 0, lineHeight: 1.4 }}>
          {localFeed.error_message}
        </p>
      )}

      <button
        onClick={handleRefresh}
        disabled={refreshing}
        style={{
          alignSelf: 'flex-start',
          padding: '4px 12px',
          borderRadius: '4px',
          border: '1px solid var(--border)',
          background: 'transparent',
          color: refreshing ? 'var(--text-muted)' : 'var(--accent)',
          cursor: refreshing ? 'not-allowed' : 'pointer',
          fontSize: '11px',
          fontFamily: 'inherit',
          display: 'flex',
          alignItems: 'center',
          gap: '5px',
          transition: 'color 0.15s',
        }}
      >
        {refreshing ? (
          <>
            <MiniSpinner />
            Refreshing…
          </>
        ) : 'Refresh'}
      </button>
    </div>
  )
}

function MiniSpinner() {
  return (
    <div style={{
      width: 10, height: 10, borderRadius: '50%',
      border: '1.5px solid var(--text-muted)',
      borderTopColor: 'var(--accent)',
      animation: 'spin 0.7s linear infinite',
    }} />
  )
}
