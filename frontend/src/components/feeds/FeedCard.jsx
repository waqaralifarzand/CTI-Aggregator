import React, { useState } from 'react'
import { refreshFeed } from '../../api/client'

const statusConfig = {
  active: { color: 'var(--clean)', bg: 'rgba(16,185,129,0.15)', label: 'Active' },
  online: { color: 'var(--clean)', bg: 'rgba(16,185,129,0.15)', label: 'Online' },
  error: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.15)', label: 'Error' },
  auth_error: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.15)', label: 'Auth Error' },
  syncing: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.15)', label: 'Syncing' },
  degraded: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.15)', label: 'Degraded' },
  timeout: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.15)', label: 'Timeout' },
  offline: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.15)', label: 'Offline' },
  no_key: { color: 'var(--text-muted)', bg: 'rgba(71,85,105,0.15)', label: 'No API Key' },
  unknown: { color: 'var(--text-muted)', bg: 'rgba(71,85,105,0.15)', label: 'Unknown' },
}

const feedMeta = {
  otx: { name: 'AlienVault OTX', borderColor: 'var(--accent)' },
  virustotal: { name: 'VirusTotal', borderColor: '#4f46e5' },
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

export default function FeedCard({ feed: initialFeed }) {
  const [feed, setFeed] = useState(initialFeed)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshMsg, setRefreshMsg] = useState(null)

  const handleRefresh = async () => {
    setRefreshing(true)
    setRefreshMsg(null)
    try {
      const res = await refreshFeed(feed.feed_name)
      if (res.data.success) {
        const d = res.data.data
        setFeed(prev => ({
          ...prev,
          status: d.status,
          last_synced: d.last_synced || new Date().toISOString(),
          record_count: d.record_count ?? prev.record_count,
          error_message: d.error_message || null,
        }))
        setRefreshMsg(d.error_message ? `Completed with issues` : 'Feed refreshed successfully')
      } else {
        setRefreshMsg('Refresh failed')
      }
    } catch {
      setRefreshMsg('Refresh failed')
    } finally {
      setRefreshing(false)
      setTimeout(() => setRefreshMsg(null), 3000)
    }
  }

  const cfg = statusConfig[feed.status] || statusConfig.unknown
  const meta = feedMeta[feed.feed_name] || { name: feed.feed_name, borderColor: 'var(--border)' }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderLeft: `4px solid ${meta.borderColor}`,
      borderRadius: '10px',
      padding: '20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '14px' }}>
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: '700', color: 'var(--text-primary)', margin: '0 0 6px' }}>
            {meta.name}
          </h3>
          <span style={{ background: cfg.bg, color: cfg.color, borderRadius: '4px', padding: '2px 8px', fontSize: '11px', fontWeight: '700' }}>
            {cfg.label}
          </span>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            color: refreshing ? 'var(--text-muted)' : 'var(--accent)',
            borderRadius: '6px', padding: '6px 12px', cursor: refreshing ? 'not-allowed' : 'pointer',
            fontSize: '12px', fontFamily: 'inherit', display: 'flex', alignItems: 'center', gap: '5px',
            flexShrink: 0,
          }}
        >
          {refreshing ? (
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              style={{ animation: 'spin 1s linear infinite' }}>
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
          ) : (
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4"/>
            </svg>
          )}
          Refresh
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: (refreshMsg || feed.error_message) ? '12px' : 0 }}>
        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '3px' }}>LAST SYNCED</div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{relativeTime(feed.last_synced)}</div>
        </div>
        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '3px' }}>RECORDS</div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{feed.record_count?.toLocaleString() || 0}</div>
        </div>
      </div>

      {feed.error_message && (
        <div style={{ fontSize: '12px', color: 'var(--critical)', background: 'rgba(239,68,68,0.08)', borderRadius: '4px', padding: '6px 10px' }}>
          {feed.error_message}
        </div>
      )}

      {refreshMsg && (
        <div style={{
          marginTop: feed.error_message ? '6px' : 0,
          fontSize: '12px',
          color: refreshMsg.includes('failed') || refreshMsg.includes('issues') ? 'var(--medium)' : 'var(--clean)',
          background: refreshMsg.includes('failed') || refreshMsg.includes('issues') ? 'rgba(234,179,8,0.08)' : 'rgba(16,185,129,0.08)',
          borderRadius: '4px',
          padding: '6px 10px',
        }}>
          {refreshMsg}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
