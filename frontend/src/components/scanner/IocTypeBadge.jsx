import React from 'react'

const typeConfig = {
  ip: { label: 'IP Address', color: 'var(--info)', bg: 'rgba(59,130,246,0.15)' },
  domain: { label: 'Domain', color: 'var(--accent)', bg: 'rgba(6,182,212,0.15)' },
  hash_md5: { label: 'MD5 Hash', color: 'var(--medium)', bg: 'rgba(234,179,8,0.15)' },
  hash_sha256: { label: 'SHA-256 Hash', color: 'var(--high)', bg: 'rgba(249,115,22,0.15)' },
  hash_sha1: { label: 'SHA-1 Hash', color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.15)' },
}

export default function IocTypeBadge({ type }) {
  if (!type) return null
  const cfg = typeConfig[type]
  if (!cfg) return null
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      padding: '3px 10px', borderRadius: '9999px',
      fontSize: '12px', fontWeight: '600',
      color: cfg.color, background: cfg.bg,
    }}>
      <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor">
        <circle cx="5" cy="5" r="5" />
      </svg>
      {cfg.label}
    </span>
  )
}
