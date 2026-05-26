import { useMemo } from 'react'

const TYPE_LABELS = {
  ip: 'IP Address',
  domain: 'Domain',
  hash_md5: 'MD5 Hash',
  hash_sha256: 'SHA256 Hash',
  hash_sha1: 'SHA1 Hash',
}

const TYPE_COLORS = {
  ip: 'var(--info)',
  domain: 'var(--accent)',
  hash_md5: 'var(--medium)',
  hash_sha256: 'var(--medium)',
  hash_sha1: 'var(--medium)',
}

function detectTypeClient(value) {
  const v = value.trim()
  if (!v) return null

  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(v)) {
    const parts = v.split('.').map(Number)
    if (parts.every(p => p >= 0 && p <= 255)) return 'ip'
  }

  // IPv6 (basic check)
  if (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v)) return 'ip'

  // MD5 — 32 hex chars
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'hash_md5'

  // SHA256 — 64 hex chars
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'hash_sha256'

  // SHA1 — 40 hex chars
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'hash_sha1'

  // Domain
  if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v)) return 'domain'

  return null
}

export default function IocTypeBadge({ value }) {
  const type = useMemo(() => detectTypeClient(value || ''), [value])

  if (!type || !value?.trim()) return null

  const color = TYPE_COLORS[type] || 'var(--text-muted)'
  const label = TYPE_LABELS[type] || type

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '5px',
      padding: '3px 10px',
      borderRadius: '999px',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      color,
      backgroundColor: `${color}22`,
      border: `1px solid ${color}44`,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: color, display: 'inline-block' }} />
      {label}
    </span>
  )
}

export { detectTypeClient }
