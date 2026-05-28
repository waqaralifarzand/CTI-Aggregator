import { useEffect, useRef, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import useScan from '../hooks/useScan'
import IocTypeBadge from '../components/scanner/IocTypeBadge'
import SeverityBadge from '../components/shared/SeverityBadge'
import { recentScans } from '../api/client'

export default function Home() {
  const navigate = useNavigate()
  const { iocValue, setIocValue, loading, error, setError, scan } = useScan()
  const [recents, setRecents] = useState([])
  const inputRef = useRef(null)

  useEffect(() => {
    inputRef.current?.focus()
    recentScans(3)
      .then(res => { if (res.data?.success) setRecents(res.data.data) })
      .catch(() => {})
  }, [])

  const handleSubmit = async (e) => {
    e?.preventDefault()
    if (!iocValue.trim() || loading) return
    const scanId = await scan(iocValue)
    if (scanId) navigate(`/results/${scanId}`)
  }

  return (
    <div style={{
      marginLeft: '240px',
      minHeight: '100vh',
      backgroundColor: 'var(--bg-primary)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px 24px',
    }}>
      {/* Hero area */}
      <div style={{ width: '100%', maxWidth: '680px', textAlign: 'center' }}>
        <p style={{
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.15em',
          textTransform: 'uppercase',
          color: 'var(--text-muted)',
          marginBottom: '14px',
        }}>
          Cyber Threat Intelligence
        </p>

        <h1 style={{
          fontSize: '40px',
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: '0 0 12px',
          lineHeight: 1.15,
        }}>
          <span style={{ color: 'var(--accent)' }}>CTI</span> Aggregator
        </h1>

        <p style={{
          fontSize: '15px',
          color: 'var(--text-secondary)',
          margin: '0 0 36px',
          lineHeight: 1.6,
        }}>
          Look up any IP address, domain, or file hash across multiple threat intelligence feeds
        </p>

        {/* Scan form */}
        <form onSubmit={handleSubmit} style={{ width: '100%' }}>
          <div style={{ position: 'relative' }}>
            <input
              ref={inputRef}
              type="text"
              value={iocValue}
              onChange={e => { setIocValue(e.target.value); setError(null) }}
              onKeyDown={e => e.key === 'Enter' && handleSubmit(e)}
              placeholder="Enter IP address, domain, or file hash..."
              disabled={loading}
              style={{
                width: '100%',
                padding: '16px 20px',
                paddingRight: '120px',
                borderRadius: '8px',
                border: `2px solid ${error ? 'var(--critical)' : 'var(--border)'}`,
                background: 'var(--bg-card)',
                color: 'var(--text-primary)',
                fontSize: '15px',
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
                boxSizing: 'border-box',
                transition: 'border-color 0.2s',
              }}
              onFocus={e => { if (!error) e.target.style.borderColor = 'var(--accent)' }}
              onBlur={e => { if (!error) e.target.style.borderColor = 'var(--border)' }}
            />

            <button
              type="submit"
              disabled={loading || !iocValue.trim()}
              style={{
                position: 'absolute',
                right: '8px',
                top: '50%',
                transform: 'translateY(-50%)',
                padding: '8px 20px',
                borderRadius: '6px',
                border: 'none',
                background: loading || !iocValue.trim() ? 'var(--bg-card-hover)' : 'var(--accent)',
                color: loading || !iocValue.trim() ? 'var(--text-muted)' : '#fff',
                cursor: loading || !iocValue.trim() ? 'not-allowed' : 'pointer',
                fontSize: '13px',
                fontWeight: 600,
                fontFamily: 'inherit',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'background 0.15s',
                whiteSpace: 'nowrap',
              }}
            >
              {loading ? (
                <>
                  <Spinner />
                  Scanning...
                </>
              ) : 'Scan'}
            </button>
          </div>

          {/* Type badge below input */}
          <div style={{ height: '28px', marginTop: '10px', textAlign: 'left' }}>
            <IocTypeBadge value={iocValue} />
          </div>

          {/* Error */}
          {error && (
            <div style={{
              marginTop: '8px',
              padding: '10px 14px',
              borderRadius: '6px',
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.3)',
              color: 'var(--critical)',
              fontSize: '13px',
              textAlign: 'left',
            }}>
              {error}
            </div>
          )}
        </form>

        {/* Hint text */}
        <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '16px' }}>
          Supports IPv4 · IPv6 · Domains · MD5 · SHA1 · SHA256
        </p>
      </div>

      {/* Recent scans */}
      {recents.length > 0 && (
        <div style={{ width: '100%', maxWidth: '680px', marginTop: '48px' }}>
          <p style={{
            fontSize: '11px',
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
            marginBottom: '12px',
          }}>
            Recent Scans
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recents.map(scan => (
              <Link
                key={scan.scan_id}
                to={`/results/${scan.scan_id}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 16px',
                  borderRadius: '6px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  textDecoration: 'none',
                  transition: 'border-color 0.15s, background 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'var(--bg-card-hover)' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-card)' }}
              >
                <span style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '13px',
                  color: 'var(--text-primary)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '420px',
                }}>
                  {scan.ioc_value}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0, marginLeft: '12px' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>
                    {scan.ioc_type?.replace('hash_', '')}
                  </span>
                  <SeverityBadge severity={scan.overall_severity} size="sm" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Spinner() {
  return (
    <div style={{
      width: 12, height: 12,
      borderRadius: '50%',
      border: '2px solid rgba(255,255,255,0.3)',
      borderTopColor: '#fff',
      animation: 'spin 0.7s linear infinite',
      flexShrink: 0,
    }} />
  )
}
