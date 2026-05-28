import React, { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import ScanBar from '../components/scanner/ScanBar'
import ScanningState from '../components/scanner/ScanningState'
import useScan from '../hooks/useScan'
import { getRecentScans } from '../api/client'
import SeverityBadge from '../components/shared/SeverityBadge'

function RecentScansQuickLinks() {
  const [scans, setScans] = useState([])

  useEffect(() => {
    getRecentScans(3)
      .then(res => {
        if (res.data.success) setScans(res.data.data || [])
      })
      .catch(() => {})
  }, [])

  if (!scans.length) return null

  return (
    <div style={{ marginTop: '24px' }}>
      <div style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>
        Recent Scans
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {scans.map(s => (
          <Link
            key={s.scan_id}
            to={`/results/${s.scan_id}`}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: '6px', padding: '8px 12px', textDecoration: 'none',
            }}
          >
            <span className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {s.ioc_value?.length > 40 ? s.ioc_value.slice(0, 40) + '…' : s.ioc_value}
            </span>
            <SeverityBadge severity={s.overall_severity} />
          </Link>
        ))}
      </div>
    </div>
  )
}

export default function Home() {
  const navigate = useNavigate()
  const { loading, error, submitScan } = useScan()

  useEffect(() => { document.title = 'CTI Aggregator' }, [])

  const handleScan = async (value) => {
    const id = await submitScan(value)
    if (id) navigate(`/results/${id}`)
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '32px 24px',
      background: 'var(--bg-primary)',
    }}>
      <div style={{ width: '100%', maxWidth: '680px' }}>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(6,182,212,0.1)',
            border: '1px solid rgba(6,182,212,0.3)',
            borderRadius: '20px',
            padding: '4px 14px',
            fontSize: '12px',
            color: 'var(--accent)',
            fontWeight: '600',
            marginBottom: '20px',
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
          }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent)', display: 'inline-block' }} />
            Threat Intelligence Platform
          </div>
          <h1 style={{
            fontSize: '42px',
            fontWeight: '800',
            color: 'var(--text-primary)',
            margin: '0 0 12px',
            lineHeight: 1.15,
            letterSpacing: '-0.5px',
          }}>
            CTI Aggregator
          </h1>
          <p style={{
            fontSize: '16px',
            color: 'var(--text-secondary)',
            margin: 0,
          }}>
            Scan IP addresses, domains, and file hashes against multiple threat intelligence feeds
          </p>
        </div>

        {loading ? (
          <ScanningState />
        ) : (
          <ScanBar onScan={handleScan} loading={loading} />
        )}

        {error && (
          <div style={{
            marginTop: '16px',
            padding: '10px 14px',
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: '6px',
            color: 'var(--critical)',
            fontSize: '13px',
            textAlign: 'center',
          }}>
            {error}
          </div>
        )}

        <div style={{
          marginTop: '32px',
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '12px',
        }}>
          {[
            { label: 'IP Address', example: '8.8.8.8', icon: '🌐' },
            { label: 'Domain', example: 'malware.example.com', icon: '🔗' },
            { label: 'File Hash', example: 'MD5 / SHA256', icon: '🔒' },
          ].map((item) => (
            <div key={item.label} style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '14px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '20px', marginBottom: '6px' }}>{item.icon}</div>
              <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>{item.label}</div>
              <div className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{item.example}</div>
            </div>
          ))}
        </div>

        <RecentScansQuickLinks />
      </div>
    </div>
  )
}
