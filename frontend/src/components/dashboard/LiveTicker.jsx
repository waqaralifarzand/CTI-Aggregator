import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getDashboardTicker } from '../../api/client'

export default function LiveTicker() {
  const [items, setItems] = useState([])

  const fetchTicker = async () => {
    try {
      const res = await getDashboardTicker(20)
      if (res.data.success) setItems(res.data.data || [])
    } catch { /* silent */ }
  }

  useEffect(() => {
    fetchTicker()
    const id = setInterval(fetchTicker, 30000)
    return () => clearInterval(id)
  }, [])

  if (!items.length) return null

  const severityColor = (sev) => {
    if (sev === 'critical') return 'var(--critical)'
    if (sev === 'high') return 'var(--high)'
    return 'var(--medium)'
  }

  return (
    <div style={{
      background: 'rgba(6,182,212,0.04)',
      borderBottom: '1px solid var(--border)',
      padding: '8px 0',
      overflow: 'hidden',
      position: 'relative',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
        <span style={{
          flexShrink: 0,
          padding: '0 14px',
          fontSize: '11px',
          fontWeight: '700',
          color: 'var(--accent)',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
          borderRight: '1px solid var(--border)',
          marginRight: '12px',
        }}>
          LIVE THREATS
        </span>
        <div style={{ overflow: 'hidden', flex: 1 }}>
          <div className="marquee-track" style={{ display: 'inline-flex', gap: '32px' }}>
            {[...items, ...items].map((item, i) => (
              <Link
                key={i}
                to={item.scan_id ? `/results/${item.scan_id}` : '#'}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', textDecoration: 'none' }}
              >
                <span style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  background: severityColor(item.severity), flexShrink: 0,
                }} />
                <span className="mono" style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                  {item.ioc_value?.length > 30 ? item.ioc_value.slice(0, 30) + '…' : item.ioc_value}
                </span>
                <span style={{ fontSize: '11px', color: severityColor(item.severity), fontWeight: '600', textTransform: 'capitalize' }}>
                  [{item.severity}]
                </span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
