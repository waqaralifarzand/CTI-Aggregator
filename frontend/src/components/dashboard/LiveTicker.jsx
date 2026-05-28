import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTicker } from '../../api/client'
import SeverityBadge from '../shared/SeverityBadge'

export default function LiveTicker() {
  const [items, setItems] = useState([])
  const [paused, setPaused] = useState(false)
  const navigate = useNavigate()

  const fetchTicker = () => {
    getTicker(20)
      .then(res => { if (res.data?.success) setItems(res.data.data) })
      .catch(() => {})
  }

  useEffect(() => {
    fetchTicker()
    const interval = setInterval(fetchTicker, 30000)
    return () => clearInterval(interval)
  }, [])

  if (!items.length) return null

  // Duplicate items for seamless infinite scroll
  const doubled = [...items, ...items]

  return (
    <div style={{
      background: 'var(--bg-card)',
      borderTop: '1px solid var(--border)',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      height: '38px',
      overflow: 'hidden',
      position: 'relative',
    }}>
      {/* Static left label */}
      <div style={{
        flexShrink: 0,
        padding: '0 14px',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        height: '100%',
        background: 'var(--bg-card)',
        zIndex: 2,
      }}>
        <span style={{
          color: 'var(--critical)',
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          fontFamily: 'JetBrains Mono, monospace',
          whiteSpace: 'nowrap',
        }}>
          ⚠ LIVE THREATS
        </span>
      </div>

      {/* Scrolling strip */}
      <div
        style={{ overflow: 'hidden', flex: 1, position: 'relative' }}
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
      >
        <div style={{
          display: 'flex',
          alignItems: 'center',
          whiteSpace: 'nowrap',
          animation: 'marquee 40s linear infinite',
          animationPlayState: paused ? 'paused' : 'running',
          gap: '0',
        }}>
          {doubled.map((item, idx) => (
            <button
              key={`${item.scan_id}-${idx}`}
              onClick={() => navigate(`/results/${item.scan_id}`)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '0 20px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                borderRight: '1px solid var(--border)',
                height: '38px',
                flexShrink: 0,
              }}
            >
              <SeverityBadge severity={item.severity} size="sm" />
              <span style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '12px',
                color: 'var(--text-primary)',
              }}>
                {item.ioc_value}
              </span>
              {item.tags?.length > 0 && (
                <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                  [{item.tags.join(', ')}]
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
