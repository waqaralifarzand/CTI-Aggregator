import React from 'react'
import { NavLink } from 'react-router-dom'

const navItems = [
  {
    path: '/',
    label: 'Scanner',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
    end: true,
  },
  {
    path: '/dashboard',
    label: 'Dashboard',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
      </svg>
    ),
  },
  {
    path: '/reports',
    label: 'Reports',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
  {
    path: '/feeds',
    label: 'Feeds',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 11a9 9 0 0 1 9 9" />
        <path d="M4 4a16 16 0 0 1 16 16" />
        <circle cx="5" cy="19" r="1" />
      </svg>
    ),
  },
  {
    path: '/ml',
    label: 'ML Insights',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z" />
      </svg>
    ),
  },
  {
    path: '/bulk',
    label: 'Bulk Scan',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="16 16 12 12 8 16" />
        <line x1="12" y1="12" x2="12" y2="21" />
        <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" />
      </svg>
    ),
  },
]

const sidebarStyle = {
  position: 'fixed',
  left: 0,
  top: 0,
  bottom: 0,
  width: '240px',
  background: 'var(--bg-card)',
  borderRight: '1px solid var(--border)',
  display: 'flex',
  flexDirection: 'column',
  zIndex: 100,
}

const logoStyle = {
  padding: '24px 20px 20px',
  borderBottom: '1px solid var(--border)',
}

const logoTextStyle = {
  fontSize: '18px',
  fontWeight: '700',
  color: 'var(--accent)',
  fontFamily: "'DM Sans', sans-serif",
  letterSpacing: '-0.3px',
}

const logoSubStyle = {
  fontSize: '11px',
  color: 'var(--text-muted)',
  marginTop: '2px',
  letterSpacing: '0.5px',
  textTransform: 'uppercase',
}

const navStyle = {
  padding: '12px 0',
  flex: 1,
}

export default function Sidebar() {
  return (
    <aside style={sidebarStyle}>
      <div style={logoStyle}>
        <div style={logoTextStyle}>CTI Aggregator</div>
        <div style={logoSubStyle}>Threat Intelligence</div>
      </div>
      <nav style={navStyle}>
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.end}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '10px 20px',
              color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
              background: isActive ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
              borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
              transition: 'all 0.15s ease',
              fontSize: '14px',
              fontWeight: isActive ? '500' : '400',
              textDecoration: 'none',
            })}
            onMouseEnter={(e) => {
              const el = e.currentTarget
              if (el.getAttribute('aria-current') !== 'page') {
                el.style.color = 'var(--text-primary)'
                el.style.background = 'rgba(255,255,255,0.03)'
              }
            }}
            onMouseLeave={(e) => {
              const el = e.currentTarget
              if (el.getAttribute('aria-current') !== 'page') {
                el.style.color = ''
                el.style.background = ''
              }
            }}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border)' }}>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          FYP Demo v1.0
        </div>
      </div>
    </aside>
  )
}
