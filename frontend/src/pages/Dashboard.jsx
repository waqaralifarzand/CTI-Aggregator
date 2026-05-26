import useDashboard from '../hooks/useDashboard'
import LiveTicker from '../components/dashboard/LiveTicker'
import StatCard from '../components/dashboard/StatCard'
import SeverityDonut from '../components/dashboard/SeverityDonut'
import ActivityLine from '../components/dashboard/ActivityLine'
import IocTypeBar from '../components/dashboard/IocTypeBar'
import FeedHealthWidget from '../components/dashboard/FeedHealthWidget'
import RecentScansTable from '../components/dashboard/RecentScansTable'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'

const CARD_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  padding: '20px',
}

const CHART_HEADER_STYLE = {
  color: 'var(--text-muted)',
  fontSize: '11px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  margin: '0 0 14px',
}

export default function Dashboard() {
  const { stats, activity, severityBreakdown, iocBreakdown, ticker, feeds, recent, lastUpdated, refresh } = useDashboard()

  const statsData = stats.data || {}
  const feedList  = feeds.data || []

  const fmt = (n) => n?.toLocaleString() ?? '—'
  const updatedStr = lastUpdated
    ? lastUpdated.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
    : null

  return (
    <div style={{ marginLeft: '240px', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      {/* Live Ticker — full width, flush */}
      <LiveTicker />

      <div style={{ padding: '24px 28px' }}>
        {/* Page header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
          <div>
            <h1 style={{ color: 'var(--text-primary)', fontSize: '22px', fontWeight: 700, margin: 0 }}>
              Dashboard
            </h1>
            {updatedStr && (
              <p style={{ color: 'var(--text-muted)', fontSize: '12px', margin: '2px 0 0' }}>
                Last updated {updatedStr}
              </p>
            )}
          </div>
          <button
            onClick={refresh}
            style={{
              padding: '6px 14px', borderRadius: '6px',
              border: '1px solid var(--border)', background: 'transparent',
              color: 'var(--accent)', cursor: 'pointer', fontSize: '12px', fontFamily: 'inherit',
            }}
          >
            Refresh
          </button>
        </div>

        {/* Stat Cards */}
        <div style={{ display: 'flex', gap: '14px', marginBottom: '20px', flexWrap: 'wrap' }}>
          <StatCard
            icon={<ScanIcon />}
            label="Total Scans"
            value={stats.loading ? '…' : fmt(statsData.total_scans)}
            accentColor="var(--accent)"
          />
          <StatCard
            icon={<ThreatsIcon />}
            label="Threats Found"
            value={stats.loading ? '…' : fmt(statsData.threats_found)}
            subtitle={statsData.total_scans ? `${Math.round((statsData.threats_found / statsData.total_scans) * 100)}% hit rate` : undefined}
            accentColor="var(--high)"
          />
          <StatCard
            icon={<CriticalIcon />}
            label="Critical Alerts"
            value={stats.loading ? '…' : fmt(statsData.critical_alerts)}
            accentColor="var(--critical)"
          />
          <StatCard
            icon={<CleanIcon />}
            label="Clean Scans"
            value={stats.loading ? '…' : fmt(statsData.clean_scans)}
            accentColor="var(--clean)"
          />
        </div>

        {/* Charts row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 1fr', gap: '14px', marginBottom: '20px' }}>
          <div style={CARD_STYLE}>
            <p style={CHART_HEADER_STYLE}>Severity Breakdown</p>
            <SeverityDonut data={severityBreakdown.data} loading={severityBreakdown.loading} />
          </div>
          <div style={CARD_STYLE}>
            <p style={CHART_HEADER_STYLE}>Scan Activity — Last 7 Days</p>
            <div style={{ display: 'flex', gap: '16px', marginBottom: '10px' }}>
              <Legend color="#06b6d4" label="Total Scans" />
              <Legend color="#f97316" label="Threats" />
            </div>
            <ActivityLine data={activity.data} loading={activity.loading} />
          </div>
          <div style={CARD_STYLE}>
            <p style={CHART_HEADER_STYLE}>IoC Type Breakdown</p>
            <IocTypeBar data={iocBreakdown.data} loading={iocBreakdown.loading} />
          </div>
        </div>

        {/* Bottom row: feed health + recent scans */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '14px', alignItems: 'start' }}>
          {/* Feed health 2×2 grid */}
          <div>
            <p style={{ ...CHART_HEADER_STYLE, marginBottom: '10px' }}>Feed Health</p>
            {feeds.loading ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                {[...Array(4)].map((_, i) => <LoadingSkeleton key={i} height={100} />)}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                {feedList.length > 0
                  ? feedList.map(feed => (
                      <FeedHealthWidget key={feed.feed_name} feed={feed} />
                    ))
                  : [{ feed_name: 'otx', display_name: 'AlienVault OTX', status: 'unknown' },
                     { feed_name: 'urlhaus', display_name: 'URLhaus', status: 'unknown' },
                     { feed_name: 'malwarebazaar', display_name: 'MalwareBazaar', status: 'unknown' },
                     { feed_name: 'virustotal', display_name: 'VirusTotal', status: 'unknown' },
                    ].map(feed => <FeedHealthWidget key={feed.feed_name} feed={feed} />)
                }
              </div>
            )}
          </div>

          {/* Recent scans table */}
          <div style={CARD_STYLE}>
            <p style={CHART_HEADER_STYLE}>Recent Scans</p>
            <RecentScansTable data={recent.data} loading={recent.loading} />
          </div>
        </div>
      </div>
    </div>
  )
}

function Legend({ color, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
      <span style={{ width: 20, height: 2, background: color, display: 'inline-block', borderRadius: '1px' }} />
      {label}
    </div>
  )
}

// Inline SVG icons (monochrome, use currentColor)
function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  )
}
function ThreatsIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  )
}
function CriticalIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    </svg>
  )
}
function CleanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  )
}
