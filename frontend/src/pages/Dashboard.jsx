import React, { useEffect } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import LiveTicker from '../components/dashboard/LiveTicker'
import StatCard from '../components/dashboard/StatCard'
import SeverityDonut from '../components/dashboard/SeverityDonut'
import IocTypeBar from '../components/dashboard/IocTypeBar'
import ActivityLine from '../components/dashboard/ActivityLine'
import RecentScansTable from '../components/dashboard/RecentScansTable'
import FeedHealthWidget from '../components/dashboard/FeedHealthWidget'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'
import EmptyState from '../components/shared/EmptyState'
import ErrorState from '../components/shared/ErrorState'
import useDashboard from '../hooks/useDashboard'

const cardStyle = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: '10px',
}

export default function Dashboard() {
  const {
    stats, statsLoading, statsError,
    activity, activityLoading,
    severityBreakdown, iocBreakdown, chartsLoading,
    recentScans, recentLoading,
    feeds,
  } = useDashboard()

  useEffect(() => { document.title = 'Dashboard — CTI Aggregator' }, [])

  const noData = !statsLoading && !statsError && (stats?.total_scans ?? 0) === 0

  return (
    <div>
      <LiveTicker />
      <PageWrapper>
        <div style={{ marginBottom: '24px' }}>
          <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>Dashboard</h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>Threat intelligence overview</p>
        </div>

        {/* Stat cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
          {statsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <LoadingSkeleton key={i} height="100px" borderRadius="10px" />)
          ) : statsError ? (
            <div style={{ gridColumn: '1 / -1' }}>
              <ErrorState message="Failed to load statistics" />
            </div>
          ) : (
            <>
              <StatCard label="Total Scans" value={stats?.total_scans ?? 0}
                icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>} />
              <StatCard label="Threats Found" value={stats?.threats_found ?? 0}
                icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>} />
              <StatCard label="Critical Alerts" value={stats?.critical_alerts ?? 0}
                icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>} />
              <StatCard label="Clean Scans" value={stats?.clean_scans ?? 0}
                icon={<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>} />
            </>
          )}
        </div>

        {/* Charts row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '24px' }}>
          {[
            { title: 'Severity Breakdown', component: noData ? <EmptyState message="No data yet" subtext="Run your first scan to see data" /> : <SeverityDonut data={severityBreakdown} /> },
            { title: 'IoC Types', component: noData ? <EmptyState message="No data yet" subtext="Run your first scan to see data" /> : <IocTypeBar data={iocBreakdown} /> },
            { title: '7-Day Activity', component: noData ? <EmptyState message="No data yet" subtext="Run your first scan to see data" /> : <ActivityLine data={activity} /> },
          ].map(({ title, component }) => (
            <div key={title} style={{ ...cardStyle, padding: '20px' }}>
              <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {title}
              </h3>
              {chartsLoading || activityLoading ? <LoadingSkeleton height="200px" /> : component}
            </div>
          ))}
        </div>

        {/* Bottom row */}
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '16px' }}>
          <div style={{ ...cardStyle, padding: '20px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Feed Health
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {feeds.map(f => <FeedHealthWidget key={f.feed_name} feed={f} />)}
              {!feeds.length && (
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center', padding: '16px' }}>No feeds</div>
              )}
            </div>
          </div>

          <div style={cardStyle}>
            <div style={{ padding: '20px 20px 0' }}>
              <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Recent Scans
              </h3>
            </div>
            {recentLoading ? (
              <div style={{ padding: '20px' }}><LoadingSkeleton height="160px" /></div>
            ) : noData ? (
              <EmptyState message="No scans yet" subtext="Run your first scan from the Scanner page" />
            ) : (
              <RecentScansTable scans={recentScans} />
            )}
          </div>
        </div>
      </PageWrapper>
    </div>
  )
}
