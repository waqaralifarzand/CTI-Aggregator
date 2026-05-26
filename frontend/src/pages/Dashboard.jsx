import PageWrapper from '../components/layout/PageWrapper'

export default function Dashboard() {
  return (
    <PageWrapper>
      <h1 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700 }}>
        Dashboard
      </h1>
      <p style={{ color: 'var(--text-muted)', marginTop: '8px' }}>
        Coming in Phase 4.
      </p>
    </PageWrapper>
  )
}
