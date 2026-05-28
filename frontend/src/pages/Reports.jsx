import React, { useEffect } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import FilterBar from '../components/reports/FilterBar'
import ReportsTable from '../components/reports/ReportsTable'
import ExportButton from '../components/reports/ExportButton'
import ErrorState from '../components/shared/ErrorState'
import useReports from '../hooks/useReports'

export default function Reports() {
  const {
    results,
    total,
    page,
    limit,
    loading,
    error,
    filters,
    setFilter,
    setPage,
    clearFilters,
    exportCSV,
    exporting,
  } = useReports()

  useEffect(() => { document.title = 'Scan History — CTI Aggregator' }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Top bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '20px 24px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card)',
      }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>
            Scan History
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            {total} total scan{total !== 1 ? 's' : ''} on record
          </p>
        </div>
        <ExportButton onExport={exportCSV} exporting={exporting} />
      </div>

      {/* Filters */}
      <FilterBar filters={filters} onFilterChange={setFilter} onClear={clearFilters} />

      {/* Content */}
      <PageWrapper style={{ flex: 1, padding: 0 }}>
        {error ? (
          <div style={{ padding: '32px' }}>
            <ErrorState message={error} onRetry={() => setPage(page)} />
          </div>
        ) : (
          <ReportsTable
            results={results}
            loading={loading}
            total={total}
            page={page}
            limit={limit}
            onPageChange={setPage}
          />
        )}
      </PageWrapper>
    </div>
  )
}
