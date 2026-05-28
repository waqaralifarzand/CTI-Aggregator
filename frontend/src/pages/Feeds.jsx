import React, { useEffect, useState } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import FeedCard from '../components/feeds/FeedCard'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'
import ErrorState from '../components/shared/ErrorState'
import { getFeeds } from '../api/client'

export default function Feeds() {
  const [feeds, setFeeds] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchFeeds = async () => {
    setLoading(true)
    try {
      const res = await getFeeds()
      if (res.data.success) setFeeds(res.data.data || [])
      else setError(res.data.error || 'Failed to load feeds')
    } catch (err) {
      setError(err.message || 'Failed to load feeds')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchFeeds() }, [])

  return (
    <PageWrapper>
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>Feed Manager</h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>
          Monitor and refresh threat intelligence feed status
        </p>
      </div>

      {loading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {Array.from({ length: 3 }).map((_, i) => <LoadingSkeleton key={i} height="160px" borderRadius="10px" />)}
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={fetchFeeds} />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {feeds.map(f => <FeedCard key={f.feed_name} feed={f} />)}
        </div>
      )}
    </PageWrapper>
  )
}
