import { useState, useEffect } from 'react'
import {
  getDashboardStats,
  getDashboardActivity,
  getSeverityBreakdown,
  getIocBreakdown,
  getTicker,
  getFeeds,
  recentScans,
} from '../api/client'

function makeSection() {
  return { data: null, loading: true, error: null }
}

export default function useDashboard() {
  const [stats,            setStats]            = useState(makeSection())
  const [activity,         setActivity]         = useState(makeSection())
  const [severityBreakdown,setSeverityBreakdown] = useState(makeSection())
  const [iocBreakdown,     setIocBreakdown]     = useState(makeSection())
  const [ticker,           setTicker]           = useState(makeSection())
  const [feeds,            setFeeds]            = useState(makeSection())
  const [recent,           setRecent]           = useState(makeSection())
  const [lastUpdated,      setLastUpdated]      = useState(null)

  function load(apiFn, setter, transform) {
    apiFn()
      .then(res => {
        const data = res.data?.success ? res.data.data : null
        setter({ data: transform ? transform(data) : data, loading: false, error: null })
      })
      .catch(err => setter({ data: null, loading: false, error: err.message || 'Failed' }))
  }

  function fetchAll() {
    setStats(makeSection())
    setActivity(makeSection())
    setSeverityBreakdown(makeSection())
    setIocBreakdown(makeSection())
    setTicker(makeSection())
    setFeeds(makeSection())
    setRecent(makeSection())

    load(getDashboardStats, setStats)
    load(getDashboardActivity, setActivity)
    load(getSeverityBreakdown, setSeverityBreakdown)
    load(getIocBreakdown, setIocBreakdown)
    load(getTicker, setTicker)
    load(getFeeds, setFeeds)
    load(() => recentScans(10), setRecent)

    setLastUpdated(new Date())
  }

  useEffect(() => { fetchAll() }, [])

  return {
    stats, activity, severityBreakdown, iocBreakdown, ticker, feeds, recent,
    lastUpdated, refresh: fetchAll,
  }
}
