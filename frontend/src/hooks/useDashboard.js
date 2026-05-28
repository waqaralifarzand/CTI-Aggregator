import { useState, useEffect } from 'react'
import {
  getDashboardStats,
  getDashboardActivity,
  getSeverityBreakdown,
  getIocBreakdown,
  getDashboardTicker,
  getRecentScans,
  getFeeds,
} from '../api/client'

export default function useDashboard() {
  const [stats, setStats] = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [statsError, setStatsError] = useState(null)

  const [activity, setActivity] = useState([])
  const [activityLoading, setActivityLoading] = useState(true)

  const [severityBreakdown, setSeverityBreakdown] = useState([])
  const [iocBreakdown, setIocBreakdown] = useState([])
  const [chartsLoading, setChartsLoading] = useState(true)

  const [ticker, setTicker] = useState([])
  const [recentScans, setRecentScans] = useState([])
  const [recentLoading, setRecentLoading] = useState(true)

  const [feeds, setFeeds] = useState([])

  useEffect(() => {
    let mounted = true

    const fetchAll = async () => {
      try {
        const [statsRes, activityRes, sevRes, iocRes, recentRes, feedsRes] = await Promise.allSettled([
          getDashboardStats(),
          getDashboardActivity(),
          getSeverityBreakdown(),
          getIocBreakdown(),
          getRecentScans(10),
          getFeeds(),
        ])

        if (!mounted) return

        if (statsRes.status === 'fulfilled') setStats(statsRes.value.data?.data)
        else setStatsError('Failed to load stats')
        setStatsLoading(false)

        if (activityRes.status === 'fulfilled') setActivity(activityRes.value.data?.data || [])
        setActivityLoading(false)

        if (sevRes.status === 'fulfilled') setSeverityBreakdown(sevRes.value.data?.data || [])
        if (iocRes.status === 'fulfilled') setIocBreakdown(iocRes.value.data?.data || [])
        setChartsLoading(false)

        if (recentRes.status === 'fulfilled') setRecentScans(recentRes.value.data?.data || [])
        setRecentLoading(false)

        if (feedsRes.status === 'fulfilled') setFeeds(feedsRes.value.data?.data || [])
      } catch {
        if (mounted) {
          setStatsLoading(false)
          setActivityLoading(false)
          setChartsLoading(false)
          setRecentLoading(false)
        }
      }
    }

    fetchAll()
    return () => { mounted = false }
  }, [])

  const fetchTicker = async () => {
    try {
      const res = await getDashboardTicker(20)
      setTicker(res.data?.data || [])
    } catch {}
  }

  useEffect(() => {
    fetchTicker()
    const interval = setInterval(fetchTicker, 30000)
    return () => clearInterval(interval)
  }, [])

  return {
    stats, statsLoading, statsError,
    activity, activityLoading,
    severityBreakdown, iocBreakdown, chartsLoading,
    ticker,
    recentScans, recentLoading,
    feeds,
  }
}
