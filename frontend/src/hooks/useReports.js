import { useState, useEffect, useRef, useCallback } from 'react'
import { getReports, exportReports } from '../api/client'

export default function useReports() {
  const [filters, setFilters] = useState({
    severity: '',
    ioc_type: '',
    date_from: '',
    date_to: '',
    search: '',
  })
  const [page, setPage] = useState(1)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exporting, setExporting] = useState(false)

  const searchDebounceRef = useRef(null)
  const pendingSearchRef = useRef(filters.search)

  const buildParams = useCallback((f, p) => {
    const params = { page: p, limit: 20 }
    if (f.severity) params.severity = f.severity
    if (f.ioc_type) params.ioc_type = f.ioc_type
    if (f.date_from) params.date_from = f.date_from
    if (f.date_to) params.date_to = f.date_to
    if (f.search) params.search = f.search
    return params
  }, [])

  const fetchData = useCallback(async (f, p) => {
    setLoading(true)
    setError(null)
    try {
      const res = await getReports(buildParams(f, p))
      setData(res.data?.data || null)
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to load reports')
    } finally {
      setLoading(false)
    }
  }, [buildParams])

  // Fetch when filters (except search debounced) or page change
  useEffect(() => {
    fetchData(filters, page)
  }, [filters.severity, filters.ioc_type, filters.date_from, filters.date_to, page, fetchData])

  const setFilter = useCallback((key, value) => {
    if (key === 'search') {
      pendingSearchRef.current = value
      setFilters(prev => ({ ...prev, search: value }))
      if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current)
      searchDebounceRef.current = setTimeout(() => {
        setPage(1)
        setFilters(prev => ({ ...prev, search: pendingSearchRef.current }))
      }, 300)
    } else {
      setPage(1)
      setFilters(prev => ({ ...prev, [key]: value }))
    }
  }, [])

  const clearFilters = useCallback(() => {
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current)
    setPage(1)
    setFilters({ severity: '', ioc_type: '', date_from: '', date_to: '', search: '' })
  }, [])

  const exportCSV = useCallback(async () => {
    setExporting(true)
    try {
      const exportFilters = {}
      if (filters.severity) exportFilters.severity = filters.severity
      if (filters.ioc_type) exportFilters.ioc_type = filters.ioc_type
      if (filters.date_from) exportFilters.date_from = filters.date_from
      if (filters.date_to) exportFilters.date_to = filters.date_to
      if (filters.search) exportFilters.search = filters.search

      const res = await exportReports(exportFilters)
      const blob = new Blob([res.data], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')

      const disposition = res.headers?.['content-disposition'] || ''
      const match = disposition.match(/filename=([^\s;]+)/)
      a.download = match ? match[1] : 'cti_report.csv'
      a.href = url
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch {
      // silently fail
    } finally {
      setExporting(false)
    }
  }, [filters])

  return {
    results: data?.results || [],
    total: data?.total || 0,
    page,
    limit: data?.limit || 20,
    loading,
    error,
    filters,
    setFilter,
    setPage,
    clearFilters,
    exportCSV,
    exporting,
  }
}
