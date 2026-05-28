import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Scan
export const submitScan  = (value) => api.post('/api/scan', { value })
export const getScan     = (scanId) => api.get(`/api/scan/${scanId}`)
export const recentScans = (limit = 10) => api.get(`/api/scans/recent?limit=${limit}`)

// Bulk
export const submitBulk = (formData) => api.post('/api/bulk/scan', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
export const getBulkJob = (jobId) => api.get(`/api/bulk/${jobId}`)

// Feeds
export const getFeeds    = () => api.get('/api/feeds')
export const refreshFeed = (feedName) => api.post(`/api/feeds/${feedName}/refresh`)

// Reports
export const getReports   = (params) => api.get('/api/reports', { params })
export const exportReports = (params) => api.get('/api/reports/export', { params, responseType: 'blob' })

// ML
export const getMLMetrics         = () => api.get('/api/ml/metrics')
export const trainModel           = () => api.post('/api/ml/train')
export const getFeatureImportance = () => api.get('/api/ml/features')

// Dashboard
export const getDashboardStats    = () => api.get('/api/dashboard/stats')
export const getDashboardActivity = (days = 7) => api.get(`/api/dashboard/activity?days=${days}`)
export const getSeverityBreakdown = () => api.get('/api/dashboard/severity-breakdown')
export const getIocBreakdown      = () => api.get('/api/dashboard/ioc-breakdown')
export const getTicker            = (limit = 20) => api.get(`/api/dashboard/ticker?limit=${limit}`)

export default api
