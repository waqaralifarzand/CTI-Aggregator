import { useState } from 'react'
import { scanIoc } from '../api/client'

export default function useScan() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [scanId, setScanId] = useState(null)

  const submitScan = async (value) => {
    setLoading(true)
    setError(null)
    setScanId(null)
    try {
      const res = await scanIoc(value.trim())
      const data = res.data
      if (data.success) {
        setScanId(data.data.scan_id)
        return data.data.scan_id
      } else {
        setError(data.error || 'Scan failed')
        return null
      }
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Scan failed'
      setError(msg)
      return null
    } finally {
      setLoading(false)
    }
  }

  return { loading, error, scanId, submitScan }
}
