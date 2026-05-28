import { useState } from 'react'
import { submitScan } from '../api/client'

export default function useScan() {
  const [iocValue, setIocValue] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const scan = async (value) => {
    const trimmed = (value || iocValue).trim()
    if (!trimmed) return null

    setLoading(true)
    setError(null)

    try {
      const res = await submitScan(trimmed)
      if (res.data?.success) {
        return res.data.data.scan_id
      }
      setError(res.data?.error || 'Scan failed')
      return null
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        err.response?.data?.error ||
        err.message ||
        'Scan request failed'
      setError(msg)
      return null
    } finally {
      setLoading(false)
    }
  }

  return { iocValue, setIocValue, loading, error, setError, scan }
}
