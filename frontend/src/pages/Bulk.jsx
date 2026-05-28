import React, { useState, useEffect, useRef } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import CsvUploader from '../components/bulk/CsvUploader'
import BulkProgressBar from '../components/bulk/BulkProgressBar'
import BulkResultsTable from '../components/bulk/BulkResultsTable'
import { uploadBulkScan, getBulkJob } from '../api/client'

export default function Bulk() {
  const [jobId, setJobId] = useState(null)
  const [job, setJob] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const pollRef = useRef(null)

  const handleUpload = async (file) => {
    setUploading(true)
    setError(null)
    setJobId(null)
    setJob(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await uploadBulkScan(formData)
      if (res.data.success) {
        setJobId(res.data.data.job_id)
      } else {
        setError(res.data.error || 'Upload failed')
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  useEffect(() => {
    if (!jobId) return
    const poll = async () => {
      try {
        const res = await getBulkJob(jobId)
        if (res.data.success) {
          setJob(res.data.data)
          if (res.data.data.status === 'done' || res.data.data.status === 'error') {
            clearInterval(pollRef.current)
          }
        }
      } catch {}
    }
    poll()
    pollRef.current = setInterval(poll, 2000)
    return () => clearInterval(pollRef.current)
  }, [jobId])

  const handleReset = () => {
    clearInterval(pollRef.current)
    setJobId(null)
    setJob(null)
    setError(null)
  }

  return (
    <PageWrapper>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '28px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>Bulk Scanner</h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>
            Upload a CSV with one IoC per line — up to 500 items
          </p>
        </div>
        {job && (
          <button onClick={handleReset} style={{
            background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)',
            borderRadius: '6px', padding: '7px 14px', cursor: 'pointer', fontSize: '13px', fontFamily: 'inherit',
          }}>
            ← New Scan
          </button>
        )}
      </div>

      {error && (
        <div style={{
          marginBottom: '16px', padding: '12px 16px',
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: '8px', fontSize: '13px', color: 'var(--critical)',
        }}>
          {error}
        </div>
      )}

      {!jobId && !job && (
        <div>
          <CsvUploader onUpload={handleUpload} />
          {uploading && (
            <div style={{ marginTop: '16px', fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center' }}>
              Uploading...
            </div>
          )}
          <div style={{ marginTop: '20px', padding: '16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: '600', textTransform: 'uppercase' }}>
              CSV Format
            </div>
            <pre className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
{`8.8.8.8
malware.example.com
44d88612fea8a8f36de82e1278abb02f`}
            </pre>
          </div>
        </div>
      )}

      {job && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <BulkProgressBar completed={job.completed} total={job.total} status={job.status} />
          <BulkResultsTable results={job.results || []} />
        </div>
      )}
    </PageWrapper>
  )
}
