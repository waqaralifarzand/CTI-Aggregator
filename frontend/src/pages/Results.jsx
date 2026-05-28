import React, { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan } from '../api/client'
import PageWrapper from '../components/layout/PageWrapper'
import ThreatOverviewCard from '../components/results/ThreatOverviewCard'
import OTXPanel from '../components/results/OTXPanel'
import AbuseChPanel from '../components/results/AbuseChPanel'
import BlacklistPanel from '../components/results/BlacklistPanel'
import MLPredictionPanel from '../components/results/MLPredictionPanel'
import GeoPanel from '../components/results/GeoPanel'
import WhoisPanel from '../components/results/WhoisPanel'
import RecommendationsPanel from '../components/results/RecommendationsPanel'
import SeverityBadge from '../components/shared/SeverityBadge'
import CopyButton from '../components/shared/CopyButton'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'

function ScanNotFound({ message }) {
  return (
    <div style={{ textAlign: 'center', padding: '64px 24px' }}>
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
        style={{ margin: '0 auto 16px', display: 'block', color: 'var(--critical)' }}>
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
      <p style={{ fontSize: '15px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 8px' }}>
        {message || 'Scan not found or no longer available.'}
      </p>
      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 24px' }}>
        The scan may have expired or the link may be incorrect.
      </p>
      <Link to="/" style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        color: 'var(--accent)', fontSize: '13px', fontWeight: '500',
        textDecoration: 'none',
      }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <line x1="19" y1="12" x2="5" y2="12" /><polyline points="12 19 5 12 12 5" />
        </svg>
        Back to Scanner
      </Link>
    </div>
  )
}

export default function Results() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    document.title = 'Scan Results — CTI Aggregator'
  }, [])

  const fetchScan = async () => {
    setLoading(true)
    setError(null)
    setNotFound(false)
    try {
      const res = await getScan(scanId)
      if (res.data.success) setScan(res.data.data)
      else {
        setNotFound(true)
        setError(res.data.error || 'Scan not found or no longer available.')
      }
    } catch (err) {
      if (err.response?.status === 404) {
        setNotFound(true)
        setError('Scan not found or no longer available.')
      } else {
        setError('Failed to load scan results.')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchScan() }, [scanId])

  return (
    <PageWrapper>
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '24px', flexWrap: 'wrap', gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <Link to="/" style={{ color: 'var(--text-muted)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="19" y1="12" x2="5" y2="12" /><polyline points="12 19 5 12 12 5" />
            </svg>
            Scan another
          </Link>
          {scan && (
            <>
              <span style={{ color: 'var(--border)' }}>|</span>
              <span className="mono" style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
                {scan.ioc?.value}
              </span>
              <CopyButton text={scan.ioc?.value || ''} />
              {scan.overall_severity && <SeverityBadge severity={scan.overall_severity} />}
            </>
          )}
        </div>
        {scan && (
          <button
            onClick={() => { navigator.clipboard.writeText(window.location.href) }}
            style={{
              background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)',
              borderRadius: '6px', padding: '6px 12px', cursor: 'pointer', fontSize: '12px',
              display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'inherit',
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            Share
          </button>
        )}
      </div>

      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <LoadingSkeleton height="110px" borderRadius="10px" />
          <LoadingSkeleton height="80px" borderRadius="10px" />
          <LoadingSkeleton height="80px" borderRadius="10px" />
          <LoadingSkeleton height="120px" borderRadius="10px" />
          <LoadingSkeleton height="80px" borderRadius="10px" />
        </div>
      )}

      {!loading && (notFound || error) && (
        <ScanNotFound message={error} />
      )}

      {scan && !loading && !error && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <ThreatOverviewCard scan={scan} />
          <OTXPanel otx={scan.feeds?.otx} />
          <AbuseChPanel urlhaus={scan.feeds?.urlhaus} malwarebazaar={scan.feeds?.malwarebazaar} />
          <BlacklistPanel blacklistStatus={scan.blacklist_status} />
          <MLPredictionPanel mlSeverity={scan.ml_severity} mlConfidence={scan.ml_confidence} />
          {scan.ioc?.type === 'ip' && <GeoPanel geo={scan.feeds?.geo} />}
          {scan.ioc?.type === 'domain' && <WhoisPanel whois={scan.feeds?.whois} />}
          <RecommendationsPanel recommendations={scan.recommendations} />
        </div>
      )}
    </PageWrapper>
  )
}
