import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan } from '../api/client'
import { SkeletonPanel } from '../components/shared/LoadingSkeleton'
import ErrorState from '../components/shared/ErrorState'
import SeverityBadge from '../components/shared/SeverityBadge'
import CopyButton from '../components/shared/CopyButton'
import ShareButton from '../components/shared/ShareButton'
import IocTypeBadge from '../components/scanner/IocTypeBadge'
import ThreatOverviewCard from '../components/results/ThreatOverviewCard'
import OTXPanel from '../components/results/OTXPanel'
import AbuseChPanel from '../components/results/AbuseChPanel'
import VirusTotalPanel from '../components/results/VirusTotalPanel'
import BlacklistPanel from '../components/results/BlacklistPanel'
import MLPredictionPanel from '../components/results/MLPredictionPanel'
import GeoPanel from '../components/results/GeoPanel'
import WhoisPanel from '../components/results/WhoisPanel'
import RecommendationsPanel from '../components/results/RecommendationsPanel'

function useAnimStyle(index) {
  return {
    opacity: 1,
    transform: 'translateY(0)',
    transition: `opacity 0.3s ease ${index * 80}ms, transform 0.3s ease ${index * 80}ms`,
  }
}

export default function Results() {
  const { scanId } = useParams()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadScan = () => {
    setLoading(true)
    setError(null)
    getScan(scanId)
      .then(res => {
        if (res.data?.success) {
          setData(res.data.data)
        } else {
          setError(res.data?.error || 'Scan not found')
        }
      })
      .catch(err => {
        if (err.response?.status === 404) {
          setError('Scan not found. This link may have expired or the ID is invalid.')
        } else {
          setError(err.message || 'Failed to load scan results')
        }
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadScan() }, [scanId])

  return (
    <div style={{
      marginLeft: '240px',
      minHeight: '100vh',
      backgroundColor: 'var(--bg-primary)',
    }}>
      {/* Sticky top bar */}
      <div style={{
        position: 'sticky',
        top: 0,
        zIndex: 50,
        background: 'var(--bg-card)',
        borderBottom: '1px solid var(--border)',
        padding: '12px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0, flex: 1 }}>
          <Link
            to="/"
            style={{
              color: 'var(--text-muted)',
              textDecoration: 'none',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              flexShrink: 0,
              whiteSpace: 'nowrap',
            }}
          >
            ← Scan Another
          </Link>
          <span style={{ color: 'var(--border)', flexShrink: 0 }}>|</span>
          {data && (
            <>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '13px',
                color: 'var(--text-primary)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {data.ioc?.value}
              </span>
              <IocTypeBadge value={data.ioc?.value} />
              <CopyButton text={data.ioc?.value} />
            </>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          {data && <SeverityBadge severity={data.overall_severity} size="md" />}
          <ShareButton />
        </div>
      </div>

      {/* Main content */}
      <div style={{ padding: '28px 32px', maxWidth: '860px' }}>
        {loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[...Array(6)].map((_, i) => <SkeletonPanel key={i} />)}
          </div>
        )}

        {!loading && error && (
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
          }}>
            <ErrorState message={error} onRetry={loadScan} />
          </div>
        )}

        {!loading && data && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <ThreatOverviewCard data={data} animStyle={useAnimStyle(0)} />
            <OTXPanel otx={data.feeds?.otx} animStyle={useAnimStyle(1)} />
            <AbuseChPanel
              urlhaus={data.feeds?.urlhaus}
              malwarebazaar={data.feeds?.malwarebazaar}
              animStyle={useAnimStyle(2)}
            />
            <VirusTotalPanel vt={data.feeds?.virustotal} animStyle={useAnimStyle(3)} />
            <BlacklistPanel blacklistStatus={data.blacklist_status} animStyle={useAnimStyle(4)} />
            <MLPredictionPanel
              mlSeverity={data.ml_severity}
              mlConfidence={data.ml_confidence}
              animStyle={useAnimStyle(5)}
            />
            {data.ioc?.type === 'ip' && data.feeds?.geo && (
              <GeoPanel geo={data.feeds.geo} animStyle={useAnimStyle(6)} />
            )}
            {data.ioc?.type === 'domain' && data.feeds?.whois && (
              <WhoisPanel whois={data.feeds.whois} animStyle={useAnimStyle(7)} />
            )}
            {data.recommendations?.length > 0 && (
              <RecommendationsPanel recommendations={data.recommendations} animStyle={useAnimStyle(8)} />
            )}
          </div>
        )}
      </div>
    </div>
  )
}
