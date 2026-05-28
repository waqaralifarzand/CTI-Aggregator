import React, { useEffect, useState } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import MetricCard from '../components/ml/MetricCard'
import FeatureImportanceChart from '../components/ml/FeatureImportanceChart'
import RetrainButton from '../components/ml/RetrainButton'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'
import { getMLMetrics, getMLFeatures } from '../api/client'

export default function MLInsights() {
  const [metrics, setMetrics] = useState(null)
  const [features, setFeatures] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [mRes, fRes] = await Promise.allSettled([getMLMetrics(), getMLFeatures()])
      if (mRes.status === 'fulfilled') {
        const d = mRes.value.data?.data
        setMetrics(d || { model_trained: false })
      }
      if (fRes.status === 'fulfilled') {
        const d = fRes.value.data?.data
        setFeatures(Array.isArray(d) ? d : [])
      }
    } catch {}
    setLoading(false)
  }

  useEffect(() => { fetchData() }, [])

  const modelTrained = metrics?.model_trained === true

  return (
    <PageWrapper>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '28px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>ML Insights</h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>
            Random Forest classifier — performance and feature analysis
          </p>
          {modelTrained && metrics.last_trained && (
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Last trained: {new Date(metrics.last_trained).toLocaleString()} &nbsp;·&nbsp; {metrics.training_samples} samples
            </p>
          )}
        </div>
        <RetrainButton onRetrain={fetchData} />
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
            {Array.from({ length: 4 }).map((_, i) => <LoadingSkeleton key={i} height="110px" borderRadius="10px" />)}
          </div>
          <LoadingSkeleton height="320px" borderRadius="10px" />
        </div>
      ) : !modelTrained ? (
        /* Empty state */
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '48px 32px',
          textAlign: 'center',
        }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5"
            style={{ margin: '0 auto 16px', display: 'block' }}>
            <path d="M12 2a10 10 0 1 0 10 10" />
            <path d="M12 6v6l4 2" />
          </svg>
          <h2 style={{ fontSize: '16px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 8px' }}>
            No model trained yet
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 24px' }}>
            You need at least 50 scans before training. Run scans from the Home page, then click Retrain.
          </p>
          <RetrainButton onRetrain={fetchData} />
        </div>
      ) : (
        <>
          {/* 4 metric cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
            <MetricCard label="Accuracy" value={metrics.accuracy} />
            <MetricCard label="Precision" value={metrics.precision} />
            <MetricCard label="Recall" value={metrics.recall} />
            <MetricCard label="F1-Score" value={metrics.f1_score} />
          </div>

          {/* Feature importance full width */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
            <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Feature Importance
            </h3>
            <FeatureImportanceChart features={features} />
          </div>
        </>
      )}
    </PageWrapper>
  )
}
