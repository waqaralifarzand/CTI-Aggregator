import React, { useEffect, useState } from 'react'
import PageWrapper from '../components/layout/PageWrapper'
import MetricCard from '../components/ml/MetricCard'
import FeatureImportanceChart from '../components/ml/FeatureImportanceChart'
import RetrainButton from '../components/ml/RetrainButton'
import LoadingSkeleton from '../components/shared/LoadingSkeleton'
import EmptyState from '../components/shared/EmptyState'
import { getMLMetrics, getMLFeatures } from '../api/client'

export default function MLInsights() {
  const [metrics, setMetrics] = useState(null)
  const [features, setFeatures] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [mRes, fRes] = await Promise.allSettled([getMLMetrics(), getMLFeatures()])
      if (mRes.status === 'fulfilled') setMetrics(mRes.value.data?.data || null)
      if (fRes.status === 'fulfilled') setFeatures(fRes.value.data?.data || [])
    } catch {}
    setLoading(false)
  }

  useEffect(() => { fetchData() }, [])

  return (
    <PageWrapper>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '28px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>ML Insights</h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '3px' }}>
            Random Forest classifier performance and feature analysis
          </p>
        </div>
        <RetrainButton onRetrain={fetchData} />
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
            {Array.from({ length: 4 }).map((_, i) => <LoadingSkeleton key={i} height="100px" borderRadius="10px" />)}
          </div>
          <LoadingSkeleton height="300px" borderRadius="10px" />
        </div>
      ) : !metrics?.model_trained ? (
        <EmptyState
          message="Model Not Trained Yet"
          subtext="Run at least 50 scans then click 'Retrain Model' to train the Random Forest classifier."
        />
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
            <MetricCard label="Accuracy" value={metrics.accuracy} />
            <MetricCard label="Precision" value={metrics.precision} />
            <MetricCard label="Recall" value={metrics.recall} />
            <MetricCard label="F1-Score" value={metrics.f1_score} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
              <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Training Info
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {[
                  { label: 'Training Samples', value: metrics.training_samples },
                  { label: 'Last Trained', value: metrics.last_trained ? new Date(metrics.last_trained).toLocaleString() : '—' },
                ].map(r => (
                  <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{r.label}</span>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-primary)' }}>{r.value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
              <h3 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-secondary)', margin: '0 0 16px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Feature Importance
              </h3>
              <FeatureImportanceChart features={features} />
            </div>
          </div>
        </>
      )}
    </PageWrapper>
  )
}
