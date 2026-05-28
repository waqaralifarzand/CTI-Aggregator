import React from 'react'
import SeverityBadge from '../shared/SeverityBadge'

export default function MLPredictionPanel({ mlSeverity, mlConfidence }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)', margin: '0 0 14px' }}>
        ML Classification
      </h3>
      {!mlSeverity ? (
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Model not trained yet. Run at least 50 scans and train via ML Insights.
        </p>
      ) : (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
            <SeverityBadge severity={mlSeverity} />
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              Random Forest prediction
            </span>
          </div>
          {mlConfidence != null && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Confidence</span>
                <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--accent)' }}>
                  {Math.round(mlConfidence * 100)}%
                </span>
              </div>
              <div style={{ height: '6px', background: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${mlConfidence * 100}%`,
                  background: 'var(--accent)',
                  borderRadius: '3px',
                  transition: 'width 0.5s ease',
                }} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
