import React from 'react'
import SeverityBadge from '../shared/SeverityBadge'

function scoreColor(score) {
  if (score >= 76) return 'var(--critical)'
  if (score >= 51) return 'var(--high)'
  if (score >= 26) return 'var(--medium)'
  if (score >= 1) return 'var(--low)'
  return 'var(--clean)'
}

export default function ThreatOverviewCard({ scan }) {
  if (!scan) return null
  const { overall_severity, threat_score, ml_severity, ml_confidence, scanned_at } = scan

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '10px',
      padding: '24px',
      display: 'grid',
      gridTemplateColumns: 'auto 1fr auto',
      gap: '24px',
      alignItems: 'center',
    }}>
      {/* Score circle */}
      <div style={{
        width: '90px',
        height: '90px',
        borderRadius: '50%',
        border: `3px solid ${scoreColor(threat_score)}`,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
      }}>
        <span style={{ fontSize: '28px', fontWeight: '800', color: scoreColor(threat_score), lineHeight: 1 }}>
          {threat_score}
        </span>
        <span style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>SCORE</span>
      </div>

      {/* Center info */}
      <div>
        <div style={{ marginBottom: '8px' }}>
          <SeverityBadge severity={overall_severity} />
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 4px' }}>
          Threat Score: <span style={{ color: scoreColor(threat_score), fontWeight: '700' }}>{threat_score}/100</span>
        </p>
        {scanned_at && (
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
            Scanned {new Date(scanned_at).toLocaleString()}
          </p>
        )}
      </div>

      {/* ML prediction */}
      {(ml_severity || ml_confidence) && (
        <div style={{
          background: 'rgba(6,182,212,0.05)',
          border: '1px solid rgba(6,182,212,0.2)',
          borderRadius: '8px',
          padding: '14px 18px',
          textAlign: 'center',
          minWidth: '140px',
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            ML Prediction
          </div>
          <SeverityBadge severity={ml_severity} />
          {ml_confidence != null && (
            <div style={{ marginTop: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Confidence: {Math.round(ml_confidence * 100)}%
              </div>
              <div style={{ height: '4px', background: 'var(--border)', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${ml_confidence * 100}%`,
                  background: 'var(--accent)',
                  borderRadius: '2px',
                  transition: 'width 0.3s',
                }} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
