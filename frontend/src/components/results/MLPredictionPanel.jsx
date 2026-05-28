import SeverityBadge from '../shared/SeverityBadge'

const SEVER_COLOR = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  clean: 'var(--clean)',
}

export default function MLPredictionPanel({ mlSeverity, mlConfidence, animStyle }) {
  const trained = mlSeverity !== null && mlSeverity !== undefined
  const percent = trained ? Math.round((mlConfidence || 0) * 100) : 0
  const barColor = SEVER_COLOR[mlSeverity] || 'var(--text-muted)'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
      ...animStyle,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
            padding: '2px 6px', borderRadius: '3px',
            background: 'rgba(59,130,246,0.15)', color: 'var(--info)',
          }}>ML</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '14px' }}>
            ML Severity Prediction
          </span>
        </div>
        {trained && <SeverityBadge severity={mlSeverity} size="md" />}
      </div>

      {trained ? (
        <>
          <div style={{ marginBottom: '6px', display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Random Forest confidence</span>
            <span style={{ fontSize: '13px', fontWeight: 700, color: barColor }}>{percent}%</span>
          </div>
          <div style={{ height: '8px', background: 'var(--border)', borderRadius: '999px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${percent}%`,
              background: barColor,
              borderRadius: '999px',
              transition: 'width 0.6s ease',
            }} />
          </div>
        </>
      ) : (
        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0 }}>
          Model not trained yet — run 50+ scans first, then trigger training from the ML Insights page.
        </p>
      )}
    </div>
  )
}
