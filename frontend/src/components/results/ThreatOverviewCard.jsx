import SeverityBadge from '../shared/SeverityBadge'

const SEVERITY_COLOR_VAR = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  clean: 'var(--clean)',
}

function ScoreRing({ score, severity }) {
  const color = SEVERITY_COLOR_VAR[severity] || 'var(--clean)'
  const radius = 44
  const circumference = 2 * Math.PI * radius
  const filled = circumference * (score / 100)
  const gap = circumference - filled

  return (
    <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
      <svg width="110" height="110" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="55" cy="55" r={radius} fill="none" stroke="var(--border)" strokeWidth="8" />
        <circle
          cx="55" cy="55" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${gap}`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: '26px', fontWeight: 700, color, lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>/100</span>
      </div>
    </div>
  )
}

export default function ThreatOverviewCard({ data }) {
  const { overall_severity, threat_score, ml_severity, ml_confidence, scanned_at, ioc } = data

  const formattedDate = scanned_at
    ? new Date(scanned_at).toLocaleString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
      })
    : '—'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '24px',
      display: 'flex',
      alignItems: 'center',
      gap: '32px',
      flexWrap: 'wrap',
    }}>
      <ScoreRing score={threat_score} severity={overall_severity} />

      <div style={{ flex: 1, minWidth: 200 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
            Threat Assessment
          </span>
          <SeverityBadge severity={overall_severity} size="md" />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', fontSize: '13px' }}>
          <span style={{ color: 'var(--text-muted)' }}>Threat Score</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{threat_score}/100</span>

          <span style={{ color: 'var(--text-muted)' }}>IoC Type</span>
          <span style={{ color: 'var(--text-primary)', textTransform: 'uppercase', fontSize: '12px', letterSpacing: '0.04em' }}>{ioc?.type?.replace('hash_', '') || '—'}</span>

          <span style={{ color: 'var(--text-muted)' }}>ML Prediction</span>
          <span style={{ color: 'var(--text-primary)' }}>
            {ml_severity
              ? <><SeverityBadge severity={ml_severity} size="sm" /> <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>{ml_confidence ? `${(ml_confidence * 100).toFixed(0)}% confidence` : ''}</span></>
              : <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Model not trained</span>
            }
          </span>

          <span style={{ color: 'var(--text-muted)' }}>Scanned</span>
          <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>{formattedDate}</span>
        </div>
      </div>
    </div>
  )
}
