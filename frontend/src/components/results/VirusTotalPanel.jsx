function severityFromRatio(detections, total) {
  if (!total || detections === 0) return 'clean'
  const ratio = detections / total
  if (ratio >= 0.4) return 'critical'
  if (ratio >= 0.2) return 'high'
  if (ratio >= 0.05) return 'medium'
  return 'low'
}

const SEVER_COLOR = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  clean: 'var(--clean)',
}

export default function VirusTotalPanel({ vt, animStyle }) {
  const detections = vt?.detections ?? 0
  const total = vt?.total_engines ?? 0
  const found = vt?.found
  const configured = !(vt?.raw_data?.note?.includes('not configured'))

  const severity = severityFromRatio(detections, total)
  const barColor = SEVER_COLOR[severity]
  const percent = total > 0 ? (detections / total) * 100 : 0

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${found ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
      borderRadius: '8px',
      padding: '20px',
      opacity: found ? 1 : 0.8,
      ...animStyle,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
            padding: '2px 6px', borderRadius: '3px',
            background: 'rgba(59,130,246,0.15)', color: 'var(--info)',
          }}>VT</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '14px' }}>VirusTotal</span>
        </div>
        {!configured ? (
          <span style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic' }}>API key not configured</span>
        ) : found ? (
          <span style={{ color: 'var(--critical)', fontSize: '12px', fontWeight: 600 }}>⚠ {detections} engines flagged</span>
        ) : (
          <span style={{ color: 'var(--clean)', fontSize: '12px' }}>✓ No detections</span>
        )}
      </div>

      {configured && total > 0 && (
        <>
          <div style={{ marginBottom: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Detection ratio</span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: barColor }}>
                {detections} / {total} engines
              </span>
            </div>
            <div style={{ height: '8px', background: 'var(--border)', borderRadius: '999px', overflow: 'hidden' }}>
              <div style={{
                height: '100%',
                width: `${percent}%`,
                background: barColor,
                borderRadius: '999px',
                transition: 'width 0.6s ease',
                minWidth: found ? '4px' : 0,
              }} />
            </div>
          </div>

          {vt?.flagged_engines?.length > 0 && (
            <div style={{ marginTop: '12px', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Flagged by: </span>
              <span style={{ color: 'var(--text-secondary)' }}>{vt.flagged_engines.join(', ')}</span>
            </div>
          )}
        </>
      )}

      {configured && total === 0 && !found && (
        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0 }}>
          No detections across 70+ AV engines.
        </p>
      )}
    </div>
  )
}
