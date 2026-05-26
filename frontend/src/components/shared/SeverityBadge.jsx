const SEVERITY_STYLES = {
  critical: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.15)' },
  high:     { color: 'var(--high)',     bg: 'rgba(249,115,22,0.15)' },
  medium:   { color: 'var(--medium)',   bg: 'rgba(234,179,8,0.15)'  },
  low:      { color: 'var(--low)',      bg: 'rgba(34,197,94,0.15)'  },
  clean:    { color: 'var(--clean)',    bg: 'rgba(16,185,129,0.15)' },
}

const LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  clean: 'Clean',
}

export default function SeverityBadge({ severity, size = 'md' }) {
  const s = (severity || 'clean').toLowerCase()
  const style = SEVERITY_STYLES[s] || SEVERITY_STYLES.clean
  const fontSize = size === 'lg' ? '13px' : size === 'sm' ? '10px' : '11px'
  const padding = size === 'lg' ? '5px 14px' : size === 'sm' ? '2px 7px' : '3px 10px'

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding,
      borderRadius: '999px',
      fontSize,
      fontWeight: 600,
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      color: style.color,
      backgroundColor: style.bg,
      border: `1px solid ${style.color}33`,
      whiteSpace: 'nowrap',
    }}>
      {LABELS[s] || s}
    </span>
  )
}
