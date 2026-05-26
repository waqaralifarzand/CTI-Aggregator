import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import LoadingSkeleton from '../shared/LoadingSkeleton'
import EmptyState from '../shared/EmptyState'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'clean']

// CSS variable values — used directly since Recharts can't read CSS vars at paint time
const SEVERITY_HEX = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  clean:    '#10b981',
}

const LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  clean: 'Clean',
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  return (
    <div style={{
      background: 'var(--bg-card-hover)',
      border: '1px solid var(--border)',
      borderRadius: '6px',
      padding: '8px 12px',
      fontSize: '13px',
      color: 'var(--text-primary)',
    }}>
      <strong>{LABELS[name] || name}:</strong> {value}
    </div>
  )
}

export default function SeverityDonut({ data, loading }) {
  if (loading) return <LoadingSkeleton height={220} />

  const ordered = SEVERITY_ORDER.map(sev => {
    const found = (data || []).find(d => d.severity === sev)
    return { name: sev, value: found?.count || 0 }
  })
  const nonZero = ordered.filter(d => d.value > 0)
  const total = ordered.reduce((s, d) => s + d.value, 0)

  if (!total) return (
    <EmptyState
      title="No scan data"
      description="Run your first scan to see severity breakdown"
    />
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ position: 'relative', height: 180 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={nonZero}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              dataKey="value"
              nameKey="name"
              paddingAngle={2}
            >
              {nonZero.map(entry => (
                <Cell key={entry.name} fill={SEVERITY_HEX[entry.name]} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <span style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{total}</span>
          <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>total</span>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', justifyContent: 'center' }}>
        {ordered.filter(d => d.value > 0).map(d => (
          <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_HEX[d.name], display: 'inline-block', flexShrink: 0 }} />
            <span style={{ color: 'var(--text-secondary)' }}>{LABELS[d.name]}</span>
            <span style={{ color: 'var(--text-muted)' }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
