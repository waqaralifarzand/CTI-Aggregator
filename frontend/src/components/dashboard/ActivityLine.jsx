import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import LoadingSkeleton from '../shared/LoadingSkeleton'
import EmptyState from '../shared/EmptyState'

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'var(--bg-card-hover)', border: '1px solid var(--border)',
      borderRadius: '6px', padding: '8px 12px', fontSize: '12px', color: 'var(--text-primary)',
    }}>
      <p style={{ margin: '0 0 4px', color: 'var(--text-muted)' }}>{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ margin: '2px 0', color: p.color }}>
          {p.dataKey === 'scans' ? 'Total Scans' : 'Threats'}: <strong>{p.value}</strong>
        </p>
      ))}
    </div>
  )
}

export default function ActivityLine({ data, loading }) {
  if (loading) return <LoadingSkeleton height={180} />

  const hasData = (data || []).some(d => d.scans > 0)
  if (!hasData) return (
    <EmptyState title="No activity yet" description="Scan activity will appear here" />
  )

  const formatted = (data || []).map(d => ({
    ...d,
    date: d.date ? d.date.slice(5) : d.date, // show MM-DD only
  }))

  return (
    <ResponsiveContainer width="100%" height={180}>
      <LineChart data={formatted} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <XAxis
          dataKey="date"
          tick={{ fill: '#475569', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: '#475569', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Line
          type="monotone"
          dataKey="scans"
          stroke="#06b6d4"
          strokeWidth={2}
          dot={{ r: 3, fill: '#06b6d4' }}
          activeDot={{ r: 5 }}
        />
        <Line
          type="monotone"
          dataKey="threats"
          stroke="#f97316"
          strokeWidth={2}
          dot={{ r: 3, fill: '#f97316' }}
          activeDot={{ r: 5 }}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
