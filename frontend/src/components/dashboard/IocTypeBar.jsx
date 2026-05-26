import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import LoadingSkeleton from '../shared/LoadingSkeleton'
import EmptyState from '../shared/EmptyState'

const TYPE_LABELS = {
  ip: 'IP',
  domain: 'Domain',
  hash_md5: 'MD5',
  hash_sha256: 'SHA256',
  hash_sha1: 'SHA1',
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'var(--bg-card-hover)', border: '1px solid var(--border)',
      borderRadius: '6px', padding: '8px 12px', fontSize: '13px', color: 'var(--text-primary)',
    }}>
      <strong>{TYPE_LABELS[label] || label}:</strong> {payload[0].value}
    </div>
  )
}

export default function IocTypeBar({ data, loading }) {
  if (loading) return <LoadingSkeleton height={180} />

  const formatted = (data || []).map(d => ({ ...d, label: TYPE_LABELS[d.type] || d.type }))
  if (!formatted.length) return (
    <EmptyState title="No IoC data" description="Run scans to populate IoC breakdown" />
  )

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={formatted} barSize={28} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <XAxis
          dataKey="label"
          tick={{ fill: '#475569', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: '#475569', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {formatted.map((_, i) => (
            <Cell key={i} fill="#06b6d4" />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
