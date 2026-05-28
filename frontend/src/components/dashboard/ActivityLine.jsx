import React from 'react'
import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts'

export default function ActivityLine({ data }) {
  if (!data?.length) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-muted)', fontSize: '13px' }}>
      No data yet
    </div>
  )

  const chartData = data.map(d => ({ ...d, date: d.date?.slice(5) }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <XAxis dataKey="date" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '12px' }}
        />
        <Legend formatter={(v) => <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{v}</span>} />
        <Line type="monotone" dataKey="scans" stroke="var(--accent)" strokeWidth={2} dot={false} name="Scans" />
        <Line type="monotone" dataKey="threats" stroke="var(--critical)" strokeWidth={2} dot={false} name="Threats" />
      </LineChart>
    </ResponsiveContainer>
  )
}
