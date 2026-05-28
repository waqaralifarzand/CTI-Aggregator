import React from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function IocTypeBar({ data }) {
  if (!data?.length) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-muted)', fontSize: '13px' }}>
      No data yet
    </div>
  )

  const chartData = data.map(d => ({ name: d.type?.replace('hash_', '').toUpperCase() || d.type, value: d.count }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '12px' }}
          cursor={{ fill: 'rgba(6,182,212,0.05)' }}
        />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} fill="var(--accent)" />
      </BarChart>
    </ResponsiveContainer>
  )
}
