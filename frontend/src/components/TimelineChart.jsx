import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";

export default function TimelineChart({ data }) {
  if (!data || data.length === 0) {
    return <p className="text-dark-muted text-center py-8">No timeline data</p>;
  }

  return (
    <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
      <h3 className="text-white font-semibold mb-4">Indicators Over Time</h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="date" stroke="#94a3b8" tick={{ fontSize: 12 }} />
          <YAxis stroke="#94a3b8" tick={{ fontSize: 12 }} />
          <Tooltip
            contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
            itemStyle={{ color: "#e2e8f0" }}
          />
          <Legend />
          <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
          <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.6} />
          <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.6} />
          <Area type="monotone" dataKey="low" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
