import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export default function SeverityChart({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return <p className="text-dark-muted text-center py-8">No data available</p>;
  }

  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  return (
    <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
      <h3 className="text-white font-semibold mb-4">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={3}
            dataKey="value"
          >
            {chartData.map((entry) => (
              <Cell
                key={entry.name}
                fill={COLORS[entry.name.toLowerCase()] || "#64748b"}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
            itemStyle={{ color: "#e2e8f0" }}
          />
          <Legend
            formatter={(value) => <span className="text-dark-text text-sm">{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
