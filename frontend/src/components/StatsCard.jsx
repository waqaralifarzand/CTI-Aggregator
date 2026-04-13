export default function StatsCard({ title, value, subtitle, color = "blue" }) {
  const colorMap = {
    blue: "border-blue-500 text-blue-400",
    red: "border-severity-critical text-severity-critical",
    orange: "border-severity-high text-severity-high",
    yellow: "border-severity-medium text-severity-medium",
    green: "border-severity-low text-severity-low",
  };

  return (
    <div
      className={`bg-dark-card border-l-4 ${colorMap[color] || colorMap.blue} rounded-lg p-5`}
    >
      <p className="text-dark-muted text-sm">{title}</p>
      <p className="text-3xl font-bold text-white mt-1">
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {subtitle && <p className="text-dark-muted text-xs mt-2">{subtitle}</p>}
    </div>
  );
}
