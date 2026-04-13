const severityBadge = (severity) => {
  const colors = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    low: "bg-green-500/20 text-green-400",
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[severity] || colors.medium}`}>
      {severity}
    </span>
  );
};

export default function ThreatTable({ indicators, onPageChange, page, total, perPage }) {
  const totalPages = Math.ceil(total / perPage);

  return (
    <div className="bg-dark-card rounded-lg border border-dark-border overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="bg-dark-border/50 text-dark-muted uppercase text-xs">
            <tr>
              <th className="px-4 py-3">IoC Value</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Malware</th>
              <th className="px-4 py-3">First Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {indicators && indicators.length > 0 ? (
              indicators.map((ind) => (
                <tr key={ind.id} className="hover:bg-dark-border/30 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-blue-400 max-w-xs truncate">
                    {ind.ioc_value}
                  </td>
                  <td className="px-4 py-3 text-dark-muted">{ind.ioc_type}</td>
                  <td className="px-4 py-3 text-dark-muted">{ind.source_feed}</td>
                  <td className="px-4 py-3">{severityBadge(ind.severity)}</td>
                  <td className="px-4 py-3 text-dark-muted">{ind.confidence?.toFixed(1)}%</td>
                  <td className="px-4 py-3 text-dark-muted">{ind.malware_family || "—"}</td>
                  <td className="px-4 py-3 text-dark-muted text-xs">
                    {ind.first_seen ? new Date(ind.first_seen).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-dark-muted">
                  No indicators found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-dark-border">
          <p className="text-dark-muted text-sm">
            Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
              className="px-3 py-1 rounded bg-dark-border text-dark-text text-sm disabled:opacity-50 hover:bg-dark-border/80"
            >
              Prev
            </button>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded bg-dark-border text-dark-text text-sm disabled:opacity-50 hover:bg-dark-border/80"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
