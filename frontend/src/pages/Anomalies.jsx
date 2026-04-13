import { useState, useCallback } from "react";
import useApi from "../hooks/useApi";
import { getAnomalies, getAnomalySummary, runDetection } from "../api/client";

const flagColors = {
  duplicate_cross_feed: "bg-blue-500/20 text-blue-400",
  frequency_spike: "bg-red-500/20 text-red-400",
  temporal_correlation: "bg-purple-500/20 text-purple-400",
  cross_feed_conflict: "bg-yellow-500/20 text-yellow-400",
  stale_recency_decay: "bg-gray-500/20 text-gray-400",
  reactivation_detected: "bg-orange-500/20 text-orange-400",
};

export default function Anomalies() {
  const [page, setPage] = useState(1);
  const perPage = 50;

  const fetchAnomalies = useCallback(
    () => getAnomalies({ page, per_page: perPage }),
    [page]
  );
  const { data, loading, execute } = useApi(fetchAnomalies, [page], true);
  const summaryApi = useApi(getAnomalySummary, [], true);

  const handleRunDetection = async () => {
    try {
      await runDetection();
      execute();
      summaryApi.execute();
    } catch (err) {
      console.error("Detection failed:", err);
    }
  };

  const summary = summaryApi.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Anomalies</h2>
          <p className="text-dark-muted text-sm mt-1">
            Detection engine results — {summary?.total_flags || 0} total flags
          </p>
        </div>
        <button
          onClick={handleRunDetection}
          className="px-4 py-2 rounded-lg bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 transition-colors"
        >
          Run Detection
        </button>
      </div>

      {/* Summary cards */}
      {summary?.by_type && (
        <div className="flex flex-wrap gap-3">
          {Object.entries(summary.by_type).map(([type, count]) => (
            <div
              key={type}
              className={`px-4 py-2 rounded-lg text-sm font-medium ${flagColors[type] || "bg-dark-border text-dark-text"}`}
            >
              {type.replace(/_/g, " ")}: {count}
            </div>
          ))}
        </div>
      )}

      {/* Anomaly list */}
      <div className="bg-dark-card rounded-lg border border-dark-border overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="bg-dark-border/50 text-dark-muted uppercase text-xs">
            <tr>
              <th className="px-4 py-3">Flag Type</th>
              <th className="px-4 py-3">Indicator ID</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">Detected</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {!loading && data?.items?.length > 0 ? (
              data.items.map((flag) => (
                <tr key={flag.id} className="hover:bg-dark-border/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${flagColors[flag.flag_type] || "bg-dark-border text-dark-text"}`}>
                      {flag.flag_type.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-dark-muted">#{flag.indicator_id}</td>
                  <td className="px-4 py-3 text-dark-text text-xs max-w-md truncate">
                    {flag.description}
                  </td>
                  <td className="px-4 py-3">
                    <span className={flag.anomaly_score >= 0 ? "text-red-400" : "text-green-400"}>
                      {flag.anomaly_score > 0 ? "+" : ""}{flag.anomaly_score}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-dark-muted text-xs">
                    {flag.detected_at ? new Date(flag.detected_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-dark-muted">
                  {loading ? "Loading..." : "No anomalies detected yet. Run detection first."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
