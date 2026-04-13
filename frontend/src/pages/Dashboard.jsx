import { useState } from "react";
import useApi from "../hooks/useApi";
import {
  getDashboardSummary, getDashboardTimeline, getFeedStatus,
  getTopIoCs, fetchFeeds, runDetection,
} from "../api/client";
import StatsCard from "../components/StatsCard";
import SeverityChart from "../components/SeverityChart";
import TimelineChart from "../components/TimelineChart";
import FeedStatusPanel from "../components/FeedStatusPanel";

export default function Dashboard() {
  const [fetching, setFetching] = useState(false);

  const summary = useApi(getDashboardSummary, [], true);
  const timeline = useApi(() => getDashboardTimeline(30), [], true);
  const feedStatus = useApi(getFeedStatus, [], true);
  const topIocs = useApi(() => getTopIoCs(5), [], true);

  const handleFetchAll = async () => {
    setFetching(true);
    try {
      await fetchFeeds("all");
      // Refresh data after fetch
      summary.execute();
      timeline.execute();
      feedStatus.execute();
      topIocs.execute();
    } catch (err) {
      console.error("Fetch failed:", err);
    }
    setFetching(false);
  };

  const handleRunDetection = async () => {
    try {
      const result = await runDetection();
      alert(`Detection complete: ${result.flags_generated} flags generated`);
    } catch (err) {
      console.error("Detection failed:", err);
    }
  };

  const s = summary.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Dashboard</h2>
          <p className="text-dark-muted text-sm mt-1">Threat Intelligence Overview</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleRunDetection}
            className="px-4 py-2 rounded-lg bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 transition-colors"
          >
            Run Detection
          </button>
          <button
            onClick={handleFetchAll}
            disabled={fetching}
            className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            {fetching ? "Fetching..." : "Fetch All Feeds"}
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Indicators"
          value={s?.total_indicators || 0}
          color="blue"
        />
        <StatsCard
          title="Critical"
          value={s?.by_severity?.critical || 0}
          color="red"
        />
        <StatsCard
          title="High"
          value={s?.by_severity?.high || 0}
          color="orange"
        />
        <StatsCard
          title="Sources Active"
          value={s?.by_source ? Object.keys(s.by_source).length : 0}
          color="green"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <TimelineChart data={timeline.data?.data} />
        </div>
        <SeverityChart data={s?.by_severity} />
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FeedStatusPanel feeds={feedStatus.data?.feeds} />

        {/* Top IoCs */}
        <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
          <h3 className="text-white font-semibold mb-4">Top Reported IoCs</h3>
          <div className="space-y-2">
            {topIocs.data && topIocs.data.length > 0 ? (
              topIocs.data.map((ioc, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-dark-bg">
                  <div>
                    <p className="text-blue-400 font-mono text-xs truncate max-w-[200px]">
                      {ioc.ioc_value}
                    </p>
                    <p className="text-dark-muted text-xs">{ioc.ioc_type}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-dark-text text-sm">{ioc.num_sources} feeds</p>
                    <p className="text-dark-muted text-xs">{ioc.severity}</p>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-dark-muted text-sm text-center py-4">No data yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
