export default function FeedStatusPanel({ feeds }) {
  if (!feeds || feeds.length === 0) {
    return <p className="text-dark-muted">No feed data</p>;
  }

  const statusColor = (status) => {
    switch (status) {
      case "success":
        return "bg-green-500";
      case "failed":
        return "bg-red-500";
      case "running":
        return "bg-yellow-500";
      default:
        return "bg-gray-500";
    }
  };

  return (
    <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
      <h3 className="text-white font-semibold mb-4">Feed Status</h3>
      <div className="space-y-3">
        {feeds.map((feed) => (
          <div
            key={feed.feed}
            className="flex items-center justify-between p-3 rounded-lg bg-dark-bg"
          >
            <div className="flex items-center gap-3">
              <div className={`w-2.5 h-2.5 rounded-full ${statusColor(feed.status)}`} />
              <div>
                <p className="text-white text-sm font-medium">{feed.feed}</p>
                <p className="text-dark-muted text-xs">
                  {feed.last_run
                    ? `Last run: ${new Date(feed.last_run).toLocaleString()}`
                    : "Never run"}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-dark-text text-sm">{feed.records_fetched} records</p>
              {feed.duration_ms && (
                <p className="text-dark-muted text-xs">{(feed.duration_ms / 1000).toFixed(1)}s</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
