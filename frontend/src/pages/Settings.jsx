import { useState } from "react";
import useApi from "../hooks/useApi";
import { getModelInfo, trainModel, fetchFeeds } from "../api/client";

export default function Settings() {
  const [trainVersion, setTrainVersion] = useState("v1");
  const [training, setTraining] = useState(false);
  const [trainResult, setTrainResult] = useState(null);

  const modelInfo = useApi(getModelInfo, [], true);

  const handleTrain = async () => {
    setTraining(true);
    setTrainResult(null);
    try {
      const result = await trainModel(trainVersion);
      setTrainResult(result);
      modelInfo.execute();
    } catch (err) {
      setTrainResult({ status: "failed", metrics: { error: err.message } });
    }
    setTraining(false);
  };

  const handleFetchSingle = async (feed) => {
    try {
      await fetchFeeds(feed);
      alert(`Fetched from ${feed} successfully`);
    } catch (err) {
      alert(`Fetch failed: ${err.message}`);
    }
  };

  const model = modelInfo.data;

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-2xl font-bold text-white">Settings</h2>
        <p className="text-dark-muted text-sm mt-1">Manage feeds and ML model</p>
      </div>

      {/* Feed Management */}
      <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
        <h3 className="text-white font-semibold mb-4">Feed Management</h3>
        <p className="text-dark-muted text-sm mb-4">Trigger individual feed fetches</p>
        <div className="grid grid-cols-2 gap-3">
          {["urlhaus", "malwarebazaar", "alienvault_otx", "misp"].map((feed) => (
            <button
              key={feed}
              onClick={() => handleFetchSingle(feed)}
              className="px-4 py-2 rounded-lg bg-dark-bg border border-dark-border text-dark-text text-sm hover:bg-dark-border/50 transition-colors"
            >
              Fetch {feed}
            </button>
          ))}
        </div>
      </div>

      {/* ML Model */}
      <div className="bg-dark-card rounded-lg p-5 border border-dark-border">
        <h3 className="text-white font-semibold mb-4">ML Model</h3>

        <div className="mb-4 p-3 rounded-lg bg-dark-bg">
          <p className="text-dark-text text-sm">
            Status: {model?.trained ? (
              <span className="text-green-400">Trained (version: {model.version})</span>
            ) : (
              <span className="text-yellow-400">Not trained</span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <input
            type="text"
            value={trainVersion}
            onChange={(e) => setTrainVersion(e.target.value)}
            placeholder="Model version"
            className="px-4 py-2 rounded-lg bg-dark-bg border border-dark-border text-dark-text text-sm focus:outline-none focus:border-blue-500 w-32"
          />
          <button
            onClick={handleTrain}
            disabled={training}
            className="px-4 py-2 rounded-lg bg-green-600 text-white text-sm font-medium hover:bg-green-700 disabled:opacity-50 transition-colors"
          >
            {training ? "Training..." : "Train Model"}
          </button>
        </div>

        {trainResult && (
          <div className="mt-4 p-3 rounded-lg bg-dark-bg text-sm">
            <p className="text-dark-text mb-2">
              Result: <span className={trainResult.status === "completed" ? "text-green-400" : "text-red-400"}>
                {trainResult.status}
              </span>
            </p>
            {trainResult.metrics && (
              <pre className="text-dark-muted text-xs overflow-x-auto">
                {JSON.stringify(trainResult.metrics, null, 2)}
              </pre>
            )}
          </div>
        )}

        {model?.feature_importances && (
          <div className="mt-4">
            <h4 className="text-dark-text text-sm font-medium mb-2">Top Features</h4>
            <div className="space-y-1">
              {Object.entries(model.feature_importances)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name, importance]) => (
                  <div key={name} className="flex items-center gap-2">
                    <div className="w-32 text-xs text-dark-muted truncate">{name}</div>
                    <div className="flex-1 bg-dark-bg rounded-full h-2">
                      <div
                        className="bg-blue-500 rounded-full h-2"
                        style={{ width: `${(importance * 100).toFixed(0)}%` }}
                      />
                    </div>
                    <span className="text-xs text-dark-muted w-12 text-right">
                      {(importance * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
