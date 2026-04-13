import { useState, useCallback } from "react";
import useApi from "../hooks/useApi";
import { getIndicators } from "../api/client";
import ThreatTable from "../components/ThreatTable";

export default function Indicators() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    ioc_type: "",
    severity: "",
    source_feed: "",
    search: "",
  });
  const perPage = 50;

  const fetchData = useCallback(
    () => getIndicators({ page, per_page: perPage, ...filters }),
    [page, filters]
  );
  const { data, loading, execute } = useApi(fetchData, [page, filters], true);

  const handleFilterChange = (key, value) => {
    setPage(1);
    setFilters((prev) => ({ ...prev, [key]: value || undefined }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Indicators</h2>
        <p className="text-dark-muted text-sm mt-1">Browse and filter threat indicators</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search IoC value or malware..."
          value={filters.search}
          onChange={(e) => handleFilterChange("search", e.target.value)}
          className="px-4 py-2 rounded-lg bg-dark-card border border-dark-border text-dark-text text-sm placeholder-dark-muted focus:outline-none focus:border-blue-500 w-64"
        />
        <select
          value={filters.ioc_type}
          onChange={(e) => handleFilterChange("ioc_type", e.target.value)}
          className="px-4 py-2 rounded-lg bg-dark-card border border-dark-border text-dark-text text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="">All Types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash_sha256">SHA256</option>
          <option value="hash_md5">MD5</option>
          <option value="hash_sha1">SHA1</option>
          <option value="email">Email</option>
        </select>
        <select
          value={filters.severity}
          onChange={(e) => handleFilterChange("severity", e.target.value)}
          className="px-4 py-2 rounded-lg bg-dark-card border border-dark-border text-dark-text text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filters.source_feed}
          onChange={(e) => handleFilterChange("source_feed", e.target.value)}
          className="px-4 py-2 rounded-lg bg-dark-card border border-dark-border text-dark-text text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="">All Sources</option>
          <option value="urlhaus">URLhaus</option>
          <option value="malwarebazaar">MalwareBazaar</option>
          <option value="alienvault_otx">AlienVault OTX</option>
          <option value="misp">MISP</option>
        </select>
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-center py-12 text-dark-muted">Loading...</div>
      ) : (
        <ThreatTable
          indicators={data?.items || []}
          page={page}
          total={data?.total || 0}
          perPage={perPage}
          onPageChange={setPage}
        />
      )}
    </div>
  );
}
