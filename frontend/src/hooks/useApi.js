import { useState, useEffect, useCallback } from "react";

export default function useApi(apiFn, deps = [], immediate = true) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const execute = useCallback(
    async (...args) => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiFn(...args);
        setData(result);
        return result;
      } catch (err) {
        setError(err?.response?.data?.detail || err.message);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [apiFn]
  );

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, deps);

  return { data, loading, error, execute };
}
