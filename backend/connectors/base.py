import abc
from typing import List, Dict, Any

import httpx

from backend.utils.rate_limiter import RateLimiter


class BaseConnector(abc.ABC):
    """Abstract base class for all CTI feed connectors."""

    def __init__(self, rate_limit: int = 60):
        self.rate_limiter = RateLimiter(max_requests=rate_limit, window_seconds=60)
        self.client = httpx.AsyncClient(timeout=30.0)

    @property
    @abc.abstractmethod
    def feed_name(self) -> str:
        """Return canonical feed name, e.g. 'urlhaus'."""
        ...

    @abc.abstractmethod
    async def fetch(self, **kwargs) -> List[Dict[str, Any]]:
        """Fetch raw data from the feed API. Returns list of raw records."""
        ...

    @abc.abstractmethod
    def parse(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse raw API response into list of cleaned dicts (feed-specific schema)."""
        ...

    @abc.abstractmethod
    def normalize(self, parsed_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map parsed feed-specific records to the unified indicator schema."""
        ...

    async def run(self, **kwargs) -> List[Dict[str, Any]]:
        """Full pipeline: fetch -> parse -> normalize."""
        raw = await self.fetch(**kwargs)
        parsed = self.parse(raw)
        normalized = self.normalize(parsed)
        return normalized

    async def close(self):
        await self.client.aclose()
