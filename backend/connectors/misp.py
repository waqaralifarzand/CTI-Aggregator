import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from backend.config import settings
from backend.connectors.base import BaseConnector
from backend.utils.retry import with_retry, ConnectorError
from backend.utils.logging import logger

# Map MISP attribute types to unified ioc_type
MISP_TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "uri": "url",
    "md5": "hash_md5",
    "sha1": "hash_sha1",
    "sha256": "hash_sha256",
    "filename": "filename",
    "email-src": "email",
    "email-dst": "email",
}

# MISP threat_level_id to severity
MISP_SEVERITY_MAP = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
}


class MISPConnector(BaseConnector):
    """Connector for MISP instance API (requires API key and instance URL)."""

    def __init__(self):
        super().__init__(rate_limit=settings.MISP_RATE_LIMIT)
        self.base_url = settings.MISP_URL.rstrip("/") if settings.MISP_URL else ""
        self.headers = {
            "Authorization": settings.MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @property
    def feed_name(self) -> str:
        return "misp"

    async def fetch(self, **kwargs) -> List[Dict[str, Any]]:
        """Fetch published events from MISP."""
        if not self.base_url or not settings.MISP_API_KEY:
            logger.warning("MISP: No URL or API key configured, skipping.")
            return []

        days_back = kwargs.get("days_back", 7)
        limit = kwargs.get("limit", 100)

        logger.info(f"MISP: Fetching events from last {days_back} days...")
        await self.rate_limiter.acquire()

        # Create client with SSL verification setting
        client = self.client
        if not settings.MISP_VERIFY_SSL:
            import httpx
            client = httpx.AsyncClient(timeout=30.0, verify=False)

        try:
            response = await with_retry(
                client.post,
                f"{self.base_url}/events/restSearch",
                json={"timestamp": f"{days_back}d", "limit": limit, "published": True},
                headers=self.headers,
            )
            response.raise_for_status()
            data = response.json()
        finally:
            if client is not self.client:
                await client.aclose()

        events = data.get("response", [])
        logger.info(f"MISP: Fetched {len(events)} events.")
        return events

    def parse(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flatten MISP events into individual attribute records."""
        parsed = []
        for event_wrapper in raw_records:
            event = event_wrapper.get("Event", event_wrapper)
            event_meta = {
                "event_id": event.get("id"),
                "event_uuid": event.get("uuid"),
                "event_info": event.get("info", ""),
                "event_date": event.get("date"),
                "threat_level_id": str(event.get("threat_level_id", "4")),
                "analysis": str(event.get("analysis", "0")),
                "event_tags": self._extract_tags(event),
            }
            for attribute in event.get("Attribute", []):
                parsed.append({
                    **event_meta,
                    "attr_type": attribute.get("type", ""),
                    "attr_value": attribute.get("value", ""),
                    "attr_category": attribute.get("category", ""),
                    "attr_comment": attribute.get("comment", ""),
                    "to_ids": attribute.get("to_ids", False),
                    "first_seen": attribute.get("first_seen"),
                    "last_seen": attribute.get("last_seen"),
                })
        return parsed

    def normalize(self, parsed_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map MISP attribute records to unified schema."""
        normalized = []
        for record in parsed_records:
            value = record.get("attr_value", "")
            attr_type = record.get("attr_type", "")
            ioc_type = MISP_TYPE_MAP.get(attr_type)
            if not value or not ioc_type:
                continue

            # Parse dates
            first_seen = self._parse_date(record.get("first_seen")) or self._parse_date(record.get("event_date"))
            last_seen = self._parse_date(record.get("last_seen")) or first_seen

            # Severity from threat_level_id
            severity = MISP_SEVERITY_MAP.get(record.get("threat_level_id", "4"), "low")

            # Confidence from to_ids and analysis
            confidence = 40.0
            if record.get("to_ids"):
                confidence += 30.0
            analysis = int(record.get("analysis", "0"))
            confidence += analysis * 15.0  # 0=initial, 1=ongoing, 2=completed

            # Tags
            tags = record.get("event_tags", [])

            # TLP from tags
            tlp = "amber"  # MISP default
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("tlp:"):
                    tlp_val = tag_lower.replace("tlp:", "").strip()
                    if tlp_val in ("white", "green", "amber", "red"):
                        tlp = tlp_val
                        break

            # Malware family from tags
            malware_family = None
            for tag in tags:
                tag_lower = tag.lower()
                if "misp-galaxy:malware=" in tag_lower or "malware:" in tag_lower:
                    malware_family = tag.split("=")[-1].strip('"').strip("'")
                    break

            source_ref = ""
            if self.base_url and record.get("event_id"):
                source_ref = f"{self.base_url}/events/view/{record['event_id']}"

            normalized.append({
                "ioc_value": value,
                "ioc_type": ioc_type,
                "source_feed": self.feed_name,
                "source_reference": source_ref,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "severity": severity,
                "confidence": min(confidence, 100.0),
                "tags": tags,
                "malware_family": malware_family,
                "tlp": tlp,
                "raw_data": json.dumps(record, default=str),
            })

        logger.info(f"MISP: Normalized {len(normalized)} indicators.")
        return normalized

    @staticmethod
    def _extract_tags(event: dict) -> List[str]:
        tags = []
        for tag in event.get("Tag", []):
            name = tag.get("name", "")
            if name:
                tags.append(name)
        return tags

    @staticmethod
    def _parse_date(value):
        if not value:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                continue
        return None
