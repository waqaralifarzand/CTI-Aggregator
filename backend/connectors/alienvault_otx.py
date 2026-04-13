import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from backend.config import settings
from backend.connectors.base import BaseConnector
from backend.utils.retry import with_retry, ConnectorError
from backend.utils.logging import logger

# Map OTX indicator types to our unified ioc_type values
OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "hostname",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email",
    "CVE": "cve",
    "CIDR": "ip",
}


class AlienVaultOTXConnector(BaseConnector):
    """Connector for AlienVault OTX API (requires free API key)."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self):
        super().__init__(rate_limit=settings.OTX_RATE_LIMIT)
        self.headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

    @property
    def feed_name(self) -> str:
        return "alienvault_otx"

    async def fetch(self, **kwargs) -> List[Dict[str, Any]]:
        """Fetch subscribed pulses from OTX with pagination."""
        if not settings.OTX_API_KEY:
            logger.warning("OTX: No API key configured, skipping.")
            return []

        days_back = kwargs.get("days_back", 7)
        max_pages = kwargs.get("max_pages", 5)
        modified_since = (
            datetime.now(tz=timezone.utc) - timedelta(days=days_back)
        ).strftime("%Y-%m-%dT%H:%M:%S")

        all_pulses = []
        page = 1

        for _ in range(max_pages):
            logger.info(f"OTX: Fetching page {page}...")
            await self.rate_limiter.acquire()
            response = await with_retry(
                self.client.get,
                f"{self.BASE_URL}/pulses/subscribed",
                params={"modified_since": modified_since, "page": page, "limit": 50},
                headers=self.headers,
            )
            response.raise_for_status()
            data = response.json()
            results = data.get("results", [])
            all_pulses.extend(results)

            if not data.get("next"):
                break
            page += 1

        logger.info(f"OTX: Fetched {len(all_pulses)} pulses.")
        return all_pulses

    def parse(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flatten pulses into individual indicator records."""
        parsed = []
        for pulse in raw_records:
            pulse_meta = {
                "pulse_name": pulse.get("name", ""),
                "pulse_created": pulse.get("created"),
                "pulse_modified": pulse.get("modified"),
                "pulse_tlp": pulse.get("TLP", "white"),
                "pulse_tags": pulse.get("tags", []),
                "pulse_malware_families": pulse.get("malware_families", []),
                "pulse_references": pulse.get("references", []),
                "pulse_targeted_countries": pulse.get("targeted_countries", []),
                "pulse_adversary": pulse.get("adversary"),
            }
            for indicator in pulse.get("indicators", []):
                parsed.append({
                    **pulse_meta,
                    "indicator_value": indicator.get("indicator", ""),
                    "indicator_type": indicator.get("type", ""),
                    "indicator_title": indicator.get("title", ""),
                    "indicator_description": indicator.get("description", ""),
                    "is_active": indicator.get("is_active", True),
                })
        return parsed

    def normalize(self, parsed_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map OTX indicator records to unified schema."""
        normalized = []
        for record in parsed_records:
            value = record.get("indicator_value", "")
            otx_type = record.get("indicator_type", "")
            ioc_type = OTX_TYPE_MAP.get(otx_type)
            if not value or not ioc_type:
                continue

            # Parse dates
            first_seen = self._parse_iso(record.get("pulse_created"))
            last_seen = self._parse_iso(record.get("pulse_modified")) or first_seen

            # TLP
            tlp = (record.get("pulse_tlp") or "white").lower()
            if tlp not in ("white", "green", "amber", "red"):
                tlp = "white"

            # Tags
            tags = record.get("pulse_tags", []) or []

            # Malware family
            families = record.get("pulse_malware_families", []) or []
            malware_family = families[0] if families else None

            # Severity based on is_active and malware family
            is_active = record.get("is_active", True)
            if is_active and malware_family:
                severity = "high"
            elif is_active:
                severity = "medium"
            else:
                severity = "low"

            # Confidence scoring
            confidence = 60.0
            if is_active:
                confidence += 20.0
            if malware_family:
                confidence += 10.0

            normalized.append({
                "ioc_value": value,
                "ioc_type": ioc_type,
                "source_feed": self.feed_name,
                "source_reference": f"https://otx.alienvault.com/indicator/{otx_type.lower()}/{value}",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "severity": severity,
                "confidence": min(confidence, 100.0),
                "tags": tags,
                "malware_family": malware_family,
                "tlp": tlp,
                "raw_data": json.dumps(record, default=str),
            })

        logger.info(f"OTX: Normalized {len(normalized)} indicators.")
        return normalized

    @staticmethod
    def _parse_iso(value):
        if not value:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
        return None
