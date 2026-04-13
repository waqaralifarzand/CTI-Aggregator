import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from backend.config import settings
from backend.connectors.base import BaseConnector
from backend.utils.retry import with_retry, ConnectorError
from backend.utils.logging import logger


class URLhausConnector(BaseConnector):
    """Connector for Abuse.ch URLhaus API (no auth required)."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        super().__init__(rate_limit=settings.URLHAUS_RATE_LIMIT)

    @property
    def feed_name(self) -> str:
        return "urlhaus"

    async def fetch(self, **kwargs) -> List[Dict[str, Any]]:
        """Fetch recently added URLs (last 3 days by default)."""
        logger.info("URLhaus: Fetching recent URLs...")
        await self.rate_limiter.acquire()
        response = await with_retry(
            self.client.post,
            f"{self.BASE_URL}/urls/recent/",
            data={},
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            raise ConnectorError(f"URLhaus query failed: {data.get('query_status')}")

        urls = data.get("urls", [])
        logger.info(f"URLhaus: Fetched {len(urls)} URLs.")
        return urls

    def parse(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract relevant fields from URLhaus response."""
        parsed = []
        for record in raw_records:
            parsed_record = {
                "url": record.get("url", ""),
                "url_status": record.get("url_status", "unknown"),
                "host": record.get("host", ""),
                "date_added": record.get("date_added"),
                "threat": record.get("threat", ""),
                "tags": record.get("tags"),
                "urlhaus_reference": record.get("urlhaus_reference", ""),
                "reporter": record.get("reporter", ""),
                "blacklists": record.get("blacklists", {}),
                "payloads": record.get("payloads") or [],
            }
            parsed.append(parsed_record)
        return parsed

    def normalize(self, parsed_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map URLhaus records to unified indicator schema."""
        normalized = []
        for record in parsed_records:
            if not record.get("url"):
                continue

            # Parse date
            first_seen = None
            if record.get("date_added"):
                try:
                    first_seen = datetime.strptime(
                        record["date_added"], "%Y-%m-%d %H:%M:%S UTC"
                    ).replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    first_seen = None

            # Map severity from url_status
            status = record.get("url_status", "unknown")
            severity = {"online": "high", "offline": "medium"}.get(status, "low")

            # Compute confidence from blacklist hits
            confidence = 50.0
            blacklists = record.get("blacklists", {}) or {}
            if blacklists.get("spamhaus_dbl") and blacklists["spamhaus_dbl"] != "not listed":
                confidence += 25.0
            if blacklists.get("surbl") and blacklists["surbl"] != "not listed":
                confidence += 25.0

            # Extract tags
            tags = record.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            # Malware family from threat field or first payload signature
            malware_family = None
            threat = record.get("threat", "")
            if threat and threat != "malware_download":
                malware_family = threat
            elif record.get("payloads"):
                for payload in record["payloads"]:
                    sig = payload.get("signature")
                    if sig and sig != "null":
                        malware_family = sig
                        break

            # URL indicator
            normalized.append({
                "ioc_value": record["url"],
                "ioc_type": "url",
                "source_feed": self.feed_name,
                "source_reference": record.get("urlhaus_reference", ""),
                "first_seen": first_seen,
                "last_seen": None,
                "severity": severity,
                "confidence": min(confidence, 100.0),
                "tags": tags,
                "malware_family": malware_family,
                "tlp": "white",
                "raw_data": json.dumps(record, default=str),
            })

            # Also emit hash indicators from payloads
            for payload in record.get("payloads", []):
                for hash_type, hash_field in [("hash_sha256", "sha256_hash"), ("hash_md5", "md5_hash")]:
                    hash_val = payload.get(hash_field)
                    if hash_val:
                        normalized.append({
                            "ioc_value": hash_val,
                            "ioc_type": hash_type,
                            "source_feed": self.feed_name,
                            "source_reference": record.get("urlhaus_reference", ""),
                            "first_seen": first_seen,
                            "last_seen": None,
                            "severity": "high",
                            "confidence": 85.0,
                            "tags": tags,
                            "malware_family": malware_family or payload.get("signature"),
                            "tlp": "white",
                            "raw_data": json.dumps(payload, default=str),
                        })

        logger.info(f"URLhaus: Normalized {len(normalized)} indicators.")
        return normalized
