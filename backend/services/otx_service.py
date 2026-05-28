import os
import httpx
from dotenv import load_dotenv

load_dotenv()

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

OTX_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "hash_md5": "file",
    "hash_sha256": "file",
    "hash_sha1": "file",
}


async def query_otx(ioc_value: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for threat intelligence on an IoC."""
    api_key = os.getenv("OTX_API_KEY", "")
    otx_type = OTX_TYPE_MAP.get(ioc_type)

    if not otx_type:
        return {"found": False, "error": f"Unsupported IoC type for OTX: {ioc_type}"}

    url = f"{OTX_BASE_URL}/{otx_type}/{ioc_value}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 404:
            return {"found": False}

        if response.status_code == 401:
            return {"found": False, "error": "Invalid or missing OTX API key"}

        if response.status_code != 200:
            return {
                "found": False,
                "error": f"OTX returned HTTP {response.status_code}",
            }

        data = response.json()

        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []
        pulse_count = pulse_info.get("count", len(pulses))

        # Extract threat tags from all pulses
        threat_tags = []
        categories = []
        for pulse in pulses[:10]:  # limit processing to first 10 pulses
            tags = pulse.get("tags", []) or []
            threat_tags.extend(tags)
            cats = pulse.get("industries", []) or []
            categories.extend(cats)

        # Deduplicate
        threat_tags = list(dict.fromkeys(threat_tags))
        categories = list(dict.fromkeys(categories))

        country = data.get("country_code") or data.get("country") or None

        return {
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "threat_tags": threat_tags,
            "categories": categories,
            "country": country,
            "raw_data": data,
        }

    except httpx.TimeoutException:
        return {"found": False, "error": "OTX request timed out"}
    except httpx.RequestError as exc:
        return {"found": False, "error": f"OTX request error: {str(exc)}"}
    except Exception as exc:
        return {"found": False, "error": f"Unexpected OTX error: {str(exc)}"}
