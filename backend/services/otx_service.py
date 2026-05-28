import os
import httpx

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "hash_md5": "file",
    "hash_sha256": "file",
    "hash_sha1": "file",
}


async def query_otx(ioc_value: str, ioc_type: str) -> dict:
    api_key = os.getenv("OTX_API_KEY", "")
    otx_type = _TYPE_MAP.get(ioc_type)
    if not otx_type:
        return {"found": False, "error": "unsupported ioc type for OTX"}

    url = f"{OTX_BASE}/{otx_type}/{ioc_value}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            return {"found": False, "pulse_count": 0, "threat_tags": [], "categories": [], "country": None, "raw_data": {}}

        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        tags = []
        categories = []
        for pulse in pulses[:10]:
            tags.extend(pulse.get("tags", []))
            categories.extend(pulse.get("targeted_countries", []))
            for cat in pulse.get("attack_ids", []):
                categories.append(cat.get("display_name", ""))

        tags = list({t.lower() for t in tags if t})[:10]
        categories = list({c for c in categories if c})[:5]

        country = data.get("country_name") or data.get("country_code")

        return {
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "threat_tags": tags,
            "categories": categories,
            "country": country,
            "raw_data": {
                "pulse_count": pulse_count,
                "reputation": data.get("reputation", 0),
                "asn": data.get("asn"),
                "city": data.get("city"),
            },
        }
    except httpx.HTTPStatusError as e:
        return {"found": False, "error": str(e), "pulse_count": 0, "threat_tags": [], "categories": [], "country": None, "raw_data": {}}
    except Exception as e:
        return {"found": False, "error": str(e), "pulse_count": 0, "threat_tags": [], "categories": [], "country": None, "raw_data": {}}
