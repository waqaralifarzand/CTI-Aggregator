import os
import httpx

VT_BASE = "https://www.virustotal.com/api/v3"


async def query_virustotal(ioc_value: str, ioc_type: str) -> dict:
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key or api_key == "placeholder_key":
        return {"found": False, "applicable": True, "detections": 0, "total_engines": 0, "raw_data": {"note": "VT_API_KEY not configured"}}

    if ioc_type == "ip":
        url = f"{VT_BASE}/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"{VT_BASE}/domains/{ioc_value}"
    elif ioc_type in ("hash_md5", "hash_sha256", "hash_sha1"):
        url = f"{VT_BASE}/files/{ioc_value}"
    else:
        return {"found": False, "applicable": False, "detections": 0, "total_engines": 0, "raw_data": {}}

    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            return {"found": False, "applicable": True, "detections": 0, "total_engines": 0, "raw_data": {}}

        if resp.status_code == 401:
            return {"found": False, "applicable": True, "detections": 0, "total_engines": 0, "raw_data": {"error": "Invalid VT API key"}}

        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values()) if last_analysis else 0
        detections = malicious + suspicious

        # Collect top malicious engine names
        engine_results = attrs.get("last_analysis_results", {})
        flagged_engines = [
            name for name, result in engine_results.items()
            if result.get("category") in ("malicious", "suspicious")
        ][:5]

        return {
            "found": detections > 0,
            "applicable": True,
            "detections": detections,
            "total_engines": total,
            "flagged_engines": flagged_engines,
            "reputation": attrs.get("reputation", 0),
            "raw_data": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": last_analysis.get("harmless", 0),
                "undetected": last_analysis.get("undetected", 0),
                "total_engines": total,
            },
        }
    except httpx.HTTPStatusError as e:
        return {"found": False, "applicable": True, "detections": 0, "total_engines": 0, "raw_data": {"error": str(e)}}
    except Exception as e:
        return {"found": False, "applicable": True, "detections": 0, "total_engines": 0, "raw_data": {"error": str(e)}}
