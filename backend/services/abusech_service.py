import httpx

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL_URL = "https://urlhaus-api.abuse.ch/v1/url/"
MB_URL = "https://mb-api.abuse.ch/api/v1/"


async def query_urlhaus(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type not in ("ip", "domain"):
        return {"found": False, "applicable": False, "url_count": 0, "tags": [], "raw_data": {}}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(URLHAUS_HOST_URL, data={"host": ioc_value})
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            return {"found": False, "applicable": True, "url_count": 0, "tags": [], "raw_data": data}

        urls = data.get("urls", [])
        tags = []
        for url_entry in urls[:10]:
            for tag in (url_entry.get("tags") or []):
                tags.append(tag)

        tags = list({t for t in tags if t})[:10]

        return {
            "found": True,
            "applicable": True,
            "url_count": len(urls),
            "tags": tags,
            "raw_data": {
                "query_status": query_status,
                "url_count": len(urls),
                "urls_sample": [u.get("url") for u in urls[:3]],
            },
        }
    except Exception as e:
        return {"found": False, "applicable": True, "url_count": 0, "tags": [], "raw_data": {"error": str(e)}}


async def query_malwarebazaar(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type not in ("hash_md5", "hash_sha256", "hash_sha1"):
        return {"found": False, "applicable": False, "file_type": None, "signature": None, "tags": [], "raw_data": {}}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(MB_URL, data={"query": "get_info", "hash": ioc_value})
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")
        if query_status != "ok":
            return {"found": False, "applicable": True, "file_type": None, "signature": None, "tags": [], "raw_data": data}

        entries = data.get("data", [])
        if not entries:
            return {"found": False, "applicable": True, "file_type": None, "signature": None, "tags": [], "raw_data": data}

        entry = entries[0]
        tags = entry.get("tags") or []

        return {
            "found": True,
            "applicable": True,
            "file_type": entry.get("file_type"),
            "signature": entry.get("signature") or entry.get("vendor_intel", {}).get("ANY.RUN", {}).get("verdict"),
            "tags": tags[:10],
            "raw_data": {
                "file_name": entry.get("file_name"),
                "file_size": entry.get("file_size"),
                "mime_type": entry.get("mime_type"),
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "reporter": entry.get("reporter"),
            },
        }
    except Exception as e:
        return {"found": False, "applicable": True, "file_type": None, "signature": None, "tags": [], "raw_data": {"error": str(e)}}
