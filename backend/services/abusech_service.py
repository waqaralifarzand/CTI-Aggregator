import httpx

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/host/"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"


async def query_urlhaus(ioc_value: str, ioc_type: str) -> dict:
    """Query URLhaus for threat intelligence on an IP or domain."""
    if ioc_type not in ("ip", "domain"):
        return {"found": False}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                URLHAUS_API_URL,
                data={"host": ioc_value},
            )

        if response.status_code != 200:
            return {
                "found": False,
                "error": f"URLhaus returned HTTP {response.status_code}",
            }

        data = response.json()

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            return {"found": False, "url_count": 0, "tags": [], "raw_data": data}

        urls = data.get("urls", []) or []
        url_count = len(urls)

        # Extract tags from all URLs
        tags = []
        for url_entry in urls:
            entry_tags = url_entry.get("tags", []) or []
            if isinstance(entry_tags, list):
                tags.extend(entry_tags)
        tags = list(dict.fromkeys(tags))  # deduplicate preserving order

        return {
            "found": url_count > 0,
            "url_count": url_count,
            "tags": tags,
            "raw_data": data,
        }

    except httpx.TimeoutException:
        return {"found": False, "error": "URLhaus request timed out"}
    except httpx.RequestError as exc:
        return {"found": False, "error": f"URLhaus request error: {str(exc)}"}
    except Exception as exc:
        return {"found": False, "error": f"Unexpected URLhaus error: {str(exc)}"}


async def query_malwarebazaar(ioc_value: str, ioc_type: str) -> dict:
    """Query MalwareBazaar for threat intelligence on a file hash."""
    if ioc_type not in ("hash_md5", "hash_sha256"):
        return {"found": False}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                MALWAREBAZAAR_API_URL,
                data={"query": "get_info", "hash": ioc_value},
            )

        if response.status_code != 200:
            return {
                "found": False,
                "error": f"MalwareBazaar returned HTTP {response.status_code}",
            }

        data = response.json()

        query_status = data.get("query_status", "")
        if query_status in ("hash_not_found", "illegal_hash"):
            return {
                "found": False,
                "file_type": None,
                "signature": None,
                "tags": [],
                "raw_data": data,
            }

        results = data.get("data", []) or []
        if not results:
            return {
                "found": False,
                "file_type": None,
                "signature": None,
                "tags": [],
                "raw_data": data,
            }

        entry = results[0]
        file_type = entry.get("file_type") or entry.get("type") or None
        signature = entry.get("signature") or None
        tags = entry.get("tags", []) or []
        if isinstance(tags, str):
            tags = [tags]

        return {
            "found": True,
            "file_type": file_type,
            "signature": signature,
            "tags": tags,
            "raw_data": data,
        }

    except httpx.TimeoutException:
        return {"found": False, "error": "MalwareBazaar request timed out"}
    except httpx.RequestError as exc:
        return {"found": False, "error": f"MalwareBazaar request error: {str(exc)}"}
    except Exception as exc:
        return {"found": False, "error": f"Unexpected MalwareBazaar error: {str(exc)}"}
