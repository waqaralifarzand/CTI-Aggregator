import httpx


async def query_geo(ip: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,as")
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return None

        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
        }
    except Exception:
        return None
