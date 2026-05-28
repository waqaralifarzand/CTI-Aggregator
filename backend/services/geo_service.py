import httpx

GEO_API_URL = "http://ip-api.com/json/{ip}"


async def query_geo(ip: str) -> dict | None:
    """Query ip-api.com for geolocation information about an IP address."""
    try:
        url = GEO_API_URL.format(ip=ip)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)

        if response.status_code != 200:
            return None

        data = response.json()

        if data.get("status") == "fail":
            return None

        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
        }

    except httpx.TimeoutException:
        return None
    except httpx.RequestError:
        return None
    except Exception:
        return None
