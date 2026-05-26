import asyncio
import whois


def _do_whois(domain: str) -> dict | None:
    try:
        w = whois.whois(domain)
        if not w or not w.domain_name:
            return None

        def _date_str(d):
            if d is None:
                return None
            if isinstance(d, list):
                d = d[0]
            return str(d)

        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = [ns.lower() for ns in name_servers if ns][:4]
        elif isinstance(name_servers, str):
            name_servers = [name_servers.lower()]
        else:
            name_servers = []

        status = w.status
        if isinstance(status, list):
            status = status[0] if status else None

        return {
            "registrar": w.registrar,
            "creation_date": _date_str(w.creation_date),
            "expiration_date": _date_str(w.expiration_date),
            "name_servers": name_servers,
            "status": status,
        }
    except Exception:
        return None


async def query_whois(domain: str) -> dict | None:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _do_whois, domain),
            timeout=10,
        )
        return result
    except Exception:
        return None
