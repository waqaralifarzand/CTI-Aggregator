import whois


def query_whois(domain: str) -> dict | None:
    """Query WHOIS information for a domain.

    Returns a normalized dict with registrar, dates, name servers, and status,
    or None if the query fails or no data is available.
    """
    try:
        w = whois.whois(domain)

        if w is None:
            return None

        # Normalize creation_date — may be a list or single value
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is not None:
            try:
                creation_date = creation_date.isoformat()
            except AttributeError:
                creation_date = str(creation_date)

        # Normalize expiration_date
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date is not None:
            try:
                expiration_date = expiration_date.isoformat()
            except AttributeError:
                expiration_date = str(expiration_date)

        # Normalize name_servers
        name_servers = w.name_servers
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif name_servers is not None:
            name_servers = [str(ns).lower() for ns in name_servers]

        # Normalize status
        status = w.status
        if isinstance(status, str):
            status = [status]
        elif status is not None:
            status = [str(s) for s in status]

        return {
            "registrar": w.registrar or None,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": name_servers or [],
            "status": status or [],
        }

    except Exception:
        return None
