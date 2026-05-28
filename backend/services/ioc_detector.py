import re
import ipaddress


def detect_type(value: str) -> str:
    v = value.strip().lower()

    # IPv4 / IPv6
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # MD5 — exactly 32 hex chars
    if re.fullmatch(r"[0-9a-f]{32}", v):
        return "hash_md5"

    # SHA256 — exactly 64 hex chars
    if re.fullmatch(r"[0-9a-f]{64}", v):
        return "hash_sha256"

    # SHA1 — exactly 40 hex chars
    if re.fullmatch(r"[0-9a-f]{40}", v):
        return "hash_sha1"

    # Domain — must have at least one dot, valid TLD-like suffix, no spaces
    domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
    if re.fullmatch(domain_pattern, v):
        return "domain"

    raise ValueError(f"Cannot detect IoC type for value: {value!r}")
