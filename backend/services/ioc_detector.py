import re
import socket


# IPv4 pattern: 4 octets each 0-255
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Hash patterns
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Domain pattern: labels separated by dots, last label at least 2 chars
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def detect_type(value: str) -> str:
    """Detect the type of an IoC value.

    Returns one of: 'ip', 'domain', 'hash_md5', 'hash_sha256', 'hash_sha1'
    Raises ValueError if the type cannot be determined.
    """
    value = value.strip()

    if not value:
        raise ValueError("IoC value cannot be empty")

    # Strip protocol prefix for domain/IP detection
    stripped = value
    for prefix in ("https://", "http://"):
        if stripped.lower().startswith(prefix):
            stripped = stripped[len(prefix):]
            break
    # Strip path/port after the host
    stripped = stripped.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    if ":" in stripped and not stripped.startswith("["):
        stripped = stripped.rsplit(":", 1)[0]

    # IPv4 check (use original stripped value)
    if _IPV4_RE.match(stripped):
        return "ip"

    # IPv6 check
    try:
        socket.inet_pton(socket.AF_INET6, stripped)
        return "ip"
    except (socket.error, OSError):
        pass

    # Hash checks — use original value (no URL stripping for hashes)
    clean = value.strip()
    if _SHA256_RE.match(clean):
        return "hash_sha256"
    if _SHA1_RE.match(clean):
        return "hash_sha1"
    if _MD5_RE.match(clean):
        return "hash_md5"

    # Domain check
    if "." in stripped and _DOMAIN_RE.match(stripped):
        return "domain"

    raise ValueError(f"Unable to detect IoC type for value: '{value}'")
