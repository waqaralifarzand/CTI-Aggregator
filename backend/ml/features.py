FEATURE_NAMES = [
    "otx_pulse_count",
    "otx_found",
    "urlhaus_found",
    "malwarebazaar_found",
    "threat_score",
    "ioc_type_ip",
    "ioc_type_domain",
    "ioc_type_hash",
    "otx_has_c2_tag",
    "otx_has_malware_tag",
]

_C2_TAGS = {"c2", "botnet", "rat", "command-and-control"}
_MALWARE_TAGS = {"malware", "ransomware", "trojan", "spyware", "adware", "rootkit"}


def extract_features(scan_data: dict) -> list:
    """Extract a fixed-length feature vector from scan result data.

    Returns a list of 10 numeric features:
    [otx_pulse_count, otx_found, urlhaus_found, malwarebazaar_found,
     threat_score, ioc_type_ip, ioc_type_domain, ioc_type_hash,
     otx_has_c2_tag, otx_has_malware_tag]
    """
    feeds = scan_data.get("feeds", {}) or {}
    ioc_type = scan_data.get("ioc_type", "") or ""
    threat_score = scan_data.get("threat_score", 0) or 0

    otx = feeds.get("otx", {}) or {}
    urlhaus = feeds.get("urlhaus", {}) or {}
    malwarebazaar = feeds.get("malwarebazaar", {}) or {}

    otx_found = 1 if otx.get("found") else 0
    otx_pulse_count = float(otx.get("pulse_count", 0) or 0)
    urlhaus_found = 1 if urlhaus.get("found") else 0
    malwarebazaar_found = 1 if malwarebazaar.get("found") else 0

    # IoC type one-hot
    ioc_type_ip = 1 if ioc_type == "ip" else 0
    ioc_type_domain = 1 if ioc_type == "domain" else 0
    ioc_type_hash = 1 if ioc_type in ("hash_md5", "hash_sha256", "hash_sha1") else 0

    # Tag analysis
    threat_tags = [t.lower() for t in (otx.get("threat_tags", []) or [])]
    otx_has_c2_tag = 1 if any(t in _C2_TAGS for t in threat_tags) else 0
    otx_has_malware_tag = 1 if any(t in _MALWARE_TAGS for t in threat_tags) else 0

    return [
        otx_pulse_count,
        otx_found,
        urlhaus_found,
        malwarebazaar_found,
        float(threat_score),
        ioc_type_ip,
        ioc_type_domain,
        ioc_type_hash,
        otx_has_c2_tag,
        otx_has_malware_tag,
    ]
