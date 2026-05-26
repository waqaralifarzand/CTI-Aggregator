import asyncio
import uuid
from datetime import datetime, timezone

from .ioc_detector import detect_type
from .otx_service import query_otx
from .abusech_service import query_urlhaus, query_malwarebazaar
from .vt_service import query_virustotal
from .geo_service import query_geo
from .whois_service import query_whois
from ..utils.severity import compute_score, score_to_severity, generate_recommendations


async def run_scan(ioc_value: str) -> dict:
    ioc_value = ioc_value.strip()
    ioc_type = detect_type(ioc_value)

    # Launch all applicable feed queries concurrently
    tasks = {
        "otx": query_otx(ioc_value, ioc_type),
        "urlhaus": query_urlhaus(ioc_value, ioc_type),
        "malwarebazaar": query_malwarebazaar(ioc_value, ioc_type),
        "virustotal": query_virustotal(ioc_value, ioc_type),
    }

    if ioc_type == "ip":
        tasks["geo"] = query_geo(ioc_value)
    if ioc_type == "domain":
        tasks["whois"] = query_whois(ioc_value)

    keys = list(tasks.keys())
    results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

    feed_results = {}
    for key, result in zip(keys, results_list):
        if isinstance(result, Exception):
            feed_results[key] = {"found": False, "error": str(result)}
        else:
            feed_results[key] = result

    threat_score = compute_score(feed_results)
    overall_severity = score_to_severity(threat_score)
    recommendations = generate_recommendations(overall_severity, feed_results)

    blacklist_status = {
        "otx_blacklist": "flagged" if (feed_results.get("otx", {}) or {}).get("found") else "clean",
        "urlhaus": "flagged" if (feed_results.get("urlhaus", {}) or {}).get("found") else "clean",
        "malwarebazaar": "flagged" if (feed_results.get("malwarebazaar", {}) or {}).get("found") else "clean",
        "virustotal": "flagged" if (feed_results.get("virustotal", {}) or {}).get("found") else "clean",
    }

    scan_id = str(uuid.uuid4())

    return {
        "scan_id": scan_id,
        "ioc": {"value": ioc_value, "type": ioc_type},
        "overall_severity": overall_severity,
        "threat_score": threat_score,
        "ml_severity": None,
        "ml_confidence": None,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "feeds": {
            "otx": feed_results.get("otx"),
            "urlhaus": feed_results.get("urlhaus"),
            "malwarebazaar": feed_results.get("malwarebazaar"),
            "virustotal": feed_results.get("virustotal"),
            "geo": feed_results.get("geo"),
            "whois": feed_results.get("whois"),
        },
        "blacklist_status": blacklist_status,
        "recommendations": recommendations,
    }
